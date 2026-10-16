//! Value-free "why is this key (not) protected?" report.
//!
//! The report shape matches the structured content of the MCP `phantom_why`
//! tool: `{key, dotenv_exists, found, classification, protected, reason,
//! matched_pattern, service, next_step}`. It never contains a secret value.

use crate::config::PhantomConfig;
use crate::dotenv::{classify, is_public_key, DotenvFile, SecretClassification};
use serde_json::{json, Value};

const PUBLIC_PREFIXES: [&str; 6] = [
    "NEXT_PUBLIC_",
    "EXPO_PUBLIC_",
    "VITE_",
    "REACT_APP_",
    "NUXT_PUBLIC_",
    "GATSBY_",
];

const SECRET_KEY_PATTERNS: [&str; 11] = [
    "KEY",
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
    "AUTH",
    "PRIVATE",
    "API_KEY",
    "ACCESS_KEY",
    "SIGNING",
];

const CONNECTION_PATTERNS: [&str; 10] = [
    "DATABASE_URL",
    "REDIS_URL",
    "MONGO_URL",
    "POSTGRES_URL",
    "MYSQL_URL",
    "AMQP_URL",
    "RABBITMQ_URL",
    "ELASTICSEARCH_URL",
    "CONNECTION_STRING",
    "DSN",
];

/// Build the value-free why report for `key`.
///
/// `dotenv` is `None` when the managed dotenv file does not exist. The caller
/// is responsible for validating a parsed dotenv before passing it in.
pub fn why_report(key: &str, dotenv: Option<&DotenvFile>, config: Option<&PhantomConfig>) -> Value {
    let mut report = json!({
        "key": key,
        "dotenv_exists": dotenv.is_some(),
        "found": false,
        "classification": null,
        "protected": false,
        "reason": null,
        "matched_pattern": null,
        "service": null,
        "next_step": null,
    });
    let Some(dotenv) = dotenv else {
        report["next_step"] =
            "Create the managed .env (or set dotenv_path in .phantom.toml), then retry.".into();
        return report;
    };
    let Some(entry) = dotenv.entries().into_iter().find(|e| e.key == key) else {
        report["next_step"] =
            "Check the exact key spelling (case-sensitive); phantom_status lists dotenv counts."
                .into();
        return report;
    };
    report["found"] = true.into();

    if entry.is_phantom {
        report["classification"] = "protected".into();
        report["protected"] = true.into();
        report["reason"] = "phantom_token".into();
        if let Some((name, svc)) =
            config.and_then(|cfg| cfg.services.iter().find(|(_, c)| c.secret_key == key))
        {
            report["service"] = json!({ "name": name, "pattern": svc.pattern });
        }
        return report;
    }

    match classify(entry) {
        SecretClassification::PublicKey => {
            let prefix = PUBLIC_PREFIXES
                .iter()
                .find(|p| key.starts_with(*p))
                .unwrap_or(&"unknown");
            report["classification"] = "public_key".into();
            report["reason"] = "public_prefix".into();
            report["matched_pattern"] = (*prefix).into();
        }
        SecretClassification::Secret => {
            report["classification"] = "secret_unprotected".into();
            report["next_step"] = "Run `phantom init` to protect it with a phantom token.".into();
            let upper = key.to_uppercase();
            if let Some(pat) = SECRET_KEY_PATTERNS.iter().find(|p| upper.contains(*p)) {
                report["reason"] = "key_name".into();
                report["matched_pattern"] = (*pat).into();
            } else if let Some(pat) = CONNECTION_PATTERNS.iter().find(|p| upper.contains(*p)) {
                report["reason"] = "connection_pattern".into();
                report["matched_pattern"] = (*pat).into();
            } else if is_public_key(key) {
                report["reason"] = "public_prefix_with_secret_value".into();
            } else {
                report["reason"] = "value_pattern".into();
            }
        }
        SecretClassification::NotSecret => {
            report["classification"] = "not_secret".into();
            report["reason"] = "no_secret_pattern".into();
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> DotenvFile {
        DotenvFile::parse_str(text)
    }

    #[test]
    fn missing_dotenv_reports_not_found_with_next_step() {
        let report = why_report("OPENAI_API_KEY", None, None);
        assert_eq!(report["dotenv_exists"], false);
        assert_eq!(report["found"], false);
        assert!(report["next_step"].is_string());
    }

    #[test]
    fn classifies_without_leaking_values() {
        let secret_value = concat!("rk", "_placeholder_value_abcdefghijklmnop");
        let dotenv = parse(&format!(
            "STRIPE_SECRET_KEY={secret_value}\nNODE_ENV=production\nVITE_APP_NAME=demo\n"
        ));
        let secret = why_report("STRIPE_SECRET_KEY", Some(&dotenv), None);
        assert_eq!(secret["found"], true);
        assert_eq!(secret["classification"], "secret_unprotected");
        assert_eq!(secret["reason"], "key_name");
        assert_eq!(secret["matched_pattern"], "KEY");
        assert!(!secret.to_string().contains(secret_value));

        let config = why_report("NODE_ENV", Some(&dotenv), None);
        assert_eq!(config["classification"], "not_secret");
        assert_eq!(config["protected"], false);

        let public = why_report("VITE_APP_NAME", Some(&dotenv), None);
        assert_eq!(public["classification"], "public_key");
        assert_eq!(public["matched_pattern"], "VITE_");

        let missing = why_report("NOPE", Some(&dotenv), None);
        assert_eq!(missing["found"], false);
        assert_eq!(missing["dotenv_exists"], true);
    }
}

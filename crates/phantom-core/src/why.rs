//! Value-free "why is this key (not) protected?" report.
//!
//! The report shape matches the structured content of the MCP `phantom_why`
//! tool: `{key, dotenv_exists, found, classification, protected, reason,
//! matched_pattern, service, exec, next_step}`. It never contains a secret
//! value.

use crate::config::{ExecDelivery, PhantomConfig};
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
        "exec": null,
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
        if let Some(cfg) = config {
            let delivery = cfg.exec_delivery_for_secret(key);
            report["exec"] = json!({
                "delivery": delivery.label(),
                "service": delivery.service(),
                "upstream": delivery.upstream(),
            });
            if let Some(step) = exec_next_step(key, &delivery) {
                report["next_step"] = step.into();
            }
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

/// What an agent should know when `phantom exec` cannot use a protected key.
///
/// `None` for a proxied key: nothing needs doing.
pub fn exec_next_step(key: &str, delivery: &ExecDelivery<'_>) -> Option<String> {
    match delivery {
        ExecDelivery::Proxied { .. } => None,
        ExecDelivery::NoRoute => Some(format!(
            "No proxy route injects `{key}`. Under `phantom exec` the child gets only a \
             session token for it, which no provider accepts, so calls that send it fail \
             (typically HTTP 401). Phantom proxies only its built-in providers \
             (phantom_status lists the configured routes). Whether this key should stay \
             protected is the user's decision in a trusted terminal."
        )),
        ExecDelivery::ConnectionStringRefused { .. } => Some(format!(
            "`phantom exec` refuses to start while the connection string `{key}` is \
             protected; it needs a protocol-aware broker. Run database commands from a \
             trusted terminal outside `phantom exec`."
        )),
        ExecDelivery::CustomRouteRefused { service } => Some(format!(
            "Service `{service}` in .phantom.toml is not Phantom's exact built-in route, \
             so `phantom exec` refuses to start with it configured. Restore the built-in \
             definition or remove the custom service."
        )),
    }
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

    #[test]
    fn protected_key_reports_how_exec_delivers_it() {
        use crate::token::PhantomToken;
        let routed = PhantomToken::generate();
        let unrouted = PhantomToken::generate();
        let database = PhantomToken::generate();
        let dotenv = parse(&format!(
            "OPENAI_API_KEY={}\nGROQ_API_KEY={}\nDATABASE_URL={}\n",
            routed.as_str(),
            unrouted.as_str(),
            database.as_str()
        ));
        let config = PhantomConfig::new_with_defaults("test".to_string());

        let proxied = why_report("OPENAI_API_KEY", Some(&dotenv), Some(&config));
        assert_eq!(proxied["classification"], "protected");
        assert_eq!(proxied["exec"]["delivery"], "proxied");
        assert_eq!(proxied["exec"]["service"], "openai");
        assert_eq!(proxied["exec"]["upstream"], "api.openai.com");
        assert!(proxied["next_step"].is_null());

        let no_route = why_report("GROQ_API_KEY", Some(&dotenv), Some(&config));
        assert_eq!(no_route["classification"], "protected");
        assert_eq!(no_route["service"], Value::Null);
        assert_eq!(no_route["exec"]["delivery"], "no_route");
        assert!(no_route["exec"]["service"].is_null());
        let step = no_route["next_step"].as_str().unwrap();
        assert!(step.contains("GROQ_API_KEY"), "{step}");
        assert!(step.contains("no provider accepts"), "{step}");

        let refused = why_report("DATABASE_URL", Some(&dotenv), Some(&config));
        assert_eq!(refused["exec"]["delivery"], "connection_string_refused");
        assert_eq!(refused["exec"]["service"], "database");
        assert!(refused["next_step"].as_str().unwrap().contains("broker"));

        // Without a config the delivery cannot be known, so it is not guessed.
        let unknown = why_report("GROQ_API_KEY", Some(&dotenv), None);
        assert!(unknown["exec"].is_null());

        for report in [&proxied, &no_route, &refused, &unknown] {
            let text = report.to_string();
            for token in [&routed, &unrouted, &database] {
                assert!(!text.contains(token.as_str()));
            }
            assert!(!text.contains("phm_"));
        }
    }
}

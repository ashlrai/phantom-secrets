//! Value-free "why is this key (not) protected?" report.
//!
//! The report shape matches the structured content of the MCP `phantom_why`
//! tool: `{key, dotenv_exists, found, classification, protected, reason,
//! matched_pattern, service, exec, next_step}`. It never contains a secret
//! value.

use crate::config::{ExecBlocker, ExecDelivery, PhantomConfig};
use crate::dotenv::{classify, is_public_key, DotenvFile, SecretClassification};
use crate::token::PhantomToken;
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
            "Check the exact key spelling (case-sensitive); `phantom status` (MCP: phantom_status) lists dotenv counts."
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
            let verdict = ExecVerdict::new(key, dotenv, cfg);
            report["exec"] = verdict.to_json();
            if let Some(step) = verdict.next_step() {
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

/// How `phantom exec` treats a protected key: the per-key delivery and any
/// configuration-wide refusal that stops exec before it starts. Value-free:
/// built from the config and the dotenv's key names and token shapes only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecVerdict<'a> {
    pub key: &'a str,
    pub delivery: ExecDelivery<'a>,
    /// Set when exec refuses to start at all; then no key reaches a child.
    pub blocked_by: Option<ExecBlocker<'a>>,
}

impl<'a> ExecVerdict<'a> {
    /// Judge `key` against `config`, treating every dotenv entry that holds a
    /// phantom token as protected, exactly as `phantom exec` does.
    pub fn new(key: &'a str, dotenv: &DotenvFile, config: &'a PhantomConfig) -> Self {
        let protected: std::collections::HashSet<String> = dotenv
            .entries()
            .into_iter()
            .filter(|entry| PhantomToken::is_phantom_token(&entry.value))
            .map(|entry| entry.key.clone())
            .collect();
        Self {
            key,
            delivery: config.exec_delivery_for_key(key),
            blocked_by: config.exec_blocker(|name| protected.contains(name)),
        }
    }

    /// `{delivery, service, upstream, blocked_by: {service, reason, key} | null}`.
    pub fn to_json(&self) -> Value {
        json!({
            "delivery": self.delivery.label(),
            "service": self.delivery.service(),
            "upstream": self.delivery.upstream(),
            "blocked_by": self.blocked_by.map(|blocker| json!({
                "service": blocker.service(),
                "reason": blocker.reason(),
                "key": blocker.key(),
            })),
        })
    }

    /// One line for human output, such as `proxied to api.openai.com`.
    pub fn summary(&self) -> String {
        let delivery = match self.delivery.upstream() {
            Some(upstream) => format!("proxied; the real value is injected for {upstream}"),
            None => self.delivery.label().replace('_', " "),
        };
        match self.blocked_by {
            Some(blocker) => format!(
                "exec will not start (blocked by service `{}`: {}); this key alone: {delivery}",
                blocker.service(),
                blocker.reason().replace('_', " ")
            ),
            None => delivery,
        }
    }

    /// What an agent should know when exec cannot use this key. `None` for a
    /// proxied key when nothing blocks exec.
    pub fn next_step(&self) -> Option<String> {
        if let Some(blocker) = self.blocked_by {
            return Some(blocked_next_step(&blocker));
        }
        exec_next_step(self.key, &self.delivery)
    }
}

pub fn blocked_next_step(blocker: &ExecBlocker<'_>) -> String {
    let service = blocker.service();
    match blocker {
        ExecBlocker::ConnectionString { key, .. } => format!(
            "`phantom exec` will not start, for any key, while the connection string `{key}` \
             (service `{service}`) is protected in the dotenv; it needs a protocol-aware \
             broker. Run database commands from a trusted terminal outside `phantom exec`, \
             and keep database work separate from API-key work."
        ),
        ExecBlocker::AlteredBuiltinRoute { .. } => format!(
            "`phantom exec` will not start, for any key, until service `{service}` in \
             .phantom.toml matches Phantom's built-in route again."
        ),
        ExecBlocker::CustomRoute { .. } => format!(
            "`phantom exec` will not start, for any key, while the custom route `{service}` \
             is in .phantom.toml; custom proxy routes are not approved for agentic execution. \
             Removing that service is the user's decision in a trusted terminal."
        ),
    }
}

/// What an agent should know when `phantom exec` cannot use a protected key,
/// judged for the key alone. `None` for a proxied key.
pub fn exec_next_step(key: &str, delivery: &ExecDelivery<'_>) -> Option<String> {
    match delivery {
        ExecDelivery::Proxied { .. } => None,
        ExecDelivery::NoRoute => Some(format!(
            "No proxy route injects `{key}`. Under `phantom exec` the child gets only a \
             session token for it, which no provider accepts, so calls that send it fail \
             (typically HTTP 401). Phantom proxies only its built-in providers \
             (`phantom status`, or phantom_status over MCP, lists the configured routes). Whether this key should stay \
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
        ExecDelivery::Withheld => Some(format!(
            "`phantom exec` never hands `{key}` to the child, not even as a session token: \
             it is a provider-management or sync credential that Phantom keeps out of agent \
             processes. Nothing under `phantom exec` can use it."
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

        // Without DATABASE_URL protected, nothing blocks exec.
        let routable = parse(&format!(
            "OPENAI_API_KEY={}\nGROQ_API_KEY={}\n",
            routed.as_str(),
            unrouted.as_str()
        ));
        let proxied = why_report("OPENAI_API_KEY", Some(&routable), Some(&config));
        assert_eq!(proxied["classification"], "protected");
        assert_eq!(proxied["exec"]["delivery"], "proxied");
        assert!(proxied["exec"]["blocked_by"].is_null());
        assert_eq!(proxied["exec"]["service"], "openai");
        assert_eq!(proxied["exec"]["upstream"], "api.openai.com");
        assert!(proxied["next_step"].is_null());

        let no_route = why_report("GROQ_API_KEY", Some(&routable), Some(&config));
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

        // A protected connection string stops exec for every key, including
        // one a built-in route would proxy.
        let blocked = why_report("OPENAI_API_KEY", Some(&dotenv), Some(&config));
        assert_eq!(blocked["exec"]["delivery"], "proxied");
        assert_eq!(blocked["exec"]["blocked_by"]["service"], "database");
        assert_eq!(blocked["exec"]["blocked_by"]["reason"], "connection_string");
        assert_eq!(blocked["exec"]["blocked_by"]["key"], "DATABASE_URL");
        let step = blocked["next_step"].as_str().unwrap();
        assert!(step.contains("will not start"), "{step}");
        assert!(
            !step.contains("reveal") && !step.contains("remove"),
            "{step}"
        );

        // A custom gateway route stops exec too, and is checked first.
        let mut gateway = PhantomConfig::new_with_defaults("test".to_string());
        gateway.services.insert(
            "gateway".to_string(),
            crate::config::ServiceConfig {
                secret_key: "GATEWAY_API_KEY".to_string(),
                pattern: Some("gateway.example.com".to_string()),
                header: Some("Authorization".to_string()),
                header_format: Some("Bearer {secret}".to_string()),
                secret_type: "api_key".to_string(),
            },
        );
        let custom = why_report("OPENAI_API_KEY", Some(&routable), Some(&gateway));
        assert_eq!(custom["exec"]["delivery"], "proxied");
        assert_eq!(custom["exec"]["blocked_by"]["service"], "gateway");
        assert_eq!(custom["exec"]["blocked_by"]["reason"], "custom_route");
        assert!(custom["exec"]["blocked_by"]["key"].is_null());
        assert!(custom["next_step"]
            .as_str()
            .unwrap()
            .contains("will not start"));

        // A key exec never hands the child.
        let mut rotating = PhantomConfig::new_with_defaults("test".to_string());
        rotating.sync.push(
            toml::from_str(
                "platform = \"vercel\"\ntoken_env = \"VERCEL_TOKEN\"\nproject_id = \"p\"\n",
            )
            .unwrap(),
        );
        let sync_token = PhantomToken::generate();
        let with_sync = parse(&format!("VERCEL_TOKEN={}\n", sync_token.as_str()));
        let withheld = why_report("VERCEL_TOKEN", Some(&with_sync), Some(&rotating));
        assert_eq!(withheld["exec"]["delivery"], "withheld");
        assert!(withheld["next_step"]
            .as_str()
            .unwrap()
            .contains("never hands"));

        for report in [
            &proxied, &no_route, &refused, &unknown, &blocked, &custom, &withheld,
        ] {
            let text = report.to_string();
            for token in [&routed, &unrouted, &database, &sync_token] {
                assert!(!text.contains(token.as_str()));
            }
            assert!(!text.contains("phm_"));
        }
    }
}

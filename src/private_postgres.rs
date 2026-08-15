//! Closed `PostgreSQL` connection construction for private one-shot writers.
//!
//! These writers accept a deployment-validated URL, but `sqlx-postgres`
//! otherwise also consults `libpq`-compatible process variables and `pgpass`.
//! This module makes that ambient input visible and forbidden before the
//! driver constructs any connection options.

use std::env;
use std::ffi::{OsStr, OsString};

use sqlx::postgres::{PgConnectOptions, PgSslMode};
use url::Url;

use crate::{FleetError, Result};

/// Exact TLS mode expected from a deployment-validated private database URL.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivatePostgresSslPolicy {
    /// Do not negotiate TLS. This is reserved for the explicit control-
    /// bootstrap loopback development escape.
    Disable,
    /// Require CA and hostname verification.
    VerifyFull,
}

impl PrivatePostgresSslPolicy {
    const fn matches(self, actual: PgSslMode) -> bool {
        matches!(
            (self, actual),
            (Self::Disable, PgSslMode::Disable) | (Self::VerifyFull, PgSslMode::VerifyFull)
        )
    }
}

/// Build closed driver options for a private, one-shot `PostgreSQL` writer.
///
/// The caller must first validate the URL as part of its dedicated runtime
/// configuration and verify every ceremony artifact. This final boundary
/// rejects all ambient `PG*` process inputs, suppresses URL details from parse
/// errors, rechecks the connection shape produced by `sqlx-postgres`, and sets
/// the process's fixed application name.
pub fn private_postgres_connect_options(
    database_url: &str,
    application_name: &str,
    expected_ssl_policy: PrivatePostgresSslPolicy,
) -> Result<PgConnectOptions> {
    private_postgres_connect_options_from_variables(
        database_url,
        application_name,
        expected_ssl_policy,
        env::vars_os(),
    )
}

fn private_postgres_connect_options_from_variables<I>(
    database_url: &str,
    application_name: &str,
    expected_ssl_policy: PrivatePostgresSslPolicy,
    variables: I,
) -> Result<PgConnectOptions>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    let forbidden_names = forbidden_pg_environment_names(variables);
    if !forbidden_names.is_empty() {
        return Err(FleetError::Configuration(format!(
            "private PostgreSQL connection forbids ambient PG* environment variables: {}; values are redacted",
            forbidden_names.join(", ")
        )));
    }

    if application_name.is_empty() || application_name.chars().any(char::is_control) {
        return Err(FleetError::Configuration(
            "private PostgreSQL application name must be nonempty and contain no control characters"
                .into(),
        ));
    }

    // Recheck explicit URL components here so a future caller cannot mistake
    // a driver's environment-derived default for deployment authority.
    let parsed_url = Url::parse(database_url)
        .map_err(|_| FleetError::Configuration("invalid private PostgreSQL database URL".into()))?;
    if !matches!(parsed_url.scheme(), "postgres" | "postgresql")
        || parsed_url.host_str().is_none_or(str::is_empty)
        || parsed_url.username().is_empty()
        || parsed_url.password().is_none_or(str::is_empty)
        || parsed_url.port().is_none_or(|port| port == 0)
        || parsed_url.path().trim_start_matches('/').is_empty()
    {
        return Err(FleetError::Configuration(
            "private PostgreSQL database URL must include an explicit nonempty host, username, password, database, and nonzero port"
                .into(),
        ));
    }

    let options = database_url
        .parse::<PgConnectOptions>()
        .map_err(|_| FleetError::Configuration("invalid private PostgreSQL database URL".into()))?
        .application_name(application_name);

    if options.get_socket().is_some()
        || options.get_host().is_empty()
        || options.get_host().starts_with(['/', '\\'])
        || options.get_username().is_empty()
        || options.get_database().is_none_or(str::is_empty)
        || options.get_port() == 0
        || options.get_options().is_some()
        || options.get_application_name() != Some(application_name)
        || !expected_ssl_policy.matches(options.get_ssl_mode())
    {
        return Err(FleetError::Configuration(
            "private PostgreSQL driver options violate the closed connection policy".into(),
        ));
    }

    Ok(options)
}

fn forbidden_pg_environment_names<I>(variables: I) -> Vec<String>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    let mut names = variables
        .into_iter()
        .filter_map(|(name, _value)| has_ascii_pg_prefix(&name).then_some(name))
        .collect::<Vec<OsString>>();
    names.sort_unstable_by(|left, right| left.as_encoded_bytes().cmp(right.as_encoded_bytes()));
    names
        .iter()
        .map(|name| escaped_environment_name(name))
        .collect()
}

fn has_ascii_pg_prefix(name: &OsStr) -> bool {
    let bytes = name.as_encoded_bytes();
    bytes.len() >= 2 && bytes[0].eq_ignore_ascii_case(&b'p') && bytes[1].eq_ignore_ascii_case(&b'g')
}

fn escaped_environment_name(name: &OsStr) -> String {
    let escaped = name
        .as_encoded_bytes()
        .iter()
        .flat_map(|byte| std::ascii::escape_default(*byte))
        .collect::<Vec<_>>();
    // `escape_default` emits ASCII bytes only.
    format!(
        "\"{}\"",
        String::from_utf8(escaped).expect("ASCII environment-name escape")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const VERIFY_FULL_URL: &str =
        "postgresql://writer:secret@db.example:26257/fleet_recall?sslmode=verify-full";

    fn variable(name: &str, value: &str) -> (OsString, OsString) {
        (OsString::from(name), OsString::from(value))
    }

    #[test]
    fn ambient_pg_classifier_is_ascii_case_insensitive_and_sorted() {
        let names = forbidden_pg_environment_names([
            variable("Path", "not-postgres"),
            variable("pgUSER", "operator"),
            variable("pGNEWSETTING", "future-driver-input"),
            variable("PGHOST", "db.internal"),
            variable("PGA", "present"),
            variable("P", "too-short"),
        ]);

        assert_eq!(
            names,
            ["\"PGA\"", "\"PGHOST\"", "\"pGNEWSETTING\"", "\"pgUSER\""]
        );
    }

    #[test]
    fn ambient_pg_rejection_reports_names_only() {
        let error = private_postgres_connect_options_from_variables(
            VERIFY_FULL_URL,
            "private-writer",
            PrivatePostgresSslPolicy::VerifyFull,
            [
                variable("pgPASSWORD", "do-not-print-lower"),
                variable("PGHOST", "do-not-print-host"),
                variable("PGPASSWORD", "do-not-print-upper"),
            ],
        )
        .expect_err("ambient PostgreSQL inputs must be rejected");
        let message = error.to_string();

        assert!(message.contains("\"PGHOST\", \"PGPASSWORD\", \"pgPASSWORD\""));
        assert!(message.contains("values are redacted"));
        for secret in [
            "do-not-print-lower",
            "do-not-print-host",
            "do-not-print-upper",
            "writer:secret",
        ] {
            assert!(!message.contains(secret));
        }
    }

    #[test]
    fn ambient_pg_names_are_escaped_before_reporting() {
        let error = private_postgres_connect_options_from_variables(
            VERIFY_FULL_URL,
            "private-writer",
            PrivatePostgresSslPolicy::VerifyFull,
            [variable("PGHOST\nforged-log-line", "secret")],
        )
        .expect_err("ambient PostgreSQL inputs must be rejected");
        let message = error.to_string();

        assert!(message.contains("\"PGHOST\\nforged-log-line\""));
        assert!(!message.contains("PGHOST\nforged-log-line"));
        assert!(!message.contains("secret"));
    }

    #[test]
    fn closed_options_preserve_explicit_identity_and_application_name() {
        let options = private_postgres_connect_options_from_variables(
            VERIFY_FULL_URL,
            "private-writer",
            PrivatePostgresSslPolicy::VerifyFull,
            [],
        )
        .expect("closed options");

        assert_eq!(options.get_host(), "db.example");
        assert_eq!(options.get_port(), 26_257);
        assert_eq!(options.get_username(), "writer");
        assert_eq!(options.get_database(), Some("fleet_recall"));
        assert_eq!(options.get_application_name(), Some("private-writer"));
        assert!(options.get_socket().is_none());
        assert!(options.get_options().is_none());
        assert!(matches!(options.get_ssl_mode(), PgSslMode::VerifyFull));
    }

    #[test]
    fn closed_options_accept_only_the_expected_tls_mode() {
        let disable_url = "postgresql://writer:secret@127.0.0.1:26257/fleet_recall?sslmode=disable";
        assert!(
            private_postgres_connect_options_from_variables(
                disable_url,
                "private-writer",
                PrivatePostgresSslPolicy::Disable,
                [],
            )
            .is_ok()
        );
        assert!(
            private_postgres_connect_options_from_variables(
                disable_url,
                "private-writer",
                PrivatePostgresSslPolicy::VerifyFull,
                [],
            )
            .is_err()
        );
        assert!(
            private_postgres_connect_options_from_variables(
                VERIFY_FULL_URL,
                "private-writer",
                PrivatePostgresSslPolicy::Disable,
                [],
            )
            .is_err()
        );
    }

    #[test]
    fn closed_options_reject_driver_socket_and_pgoptions_shapes() {
        for url in [
            "postgresql://writer:secret@%2Fvar%2Frun%2Fpostgres:26257/fleet_recall?sslmode=verify-full",
            "postgresql://writer:secret@db.example:26257/fleet_recall?sslmode=verify-full&options=-csearch_path%3Dattacker",
        ] {
            assert!(
                private_postgres_connect_options_from_variables(
                    url,
                    "private-writer",
                    PrivatePostgresSslPolicy::VerifyFull,
                    [],
                )
                .is_err(),
                "accepted closed-policy violation"
            );
        }
    }

    #[test]
    fn closed_options_require_explicit_url_identity() {
        for url in [
            "postgresql://:secret@db.example:26257/fleet_recall?sslmode=verify-full",
            "postgresql://writer@db.example:26257/fleet_recall?sslmode=verify-full",
            "postgresql://writer:@db.example:26257/fleet_recall?sslmode=verify-full",
            "postgresql://writer:secret@db.example/fleet_recall?sslmode=verify-full",
            "postgresql://writer:secret@db.example:0/fleet_recall?sslmode=verify-full",
            "postgresql://writer:secret@db.example:26257/?sslmode=verify-full",
        ] {
            assert!(
                private_postgres_connect_options_from_variables(
                    url,
                    "private-writer",
                    PrivatePostgresSslPolicy::VerifyFull,
                    [],
                )
                .is_err(),
                "accepted incomplete identity"
            );
        }
    }
}

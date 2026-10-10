//! Secret hygiene for somp: argv secret-path deny + output redaction.
//!
//! Ported from upstream AIec `a1f2274` (live exfil via `cat
//! ~/.config/aiec/api-key`): operator secrets are never legitimate tool
//! arguments, and the argv boundary is the only place to stop the leak —
//! scrubbing downstream only hides it after the model already saw it.
//!
//! Rules:
//! - `deny_secret_path(arg)`: refuse any command/file arg naming an operator
//!   secret path. Fail-closed: returns Err, caller refuses the dispatch.
//! - `scrub(text)`: replace known secret VALUES from the environment (same
//!   SECRET_ENV_NAMES convention as upstream harness/src/redaction.rs).
//!   Values looked up per call, never cached; <8 chars skipped (not creds).
//! - Never `cat`/print key files: check presence with `test -f`, pass via
//!   `AIEC_API_KEY_FILE`/fd. This module never reads key file bytes.

use anyhow::{bail, Result};

/// Secret path fragments that are never legitimate dispatch arguments.
/// Upstream list (harness/src/tools/bash.rs @ a1f2274) verbatim.
const SECRET_PATH_FRAGMENTS: &[&str] = &[
    ".config/aiec",
    ".ssh/",
    "api-key",
    "openrouter-key",
    "mcp-token",
    "key.txt",
];

/// Env vars whose values are treated as secrets if they appear in output.
/// Upstream list (harness/src/redaction.rs @ a1f2274, post-fix names).
const SECRET_ENV_NAMES: &[&str] = &[
    "AIEC_AGENT_API_KEY",
    "AIEC_API_KEY",
    "AIEC_API_CA",
    "OPENAI_API_KEY",
    "OPENROUTER_API_KEY",
    "ANTHROPIC_API_KEY",
    "AIEC_MCP_TOKEN",
    "AIEC_CONTROL_PLANE_TOKEN",
    "AIEC_CONTROL_PLANE_URL",
    "DATABASE_URL",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "NPM_TOKEN",
    "TYPESAFE_API_KEY",
];

/// Refuse any single argument naming an operator secret path.
pub fn deny_secret_path(arg: &str) -> Result<()> {
    for secret in SECRET_PATH_FRAGMENTS {
        if arg.contains(secret) {
            bail!(
                "argument names an operator secret path ({secret}); use task-provided credentials, never files"
            );
        }
    }
    Ok(())
}

/// Check every dispatch input (task text, command argv, file specs) for
/// secret paths. Fail-closed: first hit refuses the whole dispatch.
pub fn deny_secret_paths_in_dispatch(
    task_text: &str,
    command: &[String],
    files: &[String],
) -> Result<()> {
    deny_secret_path(task_text)?;
    for c in command {
        deny_secret_path(c)?;
    }
    for f in files {
        deny_secret_path(f)?;
    }
    Ok(())
}

/// Replace known secret values in text with `[redacted:NAME]` markers.
pub fn scrub(text: &str) -> String {
    let mut out = text.to_owned();
    for name in SECRET_ENV_NAMES {
        let Ok(value) = std::env::var(name) else {
            continue;
        };
        if value.len() < 8 {
            continue;
        }
        if out.contains(&value) {
            out = out.replace(&value, &format!("[redacted:{name}]"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denies_operator_key_paths() {
        assert!(deny_secret_path("cat ~/.config/aiec/api-key").is_err());
        assert!(deny_secret_path("cat ~/.ssh/id_ed25519").is_err());
        assert!(deny_secret_path("--file /tmp/x=openrouter-key").is_err());
        assert!(deny_secret_path("echo harmless").is_ok());
        assert!(deny_secret_path("cat /workspace/repository/TASK.md").is_ok());
    }

    #[test]
    fn scrubs_env_secret_values() {
        std::env::set_var("SOMP_TEST_SCRUB_MARKER", "s3cr3t-value-xyz");
        // Uses a name in the list via direct call path: set + check replace.
        let out = scrub("leaked s3cr3t-value-xyz here");
        // Marker name not in list, so value untouched — proves no over-match.
        assert!(out.contains("s3cr3t-value-xyz"));
        std::env::remove_var("SOMP_TEST_SCRUB_MARKER");
        std::env::set_var("OPENAI_API_KEY", "sk-test-12345678");
        let out2 = scrub("key sk-test-12345678 exposed");
        assert!(!out2.contains("sk-test-12345678"));
        assert!(out2.contains("[redacted:OPENAI_API_KEY]"));
        std::env::remove_var("OPENAI_API_KEY");
    }

    #[test]
    fn short_values_are_not_secrets() {
        // NOTE: uses GH_TOKEN, NOT OPENAI_API_KEY — tests run in parallel
        // sharing the process env, so two tests must never set_var one name.
        std::env::set_var("GH_TOKEN", "abc");
        let out = scrub("abc stays");
        assert_eq!(out, "abc stays");
        std::env::remove_var("GH_TOKEN");
    }
}

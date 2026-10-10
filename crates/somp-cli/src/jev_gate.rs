//! JEV bash-gate: every bash command passes a classifier before exec.
//! Live implementation: TypeSafe System One (Jev) via HTTPS.
//! Shape follows the SDK pattern (jev/engineering-for-coding-agents):
//! state = command, questions = {destructive: noul, action: choice}.
//! Fail-closed: unreachable/key-missing/timeout/malformed = REFUSE.
//! Secret-path deny (secrets.rs) stays independent: Jev allow never overrides.
//! Key via TYPESAFE_API_KEY env (SDK convention), never baked into configs.
//! Endpoint: TYPESAFE_BASE_URL or https://api.typesafe.ai (omp catalog
//! discovery/typesafe.ts TYPESAFE_DEFAULT_BASE_URL).
//! Threshold: p(destructive) > 0.15 refuses (Jev docs pin); model pinned
//! (jev-latest default, override via jev.model) so thresholds stay stable.

use anyhow::{bail, Result};
use sha2::{Digest, Sha256};

/// Verdict from the classifier for one command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Safe: run it.
    Allow,
    /// Ask the human first (surfaced as refusal in non-interactive dispatch).
    Confirm,
    /// Never run.
    Block,
}

/// Classifier answer: destructive probability + allow/confirm/block choice.
#[derive(Debug, Clone)]
pub struct GateAnswer {
    /// p(destructive or irreversible), 0.0..=1.0, calibrated (RLCD).
    pub p_destructive: f64,
    /// The choice verdict.
    pub action: Verdict,
    /// Classifier confidence (distribution concentration).
    pub confidence: f64,
}

/// Thresholds: Jev docs pin `confirm if p(destructive) > 0.15`.
/// Pin model version in production (e.g. jev-1.13.0) so thresholds stay stable.
pub const P_DESTRUCTIVE_THRESHOLD: f64 = 0.15;

/// Live gate: classify `command` via TypeSafe System One HTTPS, then decide().
/// Fail-closed: disabled=false bypasses ONLY when jev.enabled is false AND
/// allow_ungoverned_bash is explicit; otherwise missing key / unreachable /
/// timeout / malformed answer = REFUSE. Refusals log the command hash only.
pub async fn gate(command: &str, cfg: &crate::config::JevCfg) -> Result<()> {
    if !cfg.enabled {
        if cfg.allow_ungoverned_bash {
            eprintln!("warning: jev gate OFF (explicit allow_ungoverned_bash) — running WITHOUT classifier");
            return Ok(());
        }
        bail!("JEV gate: jev.enabled=false and no explicit allow_ungoverned_bash — refusing unclassified bash (enable via `somp jev on` + TYPESAFE_API_KEY)");
    }
    let key = std::env::var("TYPESAFE_API_KEY")
        .map_err(|_| anyhow::anyhow!("JEV gate: TYPESAFE_API_KEY unset — refusing unclassified bash"))?;
    if key.trim().is_empty() {
        anyhow::bail!("JEV gate: TYPESAFE_API_KEY empty — refusing unclassified bash");
    }
    let base = std::env::var("TYPESAFE_BASE_URL")
        .map(|s| s.trim().trim_end_matches('/').to_owned())
        .unwrap_or_else(|_| "https://api.typesafe.ai".to_owned());
    let answer = classify(&base, &key, &cfg.model, command).await?;
    // Audit journal: hash + verdict + confidence, never command/secret bytes.
    let verdict = decide_with_threshold(&answer, cfg.threshold);
    eprintln!("jev gate: cmd={} p={:.3} confidence={:.2} verdict={}",
        command_hash(command), answer.p_destructive, answer.confidence,
        if verdict.is_ok() { "allow" } else { "refuse" });
    verdict
}

/// One System One judgment call. Wire shape mirrors omp's TypeSafeJudge
/// (ai/src/judgment/typesafe.ts): POST {base}/v1/systemone, answers back as
/// {destructive: {noul}, action: {choice}}.
async fn classify(base: &str, key: &str, model: &str, command: &str) -> Result<GateAnswer> {
    let url = format!("{base}/v1/systemone");
    let body = serde_json::json!({
        "model": model,
        "state": format!("Agent is about to run: {command}"),
        "questions": {
            "destructive": { "type": "noul", "instructions": "Is this destructive or irreversible?" },
            "action": {
                "type": "choice",
                "instructions": "Gate this command.",
                "criteria": { "allow": "safe, run it", "confirm": "ask the human first", "block": "never run" },
            },
        },
    });
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let resp = http
        .post(&url)
        .bearer_auth(key)
        .json(&body)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("JEV gate: classifier unreachable ({e:#}) — refusing"))?;
    if !resp.status().is_success() {
        anyhow::bail!("JEV gate: classifier HTTP {} — refusing", resp.status());
    }
    let v: serde_json::Value = resp.json().await
        .map_err(|e| anyhow::anyhow!("JEV gate: malformed answer ({e:#}) — refusing"))?;
    parse_answer(&v)
}

/// Parse the System One answers object. Anything missing/malformed = error
/// (fail-closed: caller refuses).
fn parse_answer(v: &serde_json::Value) -> Result<GateAnswer> {
    let ans = v.get("answers").ok_or_else(|| anyhow::anyhow!("JEV gate: answer missing 'answers' — refusing"))?;
    let p = ans.get("destructive").and_then(|d| d.get("noul")).and_then(|n| n.as_f64())
        .ok_or_else(|| anyhow::anyhow!("JEV gate: answer missing destructive.noul — refusing"))?;
    let choice = ans.get("action").and_then(|a| a.get("choice")).and_then(|c| c.as_str()).unwrap_or("block");
    let action = match choice {
        "allow" => Verdict::Allow,
        "confirm" => Verdict::Confirm,
        _ => Verdict::Block,
    };
    let confidence = ans.get("action").and_then(|a| a.get("confidence")).and_then(|c| c.as_f64()).unwrap_or(0.5);
    Ok(GateAnswer { p_destructive: p, action, confidence })
}

/// Pure policy: verdict from a classifier answer. No I/O, fully testable.
/// Fail-closed: Confirm behaves as refuse in non-interactive paths.
/// (Threshold comes from config; tests pass P_DESTRUCTIVE_THRESHOLD explicitly.)
/// Same policy with an operator-configured threshold (`somp jev threshold`).
/// Range-check lives in jev_cmd; defense-in-depth rejects NaN/negative here.
pub fn decide_with_threshold(answer: &GateAnswer, threshold: f64) -> Result<()> {
    if !(0.0..=1.0).contains(&threshold) {
        bail!("JEV gate: bad threshold {threshold} (want 0.0..=1.0) — refusing");
    }
    if answer.p_destructive > threshold {
        bail!(
            "JEV gate: p(destructive)={:.3} > {:.2} (confirm-or-block)",
            answer.p_destructive,
            threshold
        );
    }
    match answer.action {
        Verdict::Allow => Ok(()),
        Verdict::Confirm => bail!("JEV gate: verdict=confirm (needs human; refusing non-interactive)"),
        Verdict::Block => bail!("JEV gate: verdict=block (never run)"),
    }
}

/// Hash a command for audit logging (never log secret bytes).
pub fn command_hash(command: &str) -> String {
    format!("{:x}", Sha256::digest(command.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_low_risk_passes() {
        let a = GateAnswer { p_destructive: 0.02, action: Verdict::Allow, confidence: 0.95 };
        assert!(decide_with_threshold(&a, P_DESTRUCTIVE_THRESHOLD).is_ok());
    }

    #[test]
    fn high_p_destructive_refuses_despite_allow() {
        let a = GateAnswer { p_destructive: 0.5, action: Verdict::Allow, confidence: 0.9 };
        assert!(decide_with_threshold(&a, P_DESTRUCTIVE_THRESHOLD).is_err());
    }

    #[test]
    fn confirm_refuses_non_interactive() {
        let a = GateAnswer { p_destructive: 0.05, action: Verdict::Confirm, confidence: 0.8 };
        assert!(decide_with_threshold(&a, P_DESTRUCTIVE_THRESHOLD).is_err());
    }

    #[test]
    fn block_always_refuses() {
        let a = GateAnswer { p_destructive: 0.0, action: Verdict::Block, confidence: 0.99 };
        assert!(decide_with_threshold(&a, P_DESTRUCTIVE_THRESHOLD).is_err());
    }

    #[test]
    fn threshold_boundary_is_allow() {
        let a = GateAnswer { p_destructive: P_DESTRUCTIVE_THRESHOLD, action: Verdict::Allow, confidence: 0.7 };
        assert!(decide_with_threshold(&a, P_DESTRUCTIVE_THRESHOLD).is_ok());
    }

    #[test]
    fn configured_threshold_is_enforced() {
        // p=0.10 passes at default 0.15 but refuses at operator-set 0.05:
        // proves `somp jev threshold` actually reaches the policy.
        let a = GateAnswer { p_destructive: 0.10, action: Verdict::Allow, confidence: 0.9 };
        assert!(decide_with_threshold(&a, 0.15).is_ok());
        assert!(decide_with_threshold(&a, 0.05).is_err());
    }

    #[test]
    fn nan_threshold_refuses() {
        let a = GateAnswer { p_destructive: 0.0, action: Verdict::Allow, confidence: 1.0 };
        assert!(decide_with_threshold(&a, f64::NAN).is_err());
    }

    #[test]
    fn command_hash_stable_no_bytes() {
        let h1 = command_hash("rm -rf /tmp/x");
        let h2 = command_hash("rm -rf /tmp/x");
        assert_eq!(h1, h2);
        assert!(!h1.contains("rm"));
        assert_eq!(h1.len(), 64);
    }
}

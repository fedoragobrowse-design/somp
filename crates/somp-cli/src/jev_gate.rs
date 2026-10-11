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

	/// Live gate: classify `command` via the configured backend, then decide().
	/// Backends: "typesafe" (TypeSafe System One, default) or "openrouter"
	/// (OpenAI-compatible chat completion, strict-JSON verdict).
	/// Fail-closed: disabled=false bypasses ONLY when jev.enabled is false AND
	/// allow_ungoverned_bash is explicit; otherwise missing key / unreachable /
	/// timeout / malformed answer = REFUSE. Refusals log the command hash only.
	pub async fn gate(command: &str, cfg: &crate::config::JevCfg) -> Result<()> {
	    if !cfg.enabled {
	        if cfg.allow_ungoverned_bash {
	            eprintln!("warning: jev gate OFF (explicit allow_ungoverned_bash) — running WITHOUT classifier");
	            return Ok(());
	        }
	        bail!("JEV gate: jev.enabled=false and no explicit allow_ungoverned_bash — refusing unclassified bash (enable via `somp jev on` + key)");
	    }
	    let backend = cfg.backend.trim().to_lowercase();
	    let answer = match backend.as_str() {
	        "typesafe" => {
	            let key = std::env::var("TYPESAFE_API_KEY")
	                .map_err(|_| anyhow::anyhow!("JEV gate: TYPESAFE_API_KEY unset — refusing unclassified bash"))?;
	            if key.trim().is_empty() {
	                anyhow::bail!("JEV gate: TYPESAFE_API_KEY empty — refusing unclassified bash");
	            }
	            let base = std::env::var("TYPESAFE_BASE_URL")
	                .map(|s| s.trim().trim_end_matches('/').to_owned())
	                .unwrap_or_else(|_| "https://api.typesafe.ai".to_owned());
	            classify(&base, &key, &cfg.model, command).await?
	        }
	        "openrouter" => {
	            let key = std::env::var("OPENROUTER_API_KEY")
	                .map_err(|_| anyhow::anyhow!("JEV gate: OPENROUTER_API_KEY unset — refusing unclassified bash"))?;
	            if key.trim().is_empty() {
	                anyhow::bail!("JEV gate: OPENROUTER_API_KEY empty — refusing unclassified bash");
	            }
	            let or_model = if cfg.model == "jev-latest" {
	                // jev-latest is a System One model id — meaningless on the
	                // OpenRouter backend. Refuse loudly instead of sending a
	                // bogus model string to the gateway.
	                anyhow::bail!("JEV gate: backend=openrouter but model is still jev-latest — pin a real model via `somp jev model <id>`");
	            } else if let Some(rest) = cfg.model.strip_prefix("openrouter/") {
	                // Accept the omp-catalog form ("openrouter/<id>") but send
	                // the bare id: the API routes on the path id, and the
	                // prefixed form 400s (same root cause as the mistral-large
	                // 400 via applyResponsesCompatPolicy).
	                rest.to_owned()
	            } else {
	                cfg.model.clone()
	            };
	            classify_openrouter(&key, &or_model, command).await?
	        }
	        other => {
	            anyhow::bail!("JEV gate: unknown backend {other:?} (want typesafe|openrouter) — refusing");
	        }
	    };
	    // Audit journal: hash + verdict + confidence, never command/secret bytes.
	    let verdict = decide_with_threshold(&answer, cfg.threshold);
	    eprintln!("jev gate: backend={backend} cmd={} p={:.3} confidence={:.2} verdict={}",
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
	/// OpenRouter-backend judgment call: OpenAI-compatible chat completion
	/// with a strict-JSON verdict object. POST https://openrouter.ai/api/v1/
	/// chat/completions, bearer = OPENROUTER_API_KEY. Same fail-closed
	/// contract as classify(): any transport/HTTP/shape problem = Err.
	/// Model id comes from jev.model (must be a real OpenRouter id — the
	/// typesafe default jev-latest is rejected in gate(), never sent here).
	async fn classify_openrouter(key: &str, model: &str, command: &str) -> Result<GateAnswer> {
	    let body = serde_json::json!({
	        "model": model,
	        "messages": [
	            { "role": "system", "content": "You are a command-safety classifier gating shell commands before execution. Answer with JSON only." },
	            { "role": "user", "content": format!(
	                "Agent is about to run this shell command: {command}\n\nRespond with a JSON object only: {{\"p_destructive\": <0.0-1.0 probability the command is destructive or irreversible>, \"action\": \"allow\"|\"confirm\"|\"block\", \"confidence\": <0.0-1.0>}}. allow=safe, run it. confirm=needs a human first. block=never run."
	            )},
	        ],
	        "response_format": { "type": "json_object" },
	    });
	    let http = reqwest::Client::builder()
	        .timeout(std::time::Duration::from_secs(15))
	        .build()?;
	    let resp = http
	        .post("https://openrouter.ai/api/v1/chat/completions")
	        .bearer_auth(key)
	        .header("HTTP-Referer", "https://github.com/fedoragobrowse-design/somp")
	        .header("X-Title", "somp jev gate")
	        .json(&body)
	        .send()
	        .await
	        .map_err(|e| anyhow::anyhow!("JEV gate (openrouter): classifier unreachable ({e:#}) — refusing"))?;
	    let status = resp.status();
	    if !status.is_success() {
	        anyhow::bail!("JEV gate (openrouter): classifier HTTP {status} — refusing");
	    }
	    // Decode envelope from raw text (not resp.json()): on malformed
	    // bodies the raw snippet (first 200 chars, model-chosen text) is the
	    // only diagnostic. Secret risk: the envelope echoes OUR prompt, not
	    // the key (bearer travels in the header) — safe to sample.
	    let raw = resp.text().await
	        .map_err(|e| anyhow::anyhow!("JEV gate (openrouter): unreadable body ({e:#}) — refusing"))?;
	    let v: serde_json::Value = serde_json::from_str(&raw)
	        .map_err(|e| {
	            let sample: String = raw.chars().take(200).collect();
	            anyhow::anyhow!("JEV gate (openrouter): envelope not JSON ({e:#}) status={status} body={sample:?} — refusing")
	        })?;
	    parse_openrouter_answer(&v)
	}
	
	/// Parse the OpenAI-compatible choices[0].message.content JSON verdict.
	/// Anything missing/malformed/out-of-range = error (fail-closed).
	fn parse_openrouter_answer(v: &serde_json::Value) -> Result<GateAnswer> {
	    let content = v.get("choices")
	        .and_then(|c| c.get(0))
	        .and_then(|c| c.get("message"))
	        .and_then(|m| m.get("content"))
	        .and_then(|c| c.as_str())
	        .ok_or_else(|| anyhow::anyhow!("JEV gate (openrouter): answer missing choices[0].message.content — refusing"))?;
	    let inner: serde_json::Value = serde_json::from_str(content)
	        .map_err(|e| anyhow::anyhow!("JEV gate (openrouter): verdict not JSON ({e:#}) — refusing"))?;
	    let p = inner.get("p_destructive").and_then(|p| p.as_f64())
	        .ok_or_else(|| anyhow::anyhow!("JEV gate (openrouter): verdict missing p_destructive — refusing"))?;
	    if !(0.0..=1.0).contains(&p) {
	        anyhow::bail!("JEV gate (openrouter): p_destructive {p} out of range — refusing");
	    }
	    let action = match inner.get("action").and_then(|a| a.as_str()).unwrap_or("block") {
	        "allow" => Verdict::Allow,
	        "confirm" => Verdict::Confirm,
	        _ => Verdict::Block,
	    };
	    let confidence = inner.get("confidence").and_then(|c| c.as_f64()).unwrap_or(0.5);
	    Ok(GateAnswer { p_destructive: p, action, confidence })
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
	
	    fn openrouter_envelope(content: &str) -> serde_json::Value {
	        serde_json::json!({
	            "id": "gen-test",
	            "choices": [{ "message": { "role": "assistant", "content": content } }],
	        })
	    }
	
	    #[test]
	    fn openrouter_allow_parses() {
	        let v = openrouter_envelope(r#"{"p_destructive": 0.02, "action": "allow", "confidence": 0.9}"#);
	        let a = parse_openrouter_answer(&v).expect("valid verdict parses");
	        assert!((a.p_destructive - 0.02).abs() < 1e-9);
	        assert_eq!(a.action, Verdict::Allow);
	        assert!(decide_with_threshold(&a, P_DESTRUCTIVE_THRESHOLD).is_ok());
	    }
	
	    #[test]
	    fn openrouter_block_parses_and_refuses() {
	        let v = openrouter_envelope(r#"{"p_destructive": 0.9, "action": "block", "confidence": 0.99}"#);
	        let a = parse_openrouter_answer(&v).expect("valid verdict parses");
	        assert_eq!(a.action, Verdict::Block);
	        assert!(decide_with_threshold(&a, P_DESTRUCTIVE_THRESHOLD).is_err());
	    }
	
	    #[test]
	    fn openrouter_missing_choices_refuses() {
	        let v = serde_json::json!({"id": "gen-test", "choices": []});
	        assert!(parse_openrouter_answer(&v).is_err());
	    }
	
	    #[test]
	    fn openrouter_non_json_content_refuses() {
	        let v = openrouter_envelope("sure, looks fine to me");
	        assert!(parse_openrouter_answer(&v).is_err());
	    }
	
	    #[test]
	    fn openrouter_out_of_range_p_refuses() {
	        let v = openrouter_envelope(r#"{"p_destructive": 1.5, "action": "allow", "confidence": 0.9}"#);
	        assert!(parse_openrouter_answer(&v).is_err());
	    }
	
	    #[test]
	    fn openrouter_unknown_action_maps_to_block() {
	        // Fail-closed default: any action string outside allow|confirm
	        // becomes Block (never run), even with low p_destructive.
	        let v = openrouter_envelope(r#"{"p_destructive": 0.01, "action": "maybe", "confidence": 0.5}"#);
	        let a = parse_openrouter_answer(&v).expect("parses with default");
	        assert_eq!(a.action, Verdict::Block);
	        assert!(decide_with_threshold(&a, P_DESTRUCTIVE_THRESHOLD).is_err());
	    }
	}

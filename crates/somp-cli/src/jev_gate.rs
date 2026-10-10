#![allow(dead_code)] // designed-not-yet-wired: remove when gate() calls decide()
//!
//! Addition requested 2026-10-10: all bash commands pass by a JEV-like
//! classifier model (TypeSafe AI Jev: jevtypesafeai.com/jev/classifier,
//! jev/engineering-for-coding-agents). Shape follows the documented Jev
//! engineering pattern verbatim:
//!
//! ```ignore
//! import { TypeSafe } from "@typesafe-ai/sdk";
//! const jev = new TypeSafe(); // reads TYPESAFE_API_KEY
//! const { answers } = await jev.systemOne({
//!   model: "jev-latest",
//!   state: `Agent is about to run: ${command}`,
//!   questions: {
//!     destructive: { type: "noul", instructions: "Is this destructive or irreversible?" },
//!     action: {
//!       type: "choice",
//!       instructions: "Gate this command.",
//!       criteria: { allow: "safe, run it", confirm: "ask the human first", block: "never run" },
//!     },
//!   },
//! });
//! if (answers.destructive.noul > 0.15 || answers.action.choice !== "allow") {
//!   await askHuman(command);
//! } else {
//!   await run(command);
//! }
//! ```
//! Status: DESIGNED 2026-10-10, NOT YET IMPLEMENTED — needs TYPESAFE_API_KEY
//! + SDK availability check in the guest/operator environment. Recorded in
//! UNPROVEN.md. No bash runs through the gate until implemented + tested.

//! Fail-closed contract (boring, no silent downgrade):
//! - Gate runs BEFORE exec for every command path (default + custom).
//! - `block` or `confirm` verdict, or p(destructive) > threshold, refuses.
//! - Classifier unreachable / key missing / timeout / malformed answer =
//!   REFUSE (never run ungoverned). Operator override is explicit
//!   `--allow-ungoverned-bash` on the CLI (audited, never default).
//! - Secret-path deny (secrets.rs) runs first and stays independent: even a
//!   Jev `allow` never overrides a secret-path hit.
//! - Verdicts are logged (command hash + verdict + confidence, never the
//!   secret bytes) for the audit journal.
//!
//! Wiring: the gate lives in the extension's bash-rewrite path
//! (ext/somp-ext.ts §2) + dispatch custom --command path. Both call
//! `gate(command)` before wrapping/exec. The Jev key arrives via
//! `TYPESAFE_API_KEY` env (SDK convention), never baked into configs.
//!
//! Status: DESIGNED 2026-10-10, NOT YET IMPLEMENTED — needs TYPESAFE_API_KEY
//! + SDK availability check in the guest/operator environment. Recorded in
//! UNPROVEN.md. No bash runs through the gate until implemented + tested.

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

/// Pure policy: verdict from a classifier answer. No I/O, fully testable.
/// Fail-closed: Confirm behaves as refuse in non-interactive paths.
pub fn decide(answer: &GateAnswer) -> Result<()> {
    if answer.p_destructive > P_DESTRUCTIVE_THRESHOLD {
        bail!(
            "JEV gate: p(destructive)={:.3} > {:.2} (confirm-or-block)",
            answer.p_destructive,
            P_DESTRUCTIVE_THRESHOLD
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
        assert!(decide(&a).is_ok());
    }

    #[test]
    fn high_p_destructive_refuses_despite_allow() {
        let a = GateAnswer { p_destructive: 0.5, action: Verdict::Allow, confidence: 0.9 };
        assert!(decide(&a).is_err());
    }

    #[test]
    fn confirm_refuses_non_interactive() {
        let a = GateAnswer { p_destructive: 0.05, action: Verdict::Confirm, confidence: 0.8 };
        assert!(decide(&a).is_err());
    }

    #[test]
    fn block_always_refuses() {
        let a = GateAnswer { p_destructive: 0.0, action: Verdict::Block, confidence: 0.99 };
        assert!(decide(&a).is_err());
    }

    #[test]
    fn threshold_boundary_is_allow() {
        let a = GateAnswer { p_destructive: P_DESTRUCTIVE_THRESHOLD, action: Verdict::Allow, confidence: 0.7 };
        assert!(decide(&a).is_ok());
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

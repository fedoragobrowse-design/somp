//! Tier gate: Firecracker+Guard is the only governed tier.
//! Docker/Bubblewrap/srt-only tiers MUST refuse governed work (fail-closed).

use anyhow::{bail, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// /dev/kvm + kvm module + nft usable: full stack candidate.
    Firecracker,
    /// No KVM: ungoverned local dev only.
    FallbackNoKvm,
}

pub struct TierCheck {
    pub tier: Tier,
    pub kvm_present: bool,
    pub kvm_module: bool,
    pub nft_usable: bool,
    pub bwrap_ok: bool,
}

pub fn check() -> Result<TierCheck> {
    let kvm_present = std::path::Path::new("/dev/kvm").exists();
    let kvm_module = std::fs::read_to_string("/proc/modules")
        .map(|m| m.lines().any(|l| l.starts_with("kvm")))
        .unwrap_or(false);
    let nft_usable = std::process::Command::new("nft")
        .arg("list")
        .arg("ruleset")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    let bwrap_ok = std::process::Command::new("bwrap")
        .args(["--unshare-user", "--dev-bind", "/", "/", "true"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    let tier = if kvm_present && kvm_module {
        Tier::Firecracker
    } else {
        Tier::FallbackNoKvm
    };
    Ok(TierCheck {
        tier,
        kvm_present,
        kvm_module,
        nft_usable,
        bwrap_ok,
    })
}

impl TierCheck {
    /// Governed work (session VM, subagent dispatch) requires Tier::Firecracker.
    /// Never silently downgrade: error names the loss.
    pub fn require_governed(&self) -> Result<()> {
        match self.tier {
            Tier::Firecracker => Ok(()),
            Tier::FallbackNoKvm => bail!(
                "fail-closed: no KVM (present={} module={}); governed work refused. \
                 Run `somp doctor` for the tier table; use Tier 1/2 only for explicitly ungoverned tasks",
                self.kvm_present, self.kvm_module
            ),
        }
    }
}

pub fn doctor() -> Result<()> {
    let c = check()?;
    println!("tier:          {:?}", c.tier);
    println!("/dev/kvm:      {}", c.kvm_present);
    println!("kvm module:    {}", c.kvm_module);
    println!("nft usable:    {}", c.nft_usable);
    println!("bwrap userns:  {}", c.bwrap_ok);
    println!();
    println!("Tier 0 Firecracker+Guard+srt: {}", if c.tier == Tier::Firecracker { "CANDIDATE" } else { "UNAVAILABLE (refuses governed work)" });
    println!("Tier 1 Docker (ungoverned dev only): available if docker present");
    println!("Tier 2 Bubblewrap/srt-only (no outer boundary): {}", if c.bwrap_ok { "available, refuses governed work" } else { "bwrap probe FAILED" });
    if !c.nft_usable {
        println!("note: nft unusable here — Guard enforcement lives on the AIec worker host, not this machine");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_refuses_governed() {
        let c = TierCheck {
            tier: Tier::FallbackNoKvm,
            kvm_present: false,
            kvm_module: false,
            nft_usable: false,
            bwrap_ok: true,
        };
        assert!(c.require_governed().is_err());
    }

    #[test]
    fn firecracker_allows_governed() {
        let c = TierCheck {
            tier: Tier::Firecracker,
            kvm_present: true,
            kvm_module: true,
            nft_usable: true,
            bwrap_ok: true,
        };
        assert!(c.require_governed().is_ok());
    }
}

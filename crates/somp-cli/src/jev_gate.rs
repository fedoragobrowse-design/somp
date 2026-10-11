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
	
	/// Deterministic network-command deny: runs BEFORE any classifier call.
	/// Rationale: the destructive-probability question lets network egress
	/// through (`curl https://…` is not destructive, so p≈0 → allow). Host
	/// bash has no NIC policy to enforce — the governed stance is that host
	/// shells do not touch the network at all; network work belongs in the
	/// somp_task guest. A model verdict must never be able to allow what is
	/// structurally refused, so this check is lexical, not classified.
	/// Matches: URL literals (http/https/ws/ftp/ssh), well-known egress
	/// binaries (curl/wget/ssh/nc/socat + exfil aliases), DNS/ICMP/recon
	/// tools (ping/dig/nslookup/host/traceroute/nmap/tcpdump), `getent
	/// hosts` (DNS resolution; plain `getent passwd` stays allowed),
	/// interpreter inline code naming socket/shell-out APIs (`python3 -c
	/// "socket.…"`, `node -e`, `perl -e`, `python3 -m http.server`), and
	/// `> /dev/tcp|udp/` + awk `/inet/tcp|udp/` redirections.
	/// Case-insensitive; matched token is returned for the refusal message
	/// (token only, never command bytes).
	/// NOT covered: obfuscated imports (`__import__('so'+'cket')`), file
	/// arguments whose contents open sockets (`python3 evil.py`) — string
	/// matching cannot see those; the durable fix is a netns (see UNPROVEN).
	/// Prefix commands that only wrap another command's argv (`timeout 10
	/// curl …`, `sudo -u u ping …`, `bash -c "nc …"`, `… | xargs curl`).
	/// After stripping, the remainder is token-scanned for tools — but ONLY
	/// when a wrapper was actually stripped, so `grep -e curl` (no wrapper,
	/// prose match) stays allowed while wrapper-laundered tools fail closed.
	const WRAPPERS: &[&str] = &[
	    "env", "timeout", "sudo", "doas", "runuser", "su", "nice", "nohup",
	    "stdbuf", "unshare", "nsenter", "setsid", "flock", "ionice",
	    "taskset", "numactl", "strace", "watch", "sh", "bash", "dash",
	    "zsh", "fish", "ksh", "xargs", "script",
	];
	
	/// Strip leading wrapper names; returns (remainder, progressed).
	/// Loops so `sudo timeout 5 curl` strips twice. Flags/args between the
	/// wrapper and the real command are NOT parsed — the remainder is
	/// token-scanned instead (`timeout -s KILL 5 curl` still hits `curl`).
	fn strip_wrappers(mut s: &str) -> (&str, bool) {
	    let mut progressed = false;
	    while let Some(r) = WRAPPERS.iter().find_map(|w| {
	        let t = s.trim_start();
	        if t == *w || (t.starts_with(w) && t[w.len()..].starts_with([' ', '\t', '\n'])) {
	            Some(&t[w.len()..])
	        } else {
	            None
	        }
	    }) {
	        s = r;
	        progressed = true;
	    }
	    (s.trim_start(), progressed)
	}
	
	/// Any whitespace/punct-delimited token of `s` names `tool`
	/// (path-basename-aware: `/usr/bin/ping` counts as `ping`).
	fn remainder_has_tool(s: &str, tool: &str) -> bool {
	    s.split([' ', '\t', '\n', ';', '|', '&', '(', ')', '`', '"', '\'', '{', '}', '$', ',', ':', '=', '+'])
	        .any(|tok| tok == tool || (tok.contains('/') && tok.rsplit('/').next() == Some(tool)))
	}
	
	/// Whole command + every shell-separator tail (incl `find -exec`): each
	/// is an independent candidate for tool matching.
	fn candidates(lower: &str) -> Vec<&str> {
	    const SEPS: &[&str] = &[";", "&&", "||", "|", "$(", "`", "\n", "-exec", "-execdir"];
	    let mut out = vec![lower];
	    let mut rest = lower;
	    while let Some(idx) = SEPS.iter().filter_map(|s| rest.find(s)).min() {
	        let mut tail = &rest[idx..];
	        if let Some(r) = tail.strip_prefix("-execdir") { tail = r; }
	        else if let Some(r) = tail.strip_prefix("-exec") { tail = r; }
	        else { tail = tail.trim_start_matches([';', '&', '|', '(', '`', '$', '{', ' ', '\t']); }
	        out.push(tail);
	        rest = &rest[(idx + 1).min(rest.len())..];
	    }
	    out
	}
	
	/// True when the candidate invokes `tool`: direct at start
	/// (absolute-path aware: `/usr/bin/ping` matches `ping`), or as any
	/// argv token once a WRAPPERS prefix was stripped (`timeout 5 ping …`,
	/// `bash -c "nc …"`, `… | xargs curl`). `echo curl` prose stays false.
	fn candidate_has_tool(cand: &str, tool: &str) -> bool {
	    const AFTER: [char; 9] = [' ', '\t', '\n', '-', '/', '"', '\'', ')', '}'];
	    let t = cand.trim_start();
	    if t == tool || (t.starts_with(tool) && t[tool.len()..].starts_with(AFTER)) {
	        return true;
	    }
	    if let Some(first) = t.split([' ', '\t', '\n']).next() {
	        if first.contains('/') && first.rsplit('/').next() == Some(tool) {
	            return true;
	        }
	    }
	    let (stripped, progressed) = strip_wrappers(t);
	    if progressed && remainder_has_tool(stripped, tool) {
	        return true;
	    }
	    false
	}
	
	/// True when `lower` invokes `tool` at command start or after a shell
	/// separator (`echo curl` prose stays false, `curl …` / `x && curl …`
	/// stay true). Shared by the TOOL_MARKERS loop + getent/interp checks.
	fn starts_tool(lower: &str, tool: &str) -> bool {
	    candidates(lower).iter().any(|c| candidate_has_tool(c, tool))
	}
	
	pub fn deny_network_command(command: &str) -> Option<&'static str> {
	    const URL_MARKERS: &[&str] = &[
	        "http://", "https://", "ws://", "wss://", "ftp://", "ssh://",
	        "git://",
	    ];
	    // Trailing space requires token-boundary: "nc" must not fire on "sync".
	    // NOTE (delta audit 2026-10-11): this list is a best-effort screen,
	    // not a boundary. `openssl s_client -connect` held a live TLS tunnel
	    // past the previous list; it and its cousins are named here, but the
	    // set of socket-capable binaries is unbounded — the durable fix is a
	    // netns for host bash (see UNPROVEN), not more names.
	    const TOOL_MARKERS: &[&str] = &[
	        "curl ", "wget ", "ssh ", "scp ", "sftp ", "ftp ", "nc ", "ncat ",
	        "socat ", "telnet ", "rsync ", "rclone ", "aria2c ", "axel ",
	        "httpx ", "http ", "wget2 ", "lftp ",
	        "ping ", "ping6 ", "dig ", "nslookup ", "host ", "traceroute ",
	        "tracepath ", "arping ", "fping ", "hping3 ", "nping ", "nmap ",
	        "masscan ", "mtr ", "whois ", "tcpdump ", "tshark ",
	        // TLS-tunnel-capable stock binaries (delta audit): openssl is on
	        // essentially every box; gnutls-cli/stunnel/ncat are its cousins.
	        "openssl ", "gnutls-cli ", "gnutls-serv ", "stunnel ",
	        "s_client ", "s_server ", "openconnect ", "vpnc ", "iodine ",
	        // DB/queue clients with network backends + misc socket holders.
	        "mysql ", "psql ", "pgcli ", "mycli ", "redis-cli ", "mongosh ",
	        "mongo ", "mosquitto_pub ", "mosquitto_sub ", "busybox ",
	    ];
	    const REDIR_MARKERS: &[&str] = &[
	        "/dev/tcp/", "/dev/udp/", "/inet/tcp/", "/inet/udp/",
	    ];
	    let lower = command.to_lowercase();
	    for &m in URL_MARKERS {
	        if lower.contains(m) {
	            return Some(m.trim_end_matches("://"));
	        }
	    }
	    // Tools match at command start or after a shell separator — `echo
	    // curl` (the WORD curl in prose) must not fire, `curl …` must.
	    // `host` needs a space boundary so `ghost`/`hostname` stay allowed.
	    for &m in TOOL_MARKERS {
	        let name = m.trim_end();
	        if starts_tool(&lower, name) {
	            return Some(name);
	        }
	    }
	    // `git clone/fetch/pull/push/ls-remote` open the network; local-only
	    // git (status/diff/log/add/commit/show/branch) stays allowed — the
	    // dispatch diff loop depends on it. Matches subcommand as an argv
	    // token so prose ("clone the repo pattern") does not fire.
	    const GIT_NET: &[&str] = &[
	        "clone", "fetch", "pull", "push", "ls-remote", "archive",
	        "submodule",
	    ];
	    if starts_tool(&lower, "git") {
	        let cands = candidates(&lower);
	        for cand in &cands {
	            let (stripped, _) = strip_wrappers(cand);
	            let toks: Vec<&str> = stripped.split_whitespace().collect();
	            // toks[0] is git (or its path); scan flags-aware: first
	            // non-flag token after git is the subcommand. `-C <path>`
	            // / `-c name=val` / `--git-dir <path>` consume the next
	            // token (or are attached/self-contained) — without this,
	            // `git -C /tmp/x fetch` misreads the path as the subcommand.
	            const ARG_FLAGS: &[&str] = &[
	                "-C", "-c", "--git-dir", "--work-tree", "--namespace",
	                "--super-prefix", "--config-env",
	            ];
	            let mut sub = None;
	            let mut skip_next = false;
	            for t in toks.iter().skip(1) {
	                if skip_next {
	                    skip_next = false;
	                    continue;
	                }
	                if t.starts_with('-') && *t != "-" {
	                    // Attached/self-contained (`-C/tmp/x`, `-cname=v`,
	                    // `--git-dir=/p`): flag carries its own value.
	                    let attached = (*t != "-C" && t.starts_with("-C"))
	                        || (*t != "-c" && t.starts_with("-c"))
	                        || (t.contains('=') && !t.starts_with("--exec-path"));
	                    if !attached && ARG_FLAGS.contains(t) {
	                        skip_next = true;
	                    }
	                    continue;
	                }
	                sub = Some(*t);
	                break;
	            }
	            if let Some(s) = sub {
	                let base = s.rsplit('/').next().unwrap_or(s);
	                if GIT_NET.contains(&base) {
	                    return Some("git remote");
	                }
	            }
	        }
	    }
	    if starts_tool(&lower, "getent") && lower.contains("hosts") {
	        return Some("getent hosts");
	    }
	    // Interpreter inline code naming socket/shell-out APIs: `python3 -c
	    // "socket.create_connection(…)"` opened a real TCP socket in the
	    // paste-6 audit. Match interpreter + inline/module flag + network
	    // token in the same command. Plain `python3 script.py` (file contents
	    // unseen) and bare `-c` code without network tokens still reach the
	    // classifier.
	    const INTERP: &[&str] = &["python", "python3", "node", "bun", "deno", "perl", "ruby", "php", "lua", "r", "julia"];
	    const INLINE_FLAG: &[&str] = &["-c", "-e", "--eval", "--execute", "-r", "-ro", "-m", "http.server", "socketserver"];
	    const NET_TOKENS: &[&str] = &[
	        "socket", "urllib", "requests", "fetch(", "xmlhttprequest",
	        "net::", "tcpclient", "udpclient", "netcat", "getaddrinfo",
	        "create_connection", "fsockopen", "stream_socket_client",
	        "io::socket", "tcpsocket", "udpsocket", "http::", "reqwest",
	        "curl_easy", "libcurl", "winsock", "wsasocket", "http.server",
	        "socketserver", "httpserver", "webbrowser",
	    ];
	    let has_interp = INTERP.iter().any(|i| starts_tool(&lower, i));
	    if has_interp
	        && (INLINE_FLAG.iter().any(|f| lower.contains(f)) || lower.contains("socket"))
	        && NET_TOKENS.iter().any(|t| lower.contains(t))
	    {
	        return Some("interpreter socket");
	    }
	    REDIR_MARKERS.iter().copied().find(|m| lower.contains(m))
	}
	/// Live gate: classify `command` via the configured backend, then decide().
	/// Deterministic network-command deny runs first (no key needed): host
	/// bash never touches the network; network work belongs in somp_task.
	/// Then the backend classifier as before. Fail-closed throughout.
	pub async fn gate(command: &str, cfg: &crate::config::JevCfg) -> Result<()> {
	    if let Some(token) = deny_network_command(command) {
	        bail!("JEV gate: network egress in host bash refused ({token}) — run it inside a disposable microVM via somp_task instead");
	    }
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
	    // Response headers BEFORE consuming the body: content-type/length/
	    // encoding decide whether a decode failure is gzip-misread, SSE
	    // stream, or provider error page. Header VALUES are provider-chosen
	    // (no key bytes: bearer travels in the REQUEST header, and command
	    // bytes never leave our prompt) — safe to log.
	    let ctype = resp.headers().get(reqwest::header::CONTENT_TYPE)
	        .and_then(|v| v.to_str().ok()).unwrap_or("<absent>").to_owned();
	    let clen = resp.headers().get(reqwest::header::CONTENT_LENGTH)
	        .and_then(|v| v.to_str().ok()).unwrap_or("<absent>").to_owned();
	    let cenc = resp.headers().get(reqwest::header::CONTENT_ENCODING)
	        .and_then(|v| v.to_str().ok()).unwrap_or("<absent>").to_owned();
	    if !status.is_success() {
	        anyhow::bail!("JEV gate (openrouter): classifier HTTP {status} ctype={ctype} clen={clen} cenc={cenc} — refusing");
	    }
	    // Decode envelope from raw BYTES (not resp.text()/resp.json()): the
	    // rm -rf probe returned 2xx with a body that fails UTF-8 decode, so
	    // str-decoding is exactly what breaks. bytes→lossy→parse keeps the
	    // fail-closed contract (parse still strict) while the diagnostic
	    // samples the first 200 chars of whatever arrived.
	    let bytes = resp.bytes().await
	        .map_err(|e| anyhow::anyhow!("JEV gate (openrouter): unreadable body ({e:#}) status={status} ctype={ctype} clen={clen} cenc={cenc} — refusing"))?;
	    let raw = String::from_utf8_lossy(&bytes);
	    let v: serde_json::Value = serde_json::from_str(&raw)
	        .map_err(|e| {
	            let sample: String = raw.chars().take(200).collect();
	            anyhow::anyhow!("JEV gate (openrouter): envelope not JSON ({e:#}) status={status} ctype={ctype} clen={clen} cenc={cenc} nbytes={} body={sample:?} — refusing", bytes.len())
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
	    #[test]
	    fn delta_audit_tls_tunnel_and_wrappers_denied() {
	        // Delta audit 2026-10-11: `openssl s_client -connect` held a
	        // live TLSv1.3 tunnel past the previous list — highest-value
	        // keyhole left. Plus wrapper-laundering + git remote shapes.
	        for cmd in [
	            "openssl s_client -connect example.com:443 -quiet",
	            "echo | openssl s_client -connect 192.0.2.1:443",
	            "gnutls-cli example.com",
	            "stunnel /etc/stunnel/x.conf",
	            "busybox wget http://example.com/x",
	            "mysql -h db.example.com -u u -p",
	            "psql -h db.example.com -U u",
	            "git clone https://example.com/r.git",
	            "git -C /tmp/x fetch origin",
	            "git pull",
	            "git ls-remote https://example.com/r.git",
	            "timeout 10 curl -sI https://example.com",
	            "sudo -u nobody ping -c 1 1.1.1.1",
	            "bash -c \"nc example.com 80\"",
	            "echo x | xargs curl -sI https://example.com",
	            "timeout 5 openssl s_client -connect example.com:443",
	            "/usr/bin/openssl s_client -connect example.com:443",
	        ] {
	            assert!(deny_network_command(cmd).is_some(), "must deny: {cmd}");
	        }
	    }
	
	    #[test]
	    fn delta_safe_shapes_stay_allowed() {
	        // Wrappers alone are not egress; local-only git stays allowed
	        // (dispatch diff loop depends on it); sqlite3 has no backend.
	        for cmd in [
	            "timeout 10 echo done",
	            "sudo -u nobody id",
	            "git status",
	            "git -C /workspace/repository diff --binary",
	            "git log --oneline -5",
	            "git add -N .",
	            "sqlite3 /tmp/x.db 'select 1'",
	            "grep -e curl src/",
	            "echo openssl is a tool",
	        ] {
	            assert!(deny_network_command(cmd).is_none(), "must allow: {cmd}");
	        }
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
	
	    #[test]
	    fn network_egress_denied_deterministically() {
	        // The classifier question is destructive-only: curl is not
	        // destructive, so without this lexical deny it would allow.
	        for cmd in [
	            "curl -sI https://example.com | head -3",
	            "wget -q http://example.com/x -O /tmp/x",
	            "ssh user@host true",
	            "echo hi | nc example.com 80",
	            "echo data > /dev/tcp/10.0.0.1/443",
	            "CURL -s https://example.com",
	            "true && curl -s https://example.com",
	        ] {
	            assert!(deny_network_command(cmd).is_some(), "must deny: {cmd}");
	        }
	    }
	
	    #[test]
	    fn network_deny_covers_paste6_leak_classes() {
	        // Paste-6 pentest evidence: getent (DNS), ping (ICMP), and
	        // python3 -c socket (full L4) all reached the live network.
	        for cmd in [
	            "getent hosts example.com",
	            "ping -c 1 -W 2 1.1.1.1",
	            "ping6 -c 1 ::1",
	            "dig +short example.com",
	            "nslookup example.com",
	            "host example.com",
	            "traceroute 1.1.1.1",
	            "nmap -sn 192.168.1.0/24",
	            "python3 -c \"import socket;s=socket.create_connection(('example.com',80),5)\"",
	            "python -c \"import urllib.request;print(urllib.request.urlopen('http://example.com').status)\"",
	            "node -e \"fetch('http://example.com').then(r=>console.log(r.status))\"",
	            "perl -e \"use IO::Socket;IO::Socket::INET->new('example.com:80')\"",
	            "ruby -rsocket -e \"TCPSocket.new('example.com',80)\"",
	            "php -r \"$s=fsockopen('example.com',80);\"",
	            "python3 -m http.server 8080",
	            "awk 'BEGIN{print > \"/inet/tcp/10.0.0.1/80\"}'",
	        ] {
	            assert!(deny_network_command(cmd).is_some(), "must deny: {cmd}");
	        }
	    }
	
	    #[test]
	    fn network_deny_has_no_false_positives_on_safe_words() {
	        // "sync"/"echo curl" contain decoy substrings but run no network.
	        // "hostname"/"ghost" contain the "host" marker as a prefix-word.
	        for cmd in [
	            "sync", "echo hello", "echo curl is a tool", "ls -la",
	            "hostname", "echo ghost", "getent passwd root",
	            "python3 script.py", "node server.js",
	            "echo ping is a word", "grep -r hosts src/",
	        ] {
	            assert!(deny_network_command(cmd).is_none(), "must allow: {cmd}");
	        }
	    }
	}

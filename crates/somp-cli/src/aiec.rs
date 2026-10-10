//! Minimal AIec control-plane client (subset of crates/aiec-client surface).
//! Shapes verified against AIec 0f516df: AIecClient::new(base_url, api_key),
//! create_sandbox_with_runtime (runtime merged into body), exec (ExecRequest
//! {command, working_directory?, environment?, timeout_seconds?, stdin?}),
//! git_diff, start/stop, guard proposal/events/show endpoints per CLI surface.
//!
//! No silent downgrade: callers pin runtime "firecracker" for governed work.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sandbox {
    pub id: uuid::Uuid,
    pub state: String,
    #[serde(default)]
    pub runtime: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecResult {
    pub exit_code: i32,
    #[serde(default)]
    pub stdout: String,
    #[serde(default)]
    pub stderr: String,
    #[serde(default)]
    pub duration_ms: u64,
}

#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    base_url: String,
    api_key: String,
}

impl Client {
    pub fn new(base_url: String, api_key: String) -> Result<Self> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("build http client")?;
        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_owned(),
            api_key,
        })
    }

    fn req(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.http
            .request(method, format!("{}{}", self.base_url, path))
            .bearer_auth(&self.api_key)
    }

    async fn send<T: serde::de::DeserializeOwned>(
        &self,
        b: reqwest::RequestBuilder,
    ) -> Result<T> {
        let resp = b.send().await.context("control-plane request")?;
        let status = resp.status();
        let bytes = resp.bytes().await.context("read response")?;
        if !status.is_success() {
            let msg = serde_json::from_slice::<serde_json::Value>(&bytes)
                .map(|v| v.to_string())
                .unwrap_or_else(|_| String::from_utf8_lossy(&bytes).into_owned());
            anyhow::bail!("control plane {}: {}", status, msg);
        }
        serde_json::from_slice(&bytes).context("decode response")
    }

    pub async fn create_sandbox_with_runtime(
        &self,
        request: &serde_json::Value,
        runtime: &str,
    ) -> Result<Sandbox> {
        let mut body = request.clone();
        body["runtime"] = serde_json::json!(runtime);
        let sb: Sandbox = self
            .send(self.req(reqwest::Method::POST, "/v1/sandboxes").json(&body))
            .await
            .context("create_sandbox")?;
        if sb.runtime != runtime {
            anyhow::bail!(
                "fail-closed: requested runtime {runtime} but got {} — refusing",
                sb.runtime
            );
        }
        Ok(sb)
    }

    pub async fn get_sandbox(&self, id: uuid::Uuid) -> Result<Sandbox> {
        self.send(self.req(reqwest::Method::GET, &format!("/v1/sandboxes/{id}")))
            .await
    }

    pub async fn delete_sandbox(&self, id: uuid::Uuid) -> Result<()> {
        let resp = self
            .req(reqwest::Method::DELETE, &format!("/v1/sandboxes/{id}"))
            .send()
            .await
            .context("delete sandbox")?;
        if !resp.status().is_success() {
            anyhow::bail!("delete sandbox: {}", resp.status());
        }
        Ok(())
    }

    pub async fn exec_command(
        &self,
        id: uuid::Uuid,
        command: Vec<String>,
        workdir: Option<String>,
        timeout_s: u64,
    ) -> Result<ExecResult> {
        let body = serde_json::json!({
            "command": command,
            "working_directory": workdir,
            "timeout_seconds": timeout_s,
        });
        self.send(
            self.req(reqwest::Method::POST, &format!("/v1/sandboxes/{id}/exec"))
                .json(&body),
        )
        .await
    }

    pub async fn put_file(&self, id: uuid::Uuid, path: &str, content: &[u8]) -> Result<()> {
        let body = serde_json::json!({
            "path": path,
            "content_base64": base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                content
            ),
        });
        let resp = self
            .req(reqwest::Method::PUT, &format!("/v1/sandboxes/{id}/files"))
            .json(&body)
            .send()
            .await
            .context("put file")?;
        if !resp.status().is_success() {
            anyhow::bail!("put file: {}", resp.status());
        }
        Ok(())
    }

    /// POST /v1/sandboxes/{id}/git/diff (verified: lib.rs:964; requires Running).
    pub async fn git_diff(&self, id: uuid::Uuid) -> Result<serde_json::Value> {
        self.send(self.req(reqwest::Method::POST, &format!("/v1/sandboxes/{id}/git/diff")))
            .await
    }

    /// POST /v1/sandboxes/{id}/snapshots {kind?} -> Snapshot (verified: lib.rs:999-1001,
    /// CreateSnapshotRequest{kind?}, aiec-core lib.rs:622-625). Returns the Snapshot JSON.
    pub async fn create_snapshot(
        &self,
        id: uuid::Uuid,
        kind: Option<&str>,
    ) -> Result<serde_json::Value> {
        let body = match kind {
            Some(k) => serde_json::json!({ "kind": k }),
            None => serde_json::json!({}),
        };
        self.send(
            self.req(reqwest::Method::POST, &format!("/v1/sandboxes/{id}/snapshots"))
                .json(&body),
        )
        .await
    }

    /// POST /v1/snapshots/{snapshot_id}/restore {image?,cpu?,memory_mb?,disk_mb?,runtime?}
    /// (verified: lib.rs:1003, RestoreSnapshotRequest aiec-core lib.rs:614-620).
    /// NOTE: restore targets the SNAPSHOT id, not the sandbox id.
    pub async fn restore_snapshot(&self, snapshot_id: uuid::Uuid) -> Result<serde_json::Value> {
        self.send(
            self.req(reqwest::Method::POST, &format!("/v1/snapshots/{snapshot_id}/restore"))
                .json(&serde_json::json!({})),
        )
        .await
    }

    /// POST /v1/sandboxes/{id}/guard/proposals {request:{summary,allow[]}}
    /// (verified: guard_proposals.rs:695-702, SubmitProposalBody{request: ProposalRequest},
    /// ProposalRequest{summary, allow: Vec<EgressGrant{host,port,methods?,paths?>>}).
    /// Add-only: a request can never remove/narrow rules. Approval is a separate
    /// human key (independent reviewer required); agent approval always 403s.
    pub async fn submit_proposal(
        &self,
        id: uuid::Uuid,
        summary: &str,
        allow: Vec<serde_json::Value>,
    ) -> Result<serde_json::Value> {
        let body = serde_json::json!({ "request": { "summary": summary, "allow": allow } });
        self.send(
            self.req(
                reqwest::Method::POST,
                &format!("/v1/sandboxes/{id}/guard/proposals"),
            )
            .json(&body),
        )
        .await
    }

    /// GET /v1/sandboxes/{id}/guard/proposals — pending + decided (the journal read).
    pub async fn list_proposals(&self, id: uuid::Uuid) -> Result<serde_json::Value> {
        self.send(
            self.req(reqwest::Method::GET, &format!("/v1/sandboxes/{id}/guard/proposals")),
        )
        .await
    }

    /// GET one proposal (includes state: pending/approved/denied + policy hash).
    pub async fn get_proposal(
        &self,
        id: uuid::Uuid,
        proposal: uuid::Uuid,
    ) -> Result<serde_json::Value> {
        self.send(self.req(
            reqwest::Method::GET,
            &format!("/v1/sandboxes/{id}/guard/proposals/{proposal}"),
        ))
        .await
    }
}

/**
 * somp-omp-ext — sOMP extension for omp (no omp source changes).
 *
 * Design note (verified against omp 46ad329, Phase 2): the extension seams
 * CANNOT transparently relocate a `task` spawn into a microVM —
 * BeforeSubagentSpawnEventResult is {model?, block?, reason?, note?} only
 * (types.ts:1301-1310) and a block surfaces as StructuredSubagentError; the
 * `tool_call` result is {block?, reason?, input?, additionalContext?} only
 * (shared-events.ts:325-345). So this extension does three things instead:
 *
 *  1. In governed mode (SOMP_GOVERNED=1): blocks the local `task` tool with a
 *     reason that directs the model to `somp_task`, and registers `somp_task`
 *     which shells out to the `somp dispatch` CLI (AIec create -> stage ->
 *     exec -> git_diff -> destroy, fail-closed).
 *  2. In session-VM mode (SOMP_SRT=1): rewrites `bash` tool input to prefix
 *     the srt wrapper (`srt --settings <file> sh -c <command>`), so tool
 *     processes run under bwrap --unshare-net + fs rules inside the guest.
 *  3. Registers /somp-status (tier + mode report).
 *
 * A future upstream SubagentRunner seam would let somp_task's body move into
 * the `task` tool itself; the dispatch protocol below is shaped for that.
 */
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { unlink } from "node:fs/promises";

function envFlag(name: string): boolean {
	const v = process.env[name];
	return v === "1" || v?.toLowerCase() === "true";
}

const SOMP_PATH = process.env.SOMP_BIN ?? "somp";
const SRT_SETTINGS_PATH = process.env.SOMP_SRT_SETTINGS ?? "/etc/somp/srt-settings.json";

export default function sompExt(pi: ExtensionAPI) {
	const z = pi.zod;
	const governed = envFlag("SOMP_GOVERNED");
	const srtWrap = envFlag("SOMP_SRT");

	pi.logger.info(`somp-ext loaded (governed=${governed} srt=${srtWrap})`);
	// --- 0. Security level: SOMP_LEVEL env wins; else `somp level` (config
	// file); else strict default. Badge lives in the TUI status bar via
	// ctx.ui.setStatus (session_start + live update on /somp-level).
	function resolveLevel(): { level: string; source: string } {
		const env = process.env.SOMP_LEVEL?.toLowerCase();
		if (env === "strict" || env === "standard" || env === "off") {
			return { level: env, source: "SOMP_LEVEL env" };
		}
		try {
			const r = spawnSync(SOMP_PATH, ["level"], { encoding: "utf-8", timeout: 5000 });
			const m = /level: (\w+)/.exec(r.stdout ?? "");
			if (m) return { level: m[1].toLowerCase(), source: "somp config" };
		} catch {
			/* fall through to default */
		}
		return { level: "strict", source: "default" };
	}
	const { level: secLevel, source: secSource } = resolveLevel();
	const levelBadge = (l: string) =>
		l === "strict" ? "🛡️ STRICT" : l === "standard" ? "🔶 STANDARD" : "⚠️ OFF";
	pi.logger.info(`somp-ext security level=${secLevel} (${secSource})`);

	pi.on("session_start", async (_event, ctx) => {
		if (!ctx.hasUI) return;
		ctx.ui.setStatus("somp-level", `sandbox ${levelBadge(secLevel)}`);
	});
	// Governed resume: omp prints `omp --resume <id>` on TUI exit, which
	// would reload the session WITHOUT this extension (unguarded). The
	// wrapper passes argv through, so `somp-omp --resume <id>` keeps the
	// governed seam. Remind on shutdown; the id is on omp's hint line.
	pi.on("session_shutdown", async (_event, ctx) => {
		if (!governed) return;
		const msg =
			"sOMP: to stay governed, resume with `somp-omp --resume <id>` " +
			"(same <id> as omp's hint above) — plain `omp --resume` loads UNgoverned.";
		if (ctx.hasUI) ctx.ui.notify(msg);
		else process.stderr.write(`\n${msg}\n`);
	});
// Rewrite the exact hint lines omp emits (`omp [--profile P] --resume <id>`,
// resume-command.ts) so history/persistence carry the governed form.
// Idempotent: negative lookbehind skips already-rewritten `somp-omp` lines.
// The id must be UUID-ish (real hint lines carry one) so prose/docs
// mentioning `omp --resume` without an id are left alone.
const RESUME_HINT_RE = /(?<!somp-)omp (--profile \S+ )?--resume ([0-9a-fA-F]{8}-[0-9a-fA-F-]{6,})/g;
if (governed) {
	pi.on("assistant_message", async event => {
		const content = event.message.content;
		let changed = false;
		const next = content.map(block => {
			if (block.type !== "text" || typeof block.text !== "string") return block;
			if (!RESUME_HINT_RE.test(block.text)) return block;
			RESUME_HINT_RE.lastIndex = 0;
			changed = true;
			return { ...block, text: block.text.replace(RESUME_HINT_RE, "somp-omp $1--resume $2") };
		});
		if (!changed) return undefined;
		return { content: next };
	});
}
	// --- 1. Governed mode: block local task spawns, offer somp_task ---
	if (governed) {
		pi.on("tool_call", async event => {
			if (event.toolName !== "task") return undefined;
			return {
				block: true,
				reason:
					"sOMP governed mode: local in-process subagents are disabled. " +
					"Use the somp_task tool instead — it runs the subagent in a disposable " +
					"AIec microVM (Guard model-endpoint-only egress) and returns result+diff. " +
					"If somp_task is unavailable, stop and tell the operator.",
			};
		});

		pi.registerTool({
			name: "somp_task",
			label: "sOMP governed subagent",
			description:
				"Run a subagent task inside a disposable AIec microVM with Guard " +
				"model-endpoint-only egress and srt inner sandboxing. " +
				"Stays equivalent to the task tool: takes a prompt plus optional file " +
				"context, returns the subagent's result text and a unified diff. " +
				"Prefer this over task whenever it is available.",
			parameters: z.object({
				prompt: z.string().describe("Subagent task prompt (markdown)"),
				files: z
					.array(z.string())
					.optional()
					.describe("Host paths to stage into the guest workspace"),
				timeout_s: z.number().optional().describe("Guest exec timeout seconds (default 600)"),
			}),
			async execute(_toolCallId, params, _onUpdate, _ctx, signal) {
				const bin = SOMP_PATH;
				// randomBytes, not Date.now-pid: two same-ms dispatches from
				// forked operator processes would share (and race on) one path.
				const tmpTask = `${process.env.TMPDIR ?? "/tmp"}/somp-task-${randomBytes(8).toString("hex")}.md`;
				await Bun.write(tmpTask, params.prompt as string);
				try {
					const args = ["dispatch", "--task-file", tmpTask];
					// Indexed guest names (context-0-foo.py, …): two host files
					// with the same basename would otherwise collide in REPO.
					let i = 0;
					for (const f of (params.files as string[] | undefined) ?? []) {
						args.push("--file", `/workspace/repository/context-${i++}-${f.split("/").pop()}=${f}`);
					}
					if (params.timeout_s !== undefined) {
						args.push("--timeout-s", String(params.timeout_s));
					}
					const started = Date.now();
					const r = spawnSync(bin, args, {
						encoding: "utf-8",
						timeout: ((params.timeout_s as number | undefined) ?? 600) * 1000 + 30_000,
						env: process.env,
					});
					if (signal?.aborted) {
						return {
							content: [{ type: "text", text: "somp_task aborted by caller" }],
							details: { aborted: true },
						};
					}
					const wallMs = Date.now() - started;
					if (r.error) {
						return {
							content: [{ type: "text", text: `somp dispatch failed to spawn: ${String(r.error)}` }],
							details: { error: String(r.error), wallMs },
							isError: true,
						};
					}
					if (r.status !== 0) {
						return {
							content: [
								{
									type: "text",
									text: `somp dispatch exited ${r.status}: ${(r.stdout || r.stderr || "").slice(0, 4000)}`,
								},
							],
							details: { exitCode: r.status, stdout: r.stdout, stderr: r.stderr, wallMs },
							isError: true,
						};
					}
					let out: {
						exit_code?: number;
						stdout?: string;
						stderr?: string;
						diff?: unknown;
						sandbox_id?: string;
						start_ms?: number;
						duration_ms?: number;
					};
					try {
						out = JSON.parse(r.stdout);
					} catch {
						return {
							content: [{ type: "text", text: `somp dispatch returned non-JSON: ${r.stdout.slice(0, 2000)}` }],
							details: { raw: r.stdout.slice(0, 4000), wallMs },
							isError: true,
						};
					}
					const text =
						`[somp_task sandbox=${out.sandbox_id ?? "?"} vm_start_ms=${out.start_ms ?? "?"} ` +
						`exec_ms=${out.duration_ms ?? "?"} exit=${out.exit_code ?? "?"}]\n` +
						(out.stdout ?? "") +
						(out.diff ? `\n--- diff ---\n${typeof out.diff === "string" ? out.diff : JSON.stringify(out.diff).slice(0, 8000)}` : "");
					return {
						content: [{ type: "text", text }],
						details: out,
						...(out.exit_code !== 0 ? { isError: true } : {}),
					};
				} finally {
					// unlink, not `rm -f ${tmpTask}` through a shell: Bun.$
					// interpolates into sh source (space/metachar injection);
					// TMPDIR-owned path + unlink is exact.
					try {
						await unlink(tmpTask);
					} catch {
						/* best effort */
					}
				}
			},
		});
	}

	// --- 2. srt wrapping of bash inside guests ---
	if (srtWrap) {
		const settings = SRT_SETTINGS_PATH;
		if (!existsSync(settings)) {
			pi.logger.warn(`SOMP_SRT=1 but settings missing at ${settings}; bash rewrite disabled (fail-open avoided: flag is operator-set, refusing silently would lie)`);
		} else {
			pi.on("tool_call", async event => {
				if (event.toolName !== "bash") return undefined;
				const input = event.input as { command?: unknown } | undefined;
				if (typeof input?.command !== "string" || input.command.length === 0) return undefined;
				// Prefix the srt wrapper; the command string itself is untouched.
				// srt binary must be on guest PATH (guest image contract).
				return {
					input: {
						...input,
						command: `srt --settings ${JSON.stringify(settings)} sh -c ${JSON.stringify(input.command)}`,
					},
				};
			});
		}
	}

// --- 3. /somp-status + /somp-level ---
// NOTE: command handlers return void — notify() is the ONLY output channel,
// and it is a no-op in -p mode. Every handler below branches on ctx.hasUI
// (notify in TUI, stdout/stderr write otherwise) so print-mode invocations
// are never silently empty.
function say(ctx: { hasUI: boolean; ui: { notify: (m: string) => void } }, msg: string): void {
	if (ctx.hasUI) ctx.ui.notify(msg);
	else process.stdout.write(`${msg}\n`);
}
let cur = { level: secLevel, source: secSource };
pi.registerCommand("somp-status", {
	description: "Show sOMP mode, sandbox protection level, tier evidence",
	handler: async (_args, ctx) => {
		const kvm = existsSync("/dev/kvm");
		const lines = [
			`somp-ext: governed=${governed} srt=${srtWrap}`,
			`sandbox protection level: ${levelBadge(cur.level)} (${cur.level}) — ${cur.source}`,
			`/dev/kvm here: ${kvm} (guest tier evidence; worker tier is authoritative)`,
			`somp bin: ${SOMP_PATH}`,
			`srt settings: ${SRT_SETTINGS_PATH}${existsSync(SRT_SETTINGS_PATH) ? "" : " (MISSING)"}`,
			`seams: block-local-task + somp_task (transparent relocation needs upstream SubagentRunner seam — not present in omp 46ad329)`,
		];
		say(ctx, lines.join("\n"));
	},
});
	pi.registerCommand("somp-level", {
		description: "Show or set sandbox protection level: /somp-level [strict|standard|off]",
		handler: async (args, ctx) => {
			const want = args.trim().toLowerCase();
			if (!want) {
				say(ctx, `sandbox protection level: ${levelBadge(cur.level)} (${cur.level}) — ${cur.source}\nstrict = Firecracker microVM + Guard + srt · standard = Docker + Guard + srt (dev) · off = no sandboxing (governed work refused)`);
				return;
			}
			if (want !== "strict" && want !== "standard" && want !== "off") {
				say(ctx, `unknown level ${JSON.stringify(args.trim())}: want strict|standard|off`);
				return;
			}
			const r = spawnSync(SOMP_PATH, ["level", want], { encoding: "utf-8", timeout: 10000 });
			if (r.status !== 0) {
				say(ctx, `somp level failed: ${(r.stderr ?? "").trim() || "exit " + r.status}`);
				return;
			}
			// SOMP_LEVEL env wins at resolve time: a config write looks like a
			// no-op while the env var is set. Say so explicitly.
			if (process.env.SOMP_LEVEL) {
				say(ctx, `config written (${want}), but SOMP_LEVEL=${process.env.SOMP_LEVEL} is set and still wins — unset it or expect ${process.env.SOMP_LEVEL}`);
				return;
			}
			cur = { level: want, source: "somp config (set via /somp-level)" };
			if (ctx.hasUI) ctx.ui.setStatus("somp-level", `sandbox ${levelBadge(want)}`);
			say(ctx, `sandbox protection level → ${levelBadge(want)} (${want})`);
		},
	});
	pi.registerCommand("somp-model", {
		description: "Show or set Guard model endpoint: /somp-model [show|set <host> [port]|preset muse-spark]",
		handler: async (args, ctx) => {
			const parts = args.trim().split(/\s+/).filter(Boolean);
			const sub = (parts[0] ?? "show").toLowerCase();
			const rest = parts.slice(1);
			const cliArgs = sub === "show" && rest.length === 0 ? ["model", "show"]
				: sub === "set" && rest.length >= 1 ? ["model", "set", ...rest]
				: sub === "preset" && rest.length === 1 ? ["model", "preset", ...rest]
				: null;
			if (!cliArgs) {
				say(ctx, `usage: /somp-model [show|set <host> [port]|preset muse-spark]`);
				return;
			}
			const r = spawnSync(SOMP_PATH, cliArgs, { encoding: "utf-8", timeout: 10000 });
			say(ctx, ((r.stdout ?? "") + (r.stderr ?? "")).trim() || `somp model exit ${r.status}`);
		},
	});
	pi.registerCommand("somp-jev", {
		description: "JEV bash-gate: /somp-jev [status|on|off --allow-ungoverned-bash|model <name>|threshold <v>]",
		handler: async (args, ctx) => {
			const parts = args.trim().split(/\s+/).filter(Boolean);
			const sub = (parts[0] ?? "status").toLowerCase();
			const rest = parts.slice(1);
			const cliArgs = (sub === "status" && rest.length === 0) || (sub === "on" && rest.length === 0) ? ["jev", sub]
				: sub === "off" ? ["jev", "off", ...rest]
				: (sub === "model" || sub === "threshold") && rest.length === 1 ? ["jev", sub, ...rest]
				: null;
			if (!cliArgs) {
				say(ctx, `usage: /somp-jev [status|on|off --allow-ungoverned-bash|model <name>|threshold <v>]`);
				return;
			}
			const r = spawnSync(SOMP_PATH, cliArgs, { encoding: "utf-8", timeout: 10000 });
			say(ctx, ((r.stdout ?? "") + (r.stderr ?? "")).trim() || `somp jev exit ${r.status}`);
		},
	});
}

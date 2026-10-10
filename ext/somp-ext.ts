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
				const tmpTask = `${process.env.TMPDIR ?? "/tmp"}/somp-task-${Date.now()}-${process.pid}.md`;
				await Bun.write(tmpTask, params.prompt as string);
				try {
					const args = ["dispatch", "--task-file", tmpTask];
					for (const f of (params.files as string[] | undefined) ?? []) {
						args.push("--file", `/workspace/repository/${f.split("/").pop()}=${f}`);
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
					try {
						await Bun.file(tmpTask).exists().then(async ok => {
							if (ok) await Bun.$`rm -f ${tmpTask}`.quiet();
						});
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

	// --- 3. /somp-status ---
	pi.registerCommand("somp-status", {
		description: "Show sOMP mode, tier evidence, and seam notes",
		handler: async (_args, ctx) => {
			const kvm = existsSync("/dev/kvm");
			const lines = [
				`somp-ext: governed=${governed} srt=${srtWrap}`,
				`/dev/kvm here: ${kvm} (guest tier evidence; worker tier is authoritative)`,
				`somp bin: ${SOMP_PATH}`,
				`srt settings: ${SRT_SETTINGS_PATH}${existsSync(SRT_SETTINGS_PATH) ? "" : " (MISSING)"}`,
				`seams: block-local-task + somp_task (transparent relocation needs upstream SubagentRunner seam — not present in omp 46ad329)`,
			];
			ctx.ui.notify(lines.join("\n"));
		},
	});
}

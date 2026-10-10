# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

static HTML/CSS (delegated: user chose plain static HTML/CSS/JS over recommendation)

## Users

Developers running the omp coding agent who want subagent execution sandboxed
in disposable microVMs. They live in the terminal, already use omp with their
own skills and MCP servers, and evaluate tools by reading source and running
commands — not by marketing claims.

## Product Purpose

sOMP (Secure OMP) wraps omp so every subagent the model spawns runs inside a
disposable AIec microVM — srt-wrapped, Guard-egress-controlled — while the
operator's own omp session (skills, MCP, models, history) stays exactly as
upstream ships it. Success: governed `somp` feels identical to plain `omp`
except subagents can't touch the host.

## Positioning

The governed boundary is around subagent execution, not around the operator.
Plain `omp` runs untouched; governed mode is opt-in per invocation via the
`somp-omp` wrapper. Fail-closed everywhere: if a layer can't enforce, it
refuses to run — never a silent ungoverned fallback.

## Operating Context

Terminal-first workflow: `somp` opens the governed TUI, `somp level`
sets the protection tier, `somp update` pulls from the operator repo only.
Subagents run headless in AIec boxes (Firecracker strict, Docker standard),
return a git diff, then the box is destroyed. Guard egress is
model-endpoint-only by default; widening is propose + out-of-band human
approve + journal.

## Capabilities and Constraints

Confirmed: bare `somp` = governed TUI; `/somp-status`, `/somp-level`
commands; `task` tool blocked locally with `somp_task` redirect;
`srt` bash rewrite; secret scrubbing (`OPENAI/OPENROUTER/ANTHROPIC_API_KEY`,
`TYPESAFE_API_KEY`); `somp update` exact-origin gate. Unproven (must not be
claimed): <1s warm subagent start, per-subagent RSS — see docs/UNPROVEN.md.

## Brand Commitments

Name sOMP / Secure OMP. Sibling of omp/omp.sh (dark terminal aesthetic is
the family resemblance, not a copy). Voice: evidence-first terse engineer —
every sentence fact, decision, or risk. No invented testimonials, benchmarks,
or pricing.

## Evidence on Hand

Repo: https://github.com/fedoragobrowse-design/somp (public). Root README.md
(one-liner install, usage table). `somp doctor` tier output, `somp bench`
raw-JSON artifacts (git-ignored). No screenshots, no customer quotes — do not
fabricate.

## Product Principles

1. Prove, don't claim — every number traces to a measurement.
2. Fail closed, never silent — refusal beats ungoverned fallback.
3. Minimal wrapper, maximal upstream — `omp update` must never break `somp`.
4. Non-interference — plain `omp` runs exactly as before, always.
5. Honest limits — UNPROVEN.md is a feature, not an embarrassment.

## Accessibility & Inclusion

Terminal operators; standard web a11y (contrast, keyboard, reduced-motion)
for the site. No product-specific requirement established.

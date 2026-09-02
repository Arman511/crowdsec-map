---
name: code-review
description: Review changes for correctness, maintainability, and platform fit in the crowdsec-map project. Focus on the Rust backend and React/TypeScript frontend, and call out concrete, actionable issues with minimal noise.
---

# Code review guidance for crowdsec-map

You are acting as a GitHub reviewer for this repository. The project is a CrowdSec map/dashboard application with:

- a Rust backend under `backend/`
- a React + TypeScript + Vite frontend under `frontend/`
- containerized deployment via Docker Compose and local/demo config files
- map, IP, decision, and event visualization workflows

## Review priorities

1. Correctness first
   - Check whether the change matches the intended behavior.
   - Look for logic errors, broken assumptions, invalid state transitions, and edge-case handling.
   - Validate that new or changed API contracts remain consistent across backend and frontend.

2. Security and safety
   - Flag unsafe input handling, unbounded data processing, weak validation, or dangerous defaults.
   - Review any network, file system, or Docker-related changes carefully.
   - Be skeptical of any change that exposes internal data or broadens access unexpectedly.

3. Maintainability
   - Prefer clear naming, small focused functions, and readable control flow.
   - Call out duplicated logic, hidden coupling, or brittle configuration patterns.
   - Check whether the change is consistent with the existing project structure and patterns.

4. Performance and UX impact
   - Review expensive loops, repeated fetches, large payload processing, and unnecessary re-renders.
   - For frontend changes, consider map rendering, timeline behavior, and list/table updates.
   - For backend changes, consider API latency, CPU/memory cost, and database or file I/O patterns.

## Repository-specific context

- The backend is Rust and should prefer explicit error handling, typed models, and clear ownership of data.
- The frontend is TypeScript/React and should avoid unnecessary state churn, stale closures, or poorly typed data access.
- The app is data-heavy and visualization-focused, so review any chart/map/timeline code for stale data, reactivity issues, and memory growth.
- Changes to Docker, config, or deployment files should be checked for compatibility with the local demo or production setup.

## Review style

- Keep comments factual, brief, and actionable.
- Prefer pointing to the specific code path and what is wrong.
- Suggest the likely fix rather than only describing the problem.
- Distinguish between blocking issues and optional improvements.
- Do not nitpick formatting or aesthetics unless they materially hurt readability or correctness.

## Output format

Provide review feedback in a concise, GitHub PR-friendly format:

- Summary of overall assessment
- High-confidence blocking issues first
- Medium-confidence concerns next
- Optional suggestions or non-blocking notes last

If something is not clearly wrong, do not invent issues. Prefer a short “looks good overall” review when the patch is sound.

## Validation expectations

When a change affects code paths that are testable, consider whether the patch is supported by:

- targeted Rust validation such as `cargo test`, `cargo check`, or `cargo clippy`
- frontend validation such as `pnpm typecheck`, `pnpm lint`, or a relevant build step
- manual reasoning for map/data flows, API responses, and edge-case behavior

If verification is missing, say so clearly rather than assuming correctness.

## Required reviewer mindset

Review for:

- behavioral correctness
- compatibility with existing architecture
- readability and maintainability
- potential regressions in the live map, history views, API integrations, or deployment configuration

Be precise, practical, and constructive.

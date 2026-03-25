# CLAUDE.md — sigint

## gstack

Use `/browse` from gstack for all web browsing and site interaction. Never use `mcp__claude-in-chrome__*` tools.

**Available skills:**
- `/plan-ceo-review` — CEO/founder-mode plan review
- `/plan-eng-review` — Engineering manager plan review
- `/plan-design-review` — Designer's eye plan review
- `/design-consultation` — Design system creation
- `/review` — Pre-landing PR review
- `/ship` — Ship workflow (tests, PR, push)
- `/browse` — Headless browser for QA and site testing
- `/qa` — QA test and fix bugs
- `/qa-only` — QA report only (no fixes)
- `/qa-design-review` — Visual design audit
- `/setup-browser-cookies` — Import browser cookies for auth
- `/retro` — Weekly engineering retrospective
- `/document-release` — Post-ship documentation update

If gstack skills aren't working, run `cd .claude/skills/gstack && ./setup` to build the binary and register skills.

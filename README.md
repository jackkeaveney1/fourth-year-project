# Agentic Cyber Range

A cyber range where an autonomous LLM agent attacks an isolated, disposable
target network — reasoning through recon, exploitation, and exfiltration
step by step rather than replaying a fixed script — while a student
defends and hardens the system in response.

Full concept and design rationale: [`docs/project-concept.md`](docs/project-concept.md).

## What's implemented so far

This is a working scaffold, not the finished platform — treat it as the
foundation to build the year's project on top of, not the deliverable
itself.

| Piece | Status |
|---|---|
| Data contracts (`Scenario`, `TrajectoryStep`, `RunReport`, `ScoreCard`, …) | Done |
| Guardrails (step/cost budget, tool allowlist, network confinement, kill switch) | Done, unit tested |
| Agent tools (recon, HTTP, sandboxed shell, credential stuffing, exfil parsing, defender inspection) | Done |
| ReAct agent loop (reason → act → observe, guardrail-checked) | Done, unit tested |
| Red-team / blue-team agent roles | Done |
| Scenario-generator agent (catalog-driven, deterministic, 4 difficulty tiers) | Done, unit tested |
| Deterministic scenario engine (renders + provisions/tears down docker-compose per run) | Done — compose rendering unit tested; **live `docker compose up` not exercised in this environment** (no Docker socket access here — see Verification below) |
| Deterministic post-hardening scorer | Done, unit tested |
| FastAPI backend (scenario generation, run launch, live WebSocket trajectory feed) | Done, boot-tested |
| Vulnerable target app (real SQLi, weak creds, seeded canary record) | Written, **not build-tested in this environment** |
| React + TypeScript frontend (scenario picker, live attack timeline, report) | Done, typechecks and builds cleanly |
| Monitoring (Prometheus/Grafana), Redis-backed run store, Kubernetes | **Not built** — noted in the design doc as stretch/infra scaling, deliberately left out of the scaffold |

## Architecture

```
React frontend  ──HTTP/WebSocket──>  FastAPI backend
                                          │
                        ┌─────────────────┴─────────────────┐
                        │                                   │
                 Scenario Engine                    Agent Orchestrator
                 (deterministic)                     (LLM agents)
                        │                                   │
                  docker compose                  Red / Blue agents
                        │                          (ReAct loop, guardrailed)
             ┌──────────┴──────────┐
          attacker   web · db · …
       (isolated, no-egress network per run)
```

- **Deterministic**: scenario generation topology, docker-compose rendering,
  provisioning/teardown, goal-achievement checking (string match on a
  per-run canary marker, not an LLM self-report), and scoring.
- **Agentic**: the red-team and blue-team reasoning loops. Same code path,
  different topology in → different attack path out, with no new code
  written per scenario.

See `backend/app/guardrails/policy.py` for the safety design: every tool
call an agent makes passes through a step budget, a tool allowlist, and a
network allowlist that confines it to the run's own `/24` subnet before
anything executes.

## Repo layout

```
backend/
  app/
    agents/            # ReAct loop, red/blue/generator agents, LLM client abstraction
    tools/              # recon, http, shell, bruteforce, exfil, defender inspection
    guardrails/         # step/cost budgets, allowlists, kill switch
    scenario_engine/     # docker-compose templating + provisioning
    scoring/            # deterministic post-hardening scorer
    models/             # pydantic schemas shared across the app
    api/                # FastAPI routes
  tests/                # pytest — guardrails, scoring, goal-check, scenario generator, agent loop
  docker/agent-runtime/  # image the agents' run_shell tool execs into
targets/
  web-vuln/             # the actual vulnerable Flask+Postgres target app
  generated/             # per-run rendered docker-compose files (gitignored)
frontend/
  src/                  # scenario picker, live attack timeline, report view
docs/
  project-concept.md    # original design doc this scaffold was built from
```

## Running it

### Backend

```bash
cd backend
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
cp .env.example .env   # add ANTHROPIC_API_KEY, or leave USE_SCRIPTED_LLM=1 for a stubbed demo run
.venv/bin/uvicorn app.main:app --reload
```

Runs on `http://localhost:8000`; interactive API docs at `/docs`.

Without `ANTHROPIC_API_KEY` set, the backend automatically falls back to a
deterministic `ScriptedLLMClient` stub so you can exercise the API and
frontend without an API key or Docker running — see `app/config.py`.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Runs on `http://localhost:5173`, talks to the backend at
`VITE_API_URL` (defaults to `http://localhost:8000`).

### Building the target images (needed for a real, non-stubbed run)

```bash
docker build -t cyber-range/web-vuln:latest targets/web-vuln
docker build -t cyber-range/agent-runtime:latest backend/docker/agent-runtime
```

### Tests

```bash
cd backend
.venv/bin/pytest -q
```

## Verification performed while building this scaffold

- `pytest`: 22/22 passing (guardrails, scoring against the doc's worked
  example, goal-check marker matching, scenario generator topology per
  difficulty, and the ReAct loop including a step-budget-exhaustion case).
- Backend boots with `uvicorn` and correctly serves `/health` and
  `/scenarios/generate` end to end.
- The Jinja2 docker-compose template was rendered for all four difficulty
  tiers and validated as parseable YAML with `internal: true` set on the
  range network.
- Frontend: `tsc -b && vite build` completes with zero type errors.
- **Not verified here**: an actual `docker compose up` of a rendered range,
  or a build of the `web-vuln`/`agent-runtime` images — this sandbox's
  Docker socket isn't accessible to the current user. Run the two `docker
  build` commands above and `.venv/bin/pytest` locally, then do a full
  `POST /scenarios/generate` → `POST /runs` round trip against a real
  Anthropic API key, before relying on the live-attack path for a demo.

## Immediate next steps

1. Build the two Docker images locally and do one real end-to-end run
   against the `easy` scenario with a real API key, to validate the
   provisioning → attack → teardown path outside this sandbox.
2. Wire `run_blue_team` and the scorer into the API (currently only the
   red-team run is exposed over HTTP — the blue-team advisor and
   `compute_scorecard` exist and are tested, but need `/runs/{id}/harden`
   and `/runs/{id}/score` endpoints).
3. Flesh out the frontend's network graph visualisation (currently a flat
   topology list) and wire the blue-team/report views once those
   endpoints exist.
4. Build the `hard`/`expert` tier's `fileserver`/`employee_pc` images for
   real rather than reusing the `web-vuln` image as a placeholder.
5. Start the reproducibility research track: N-trial runs per difficulty,
   scripted-baseline-vs-agentic comparison (see the design doc's Research
   Angle section).

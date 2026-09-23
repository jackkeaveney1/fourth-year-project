# Project Concept

An automated **cyber range** platform. A lecturer, student, or security enthusiast spins up a virtual company network with one click — then an **autonomous AI attacker agent** tries to break into it while the learner defends.

The key shift from a typical student project: the attacks aren't hardcoded scripts that replay the same steps every time. An LLM-driven agent is dropped into the network with a goal and a set of tools, and it *decides* how to attack — recon, reason, exploit, adapt.

Example network:

```text
Internet
     |
 Firewall
     |
 -------------------------
 |           |           |
Web Server  Database   Employee PC
                 |
           Internal File Server
```

The user picks a scenario (or lets the platform generate one), presses **Launch**, and the agent goes to work. Afterward the system produces a report:

```text
Attack: SQL Injection (agent-discovered)

Goal given to agent:
"Exfiltrate the customer database"

Path the agent took:
Recon → found login form → tested for SQLi → bypassed auth → dumped users

Vulnerability:
Unsanitized SQL query on /login

Compromised:
✓ User database

Privilege Escalation:
No

Detected:
No

Time to compromise:
41 seconds (12 agent steps)

Recommended Fixes:
✓ Parameterized queries
✓ Prepared statements
✓ WAF
```

---

# Why it's Interesting

Instead of building:

> "Here's a vulnerable website."

or even:

> "Here's an automated training environment that replays attacks."

you're building:

> "Here's a cyber range that an autonomous AI agent attacks and reasons about on its own — and that a student defends against in real time."

The **agentic layer** is what makes this a genuine software-engineering + AI project rather than a scripted lab. The attacker isn't a recording; it's a decision-maker operating in a live environment.

---

# The Agentic Core

This is the heart of the project. Three agents, each doing real reason–act–observe work, not canned responses.

## 1. Red-Team Agent (autonomous attacker)

The scenario engine builds the network; the **agent** does the attacking.

```text
        ┌─────────────────────────────┐
        │      Red-Team Agent (LLM)   │
        │  goal: "compromise the DB"  │
        └──────────────┬──────────────┘
                       │  reason → act → observe (loop)
        ┌──────────────▼──────────────┐
        │       Tool Interface        │
        │  run_shell()  http_request()│
        │  scan_ports() read_page()   │
        └──────────────┬──────────────┘
                       │  (locked to target subnet only)
        ┌──────────────▼──────────────┐
        │   Sandboxed Target Network  │
        │   Web · DB · Victim · FW    │
        └─────────────────────────────┘
```

The loop:

```text
Thought:  "I see a login form. Let me test for SQL injection."
Action:   http_request(POST /login, payload="' OR '1'='1")
Observation: "Logged in as admin. No input validation."
Thought:  "Auth bypassed. Now dump the users table."
Action:   http_request(GET /admin/users)
Observation: "Returned 4,000 user records."
Thought:  "Goal achieved. Database exfiltrated."
```

Because the agent *reasons* rather than replays, a different network topology produces a different attack path — **with no new code written**. That's the payoff.

## 2. Blue-Team Agent (defender advisor)

After the attack, the learner tries to secure the system. Instead of static hints, an agent **inspects the live system state** — reads configs, checks running services, diffs against a hardened baseline — and reasons about the real gaps.

Example output:

> You've patched the SQL injection on `/login`, but the same endpoint is still open to credential stuffing — there's no rate limiting and no account lockout.

It can either advise the student or, in auto mode, propose and apply the hardening itself.

## 3. Scenario-Generator Agent (procedural ranges)

Given a difficulty target and a learning objective, this agent **designs a new range**: picks a topology, chooses which services to deploy, and injects a *coherent chain* of vulnerabilities — then emits the `docker-compose` + configs.

This turns "difficulty levels" from hand-authored fixtures into genuinely generated content.

---

# What Stays Deterministic (on purpose)

Not everything should be an agent. The infrastructure layer must be **reliable and reproducible**, so it stays scripted:

```text
                React Frontend
                      |
                REST / WebSocket API
                      |
        ┌─────────────┴─────────────┐
        │                           │
  Scenario Engine            Agent Orchestrator
  (deterministic)            (LLM agents)
        │                           │
   Docker API              Red / Blue / Generator
        │
  ┌─────┴─────┬──────┬─────────┐
 Web         DB    Victim   Firewall
```

- **Scenario Engine** — starts containers, creates the network, populates databases, configures the firewall, deploys the vulnerable app. Boring, deterministic, dependable.
- **Agent Orchestrator** — runs the LLM agents, manages their tool calls, enforces guardrails, logs trajectories.

Rule of thumb: **agents go where there's genuine decision-making under uncertainty** (attack path, remediation reasoning, scenario design). Everything mechanical stays scripted.

---

# Attack Modules → Agent Tools

The old "each attack is a plugin" idea evolves. Attacks are no longer fixed scripts — they're **capabilities the agent can choose to use**, exposed as tools:

```text
tools/
├── recon/          (nmap, service detection)
├── web/            (http_request, headless browser)
├── shell/          (run_command in attacker container)
├── bruteforce/     (credential attacks)
└── exfil/          (data extraction helpers)
```

You can still ship curated scenarios ("today's target is vulnerable to XSS") by constraining the toolset and the goal, but the agent picks *how* to use them.

---

# Guardrails (this is a safety-critical design)

An autonomous agent with shell access + exploit tools is genuinely more dangerous than a static vulnerable app. The sandbox is now the **central safety argument**, not a footnote.

- **Network egress locked** — the agent's container can only reach the target subnet; **no path to the external internet**.
- **Tool allowlist** — the agent can only call the defined tools, not arbitrary binaries.
- **Step + cost budget** — hard cap on loop iterations and token/API spend per run.
- **Kill switch** — orchestrator can terminate any run instantly.
- **Disposable environments** — every range is torn down and rebuilt clean.

---

# Defender Mode

After the attack, students harden the system.

### Before

```text
Password
admin / 123456
```

### After

- Strong password hashing
- Rate limiting + account lockout
- Two-factor authentication (2FA)
- Parameterized queries

The **red-team agent reruns the attack** against the hardened system. If it can no longer reach its goal within its step budget:

> Student wins.

Because the attacker is adaptive, the student can't just patch the one exact step from last time — the agent may find another path. That's the point.

---

# Automatic Scoring

Deterministic scoring for reproducibility (important for the research eval), with the blue-team agent adding qualitative feedback on top.

| Task | Score |
|------|------:|
| Agent still compromised DB | -20 |
| Database encrypted at rest | +20 |
| Firewall correctly configured | +10 |
| Password policy enforced | +10 |
| HTTPS enabled | +10 |
| Unused ports closed | +5 |

**Total:** **85%**

---

# Live Visualisation (comes for free)

The agent logs every `thought → action → observation`. That trajectory *is* your visualisation — no faked demo data.

**Network graph** with live red arrows as the agent moves:

```text
Attacker Agent
      |
      V
 Web Server
      |
      V
  Database
```

**Attack timeline** = the agent's real trace:

```text
12:01  Recon (nmap scan)
        ↓
12:03  Found login form
        ↓
12:05  Tested SQLi payload
        ↓
12:06  Auth bypassed
        ↓
12:07  Dumped users table
        ↓
12:08  Goal achieved
```

---

# Live Monitoring Dashboard

Real-time metrics from the range and the agent:

- CPU / Memory / Bandwidth
- Requests / blocked traffic
- Agent step count + current reasoning
- Successful vs failed attacks
- Container health

---

# Difficulty Levels

Now driven by the scenario-generator agent:

- **Easy** — one vulnerability, single service
- **Medium** — multiple services, one clear path
- **Hard** — chained exploits required
- **Expert** — enterprise network, agent must pivot across hosts

---

# Research Angle

The agentic layer sharpens the academic contribution:

- Can an **autonomous, adaptive AI attacker** teach defensive skills better than static, scripted lab exercises?
- How reliably can an LLM agent exploit a cyber range, and what are its failure modes?
- Can automated assessment fairly grade defensive security skills?

Evaluate with classmates by measuring:

- Completion times
- Learning outcomes (defended vs. compromised)
- Usability + student satisfaction
- Agent success rate across difficulty levels

**Reproducibility note:** a nondeterministic agent means "time to compromise" varies run to run. Handle it by running N trials and reporting distributions, and/or keeping a scripted-baseline mode to compare against the agentic mode — that comparison is itself a research result.

---

# Technologies

## Backend
- Go **or** Python (FastAPI) — orchestrates agents + scenario engine

## Agents
- LLM API (tool-calling / function-calling)
- ReAct-style agent loop
- Structured tool interface + trajectory logging

## Frontend
- React + TypeScript

## Infrastructure
- Docker + Docker Compose
- Virtual networking (isolated subnets, no external egress)

## Database
- PostgreSQL

## Monitoring
- Prometheus + Grafana

## Messaging
- Redis (agent job queue, live event stream)

## Optional
- Kubernetes (to scale infrastructure complexity)

---

# Stretch Goals

- Red-team agent **vs** blue-team agent (fully autonomous match)
- Multiplayer "Red Team vs Blue Team" (student blue vs agent red)
- Agent trajectory replay with step-by-step playback
- Procedurally generated networks (generator agent)
- Importing existing deliberately-vulnerable apps as targets
- Leaderboards + achievement badges
- Exportable reports for lecturers

---

# Why this Stands Out

Most student cybersecurity projects stop at a vulnerable web app or a single scripted exploit. This project builds a platform that:

- Automatically generates isolated cyber range environments
- Runs an **autonomous AI agent** that reasons its way through attacks
- Lets a defender agent inspect and harden live systems
- Monitors and visualises the attack in real time from the agent's own trace
- Automatically grades defensive measures

Demonstrated skills:

- Agentic AI / LLM tool-use systems
- Distributed systems + container orchestration
- Networking + cybersecurity
- Software architecture
- Full-stack development
- UX

...while solving a real problem in cybersecurity education.

The critical constraint: **all attack simulations are confined to isolated, disposable environments with no path to external networks.** With a capable autonomous agent in the loop, that isolation isn't just good practice — it's the core of the responsible-design story. Ambitious, practical, and defensible.

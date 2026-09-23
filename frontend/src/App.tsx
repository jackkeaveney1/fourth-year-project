import { useCallback, useEffect, useRef, useState } from "react";
import "./App.css";
import { generateScenario, getRun, launchRun, subscribeToRun } from "./api";
import type {
  AttackAttempt,
  Difficulty,
  RunPhase,
  RunStatus,
  RunStatusResponse,
  Scenario,
  TrajectoryStep,
} from "./types";

const DIFFICULTIES: Difficulty[] = ["easy", "medium", "hard", "expert"];
const RED_MAX_STEPS = 15;

const PHASE_LABEL: Record<RunPhase, string> = {
  pending: "Queued",
  provisioning: "Provisioning range (starting containers)",
  running: "Red team attacking",
  assessing: "Blue team assessing damage",
  done: "Finished",
};

function collectErrors(steps: TrajectoryStep[]): string[] {
  const out: string[] = [];
  for (const s of steps) {
    if (s.thought?.startsWith("LLM call failed:")) {
      out.push(`[${s.role}-team] ${s.thought}`);
    } else if (s.observation?.startsWith("ERROR:") || s.observation?.startsWith("BLOCKED:")) {
      out.push(`[${s.role}-team] ${s.tool_call?.name ?? "tool"} — ${s.observation}`);
    }
  }
  return out;
}

function Timeline({ steps }: { steps: TrajectoryStep[] }) {
  return (
    <ol className="timeline">
      {steps.map((step) => (
        <li key={`${step.role}-${step.step}`} className={`role-${step.role}`}>
          <div className="step-head">
            <span className="step-number">Step {step.step}</span>
            <span className="step-time">{new Date(step.timestamp).toLocaleTimeString()}</span>
          </div>
          <div className="thought">{step.thought}</div>
          {step.tool_call && (
            <div className="tool-call">
              <code>
                {step.tool_call.name}({JSON.stringify(step.tool_call.arguments)})
              </code>
            </div>
          )}
          {step.observation && <div className="observation">{step.observation}</div>}
        </li>
      ))}
    </ol>
  );
}

function oneLineStep(step: TrajectoryStep): string {
  const toolPart = step.tool_call ? `${step.tool_call.name}(${JSON.stringify(step.tool_call.arguments)})` : null;
  const obsPart = step.observation ? step.observation.split("\n")[0].slice(0, 90) : null;
  return [toolPart, obsPart].filter(Boolean).join(" → ") || step.thought.slice(0, 100) || "(thinking...)";
}

/** While a run is live, show only the latest action as a single rolling line
 * instead of the full accumulating step list — the full trace is still kept
 * and shown, collapsed, in the report once the run finishes. */
function LiveActivity({ label, steps }: { label: string; steps: TrajectoryStep[] }) {
  const latest = steps[steps.length - 1];
  return (
    <div className="live-activity">
      <span className="live-activity-label">{label}</span>
      <span className="live-activity-line">{latest ? oneLineStep(latest) : "Starting…"}</span>
    </div>
  );
}

function TimelineDetails({
  summary,
  steps,
}: {
  summary: string;
  steps: TrajectoryStep[];
}) {
  return (
    <details className="timeline-details">
      <summary>{summary}</summary>
      <Timeline steps={steps} />
    </details>
  );
}

function AttemptGroup({ title, attempts }: { title: string; attempts: AttackAttempt[] }) {
  if (attempts.length === 0) return null;
  return (
    <>
      <h3>
        {title} <span className="attempt-count">({attempts.length})</span>
      </h3>
      <ul className="attempt-list">
        {attempts.map((a) => (
          <li key={a.step} className={`attempt-${a.outcome}`}>
            <div className="attempt-action">
              <span className="attempt-step">#{a.step}</span> {a.action}
            </div>
            <div className="attempt-detail">{a.detail}</div>
          </li>
        ))}
      </ul>
    </>
  );
}

function App() {
  const [difficulty, setDifficulty] = useState<Difficulty>("easy");
  const [scenario, setScenario] = useState<Scenario | null>(null);
  const [runId, setRunId] = useState<string | null>(null);
  const [steps, setSteps] = useState<TrajectoryStep[]>([]);
  const [phase, setPhase] = useState<RunPhase>("pending");
  const [maxSteps, setMaxSteps] = useState(RED_MAX_STEPS);
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const [runStatus, setRunStatus] = useState<RunStatusResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const unsubscribeRef = useRef<(() => void) | null>(null);
  const startTimeRef = useRef<number | null>(null);

  useEffect(() => () => unsubscribeRef.current?.(), []);

  useEffect(() => {
    if (phase === "done" || phase === "pending") return;
    const interval = setInterval(() => {
      if (startTimeRef.current !== null) {
        setElapsedSeconds(Math.floor((Date.now() - startTimeRef.current) / 1000));
      }
    }, 1000);
    return () => clearInterval(interval);
  }, [phase]);

  const handleGenerate = useCallback(async () => {
    setError(null);
    setBusy(true);
    try {
      const generated = await generateScenario(difficulty);
      setScenario(generated);
      setRunId(null);
      setSteps([]);
      setRunStatus(null);
      setPhase("pending");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }, [difficulty]);

  const handleLaunch = useCallback(async () => {
    if (!scenario) return;
    setError(null);
    setBusy(true);
    setSteps([]);
    setRunStatus(null);
    setPhase("pending");
    setMaxSteps(RED_MAX_STEPS);
    setElapsedSeconds(0);
    startTimeRef.current = Date.now();
    try {
      const { run_id } = await launchRun(scenario.id, RED_MAX_STEPS);
      setRunId(run_id);
      setPhase("provisioning");

      unsubscribeRef.current?.();
      unsubscribeRef.current = subscribeToRun(run_id, {
        onStep: (step) => setSteps((prev) => [...prev, step]),
        onPhase: (nextPhase, phaseMaxSteps) => {
          setPhase(nextPhase);
          if (phaseMaxSteps) setMaxSteps(phaseMaxSteps);
        },
        onComplete: async (_status: RunStatus) => {
          setPhase("done");
          const status = await getRun(run_id);
          setRunStatus(status);
        },
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }, [scenario]);

  const redStepsLive = steps.filter((s) => s.role === "red");
  const blueStepsLive = steps.filter((s) => s.role === "blue");
  // Once the run is complete, prefer the report's own trajectories — they're
  // the source of truth and survive a page refresh, unlike the live buffer.
  const redSteps = runStatus?.report ? runStatus.report.trajectory : redStepsLive;
  const blueSteps = runStatus?.report ? runStatus.report.blue_team_trajectory : blueStepsLive;

  const exploitedVulns = scenario
    ? scenario.services
        .flatMap((s) => s.vulnerabilities)
        .filter((v) => runStatus?.report?.vulnerabilities_exploited.includes(v.id))
    : [];
  const errorNotes = runStatus?.report ? collectErrors([...redSteps, ...blueSteps]) : [];

  const currentPhaseStepCount = phase === "assessing" ? blueStepsLive.length : redSteps.length;
  const progressPercent = Math.min(100, Math.round((currentPhaseStepCount / maxSteps) * 100));
  const isLive = runId !== null && phase !== "done";

  return (
    <div className="range-app">
      <header>
        <h1>Agentic Cyber Range</h1>
        <p className="subtitle">
          An autonomous red-team agent reasons its way through an isolated target network, then a
          blue-team agent assesses the damage. No scripted replay &mdash; every run can take a
          different path.
        </p>
      </header>

      <section className="panel controls">
        <label htmlFor="difficulty">Difficulty</label>
        <select
          id="difficulty"
          value={difficulty}
          onChange={(e) => setDifficulty(e.target.value as Difficulty)}
          disabled={busy}
        >
          {DIFFICULTIES.map((d) => (
            <option key={d} value={d}>
              {d}
            </option>
          ))}
        </select>
        <button onClick={handleGenerate} disabled={busy}>
          Generate Scenario
        </button>
        <button onClick={handleLaunch} disabled={busy || !scenario || isLive}>
          Launch Attack
        </button>
      </section>

      {error && <div className="panel error">{error}</div>}

      {scenario && (
        <section className="panel">
          <h2>{scenario.title}</h2>
          <p>
            <strong>Objective:</strong> {scenario.objective}
          </p>
          <div className="topology">
            {scenario.services.map((service) => (
              <div key={service.name} className="node">
                <div className="node-name">{service.name}</div>
                <div className="node-image">{service.image}</div>
                {service.vulnerabilities.map((v) => (
                  <div key={v.id} className="vuln-tag">
                    {v.name}
                  </div>
                ))}
              </div>
            ))}
          </div>
        </section>
      )}

      {runId && (
        <section className="panel">
          <div className="progress-head">
            <span className={`phase-badge phase-${phase}`}>
              {isLive && <span className="spinner" aria-hidden="true" />}
              {PHASE_LABEL[phase]}
            </span>
            <span className="progress-meta">
              {phase === "running" && `Step ${redSteps.length} / ${maxSteps}`}
              {phase === "assessing" && `Step ${blueStepsLive.length} / ${maxSteps}`}
              {"  ·  "}
              {elapsedSeconds}s elapsed
            </span>
          </div>
          <div className="progress-track">
            <div
              className={`progress-fill ${phase === "provisioning" ? "indeterminate" : ""}`}
              style={phase === "provisioning" ? undefined : { width: `${progressPercent}%` }}
            />
          </div>
        </section>
      )}

      {runId && phase !== "done" && (
        <section className="panel">
          <h2>Attack Timeline</h2>
          {phase === "provisioning" && <p>Spinning up the isolated range (containers, network)&hellip;</p>}
          {(phase === "running" || phase === "assessing") && (
            <LiveActivity label="Red team" steps={redSteps} />
          )}
          {phase === "assessing" && <LiveActivity label="Blue team" steps={blueSteps} />}
        </section>
      )}

      {runId && phase === "done" && (
        <section className="panel">
          <h2>Run Log</h2>
          <p className="section-note">
            Full step-by-step reasoning for both agents, collapsed by default &mdash; the clean
            summary is in the Report and Findings sections below.
          </p>
          {runStatus?.report?.blue_team_error && (
            <p className="section-note error-note">
              Blue-team assessment cut short: {runStatus.report.blue_team_error}
            </p>
          )}
          <TimelineDetails summary={`Red team — ${redSteps.length} steps`} steps={redSteps} />
          <TimelineDetails summary={`Blue team — ${blueSteps.length} steps`} steps={blueSteps} />
        </section>
      )}

      {runStatus?.report && (
        <section className="panel report">
          <h2>Report</h2>
          <p>
            <strong>Status:</strong> {runStatus.report.status}
          </p>
          <p>
            <strong>Goal achieved:</strong> {runStatus.report.goal_achieved ? "Yes" : "No"}
          </p>
          <p>
            <strong>Privilege escalation:</strong> {runStatus.report.privilege_escalation ? "Yes" : "No"}
          </p>
          <p>
            <strong>Agent steps:</strong> {runStatus.report.agent_step_count}
          </p>
          {runStatus.report.time_to_compromise_seconds !== null && (
            <p>
              <strong>Time to compromise:</strong>{" "}
              {runStatus.report.time_to_compromise_seconds.toFixed(1)}s
            </p>
          )}
        </section>
      )}

      {runStatus?.report?.attack_report && (
        <section className="panel attack-report">
          <h2>
            Attack Report —{" "}
            <span className={runStatus.report.attack_report.breached ? "breach-yes" : "breach-no"}>
              {runStatus.report.attack_report.breached ? "Breached" : "Not breached"}
            </span>
          </h2>
          <p className="section-note">{runStatus.report.attack_report.summary}</p>

          <AttemptGroup
            title="Succeeded"
            attempts={runStatus.report.attack_report.successful_attempts}
          />
          <AttemptGroup title="Failed" attempts={runStatus.report.attack_report.failed_attempts} />
          <AttemptGroup
            title="Blocked by guardrails"
            attempts={runStatus.report.attack_report.blocked_attempts}
          />

          {runStatus.report.attack_report.recommendations.length > 0 && (
            <>
              <h3>How to improve</h3>
              <ul className="finding-fix-list">
                {runStatus.report.attack_report.recommendations.map((rec) => (
                  <li key={rec}>{rec}</li>
                ))}
              </ul>
            </>
          )}
        </section>
      )}

      {runStatus?.report?.scorecard && (
        <section className="panel scorecard">
          <h2>
            Grade: {runStatus.report.scorecard.total_points} / {runStatus.report.scorecard.max_points}
            <span className="scorecard-pct">
              {" "}
              ({Math.round((runStatus.report.scorecard.total_points / Math.max(1, runStatus.report.scorecard.max_points)) * 100)}%)
            </span>
          </h2>
          <ul className="scorecard-list">
            {runStatus.report.scorecard.entries.map((entry) => {
              // For a penalty entry (negative points), "achieved" means the
              // penalty was triggered — that's the BAD outcome, so the good/bad
              // sense is inverted relative to a normal positive-points entry.
              const isGood = entry.points < 0 ? !entry.achieved : entry.achieved;
              return (
                <li key={entry.label} className={isGood ? "achieved" : "missed"}>
                  <span className="score-icon" aria-hidden="true">
                    {isGood ? "✔" : "✖"}
                  </span>
                  <span className="score-label">{entry.label}</span>
                  <span className="score-points">
                    {entry.points > 0 ? "+" : ""}
                    {entry.points}
                  </span>
                </li>
              );
            })}
          </ul>
        </section>
      )}

      {runStatus?.report && (
        <section className="panel findings">
          <h2>Findings &amp; Recommendations</h2>

          <h3>Red team — vulnerabilities exploited</h3>
          {exploitedVulns.length === 0 ? (
            <p className="section-note">No vulnerabilities were confirmed exploited this run.</p>
          ) : (
            <ul className="findings-list">
              {exploitedVulns.map((v) => (
                <li key={v.id}>
                  <div className="finding-title">
                    {v.name} {v.cwe && <span className="cwe-tag">{v.cwe}</span>}
                  </div>
                  <div className="finding-desc">{v.description}</div>
                  {v.remediation.length > 0 && (
                    <div className="finding-fix">
                      <strong>Potential fix:</strong>
                      <ul>
                        {v.remediation.map((step) => (
                          <li key={step}>{step}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </li>
              ))}
            </ul>
          )}

          <h3>Blue team — assessment</h3>
          <p className="section-note">
            {runStatus.report.blue_team_summary ??
              (runStatus.report.blue_team_error
                ? `Assessment did not complete: ${runStatus.report.blue_team_error}`
                : "No blue-team summary available.")}
          </p>

          {errorNotes.length > 0 && (
            <>
              <h3>Errors encountered during the run</h3>
              <ul className="error-list">
                {errorNotes.map((note, i) => (
                  <li key={i}>{note}</li>
                ))}
              </ul>
            </>
          )}
        </section>
      )}
    </div>
  );
}

export default App;

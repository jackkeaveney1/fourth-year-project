import { useCallback, useEffect, useRef, useState } from "react";
import "./App.css";
import { generateScenario, getRun, launchRun, subscribeToRun } from "./api";
import type { Difficulty, RunStatusResponse, Scenario, TrajectoryStep } from "./types";

const DIFFICULTIES: Difficulty[] = ["easy", "medium", "hard", "expert"];

function App() {
  const [difficulty, setDifficulty] = useState<Difficulty>("easy");
  const [scenario, setScenario] = useState<Scenario | null>(null);
  const [runId, setRunId] = useState<string | null>(null);
  const [steps, setSteps] = useState<TrajectoryStep[]>([]);
  const [runStatus, setRunStatus] = useState<RunStatusResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const unsubscribeRef = useRef<(() => void) | null>(null);

  useEffect(() => () => unsubscribeRef.current?.(), []);

  const handleGenerate = useCallback(async () => {
    setError(null);
    setBusy(true);
    try {
      const generated = await generateScenario(difficulty);
      setScenario(generated);
      setRunId(null);
      setSteps([]);
      setRunStatus(null);
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
    try {
      const { run_id } = await launchRun(scenario.id, 40);
      setRunId(run_id);

      unsubscribeRef.current?.();
      unsubscribeRef.current = subscribeToRun(
        run_id,
        (step) => setSteps((prev) => [...prev, step]),
        async () => {
          const status = await getRun(run_id);
          setRunStatus(status);
        },
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }, [scenario]);

  return (
    <div className="range-app">
      <header>
        <h1>Agentic Cyber Range</h1>
        <p className="subtitle">
          An autonomous red-team agent reasons its way through an isolated target network. No
          scripted replay &mdash; every run can take a different path.
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
        <button onClick={handleLaunch} disabled={busy || !scenario || runId !== null}>
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
          <h2>Attack Timeline</h2>
          <ol className="timeline">
            {steps.map((step) => (
              <li key={step.step} className={`role-${step.role}`}>
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
          {steps.length === 0 && <p>Waiting for the agent's first move&hellip;</p>}
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
    </div>
  );
}

export default App;

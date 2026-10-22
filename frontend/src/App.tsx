import { useCallback, useEffect, useRef, useState } from "react";
import "./App.css";
import {
  createCustomScenario,
  createImportedScenario,
  generateScenario,
  getInfrastructure,
  getRun,
  getVulnerabilityCatalog,
  launchRun,
  subscribeToRun,
} from "./api";
import type {
  AttackAttempt,
  CustomServiceSpec,
  Difficulty,
  InfrastructureResponse,
  LLMProvider,
  LLMSelection,
  RangeContainer,
  RunPhase,
  RunStatus,
  RunStatusResponse,
  Scenario,
  ServiceRole,
  TrajectoryStep,
  Vulnerability,
} from "./types";

const DIFFICULTIES: Difficulty[] = ["easy", "medium", "hard", "expert"];
const RED_MAX_STEPS = 15;
const LLM_PROVIDERS: LLMProvider[] = ["groq", "anthropic", "gemini", "aionlabs"];
const SERVICE_ROLES: ServiceRole[] = ["web", "db", "internal"];

/** A locally-editable service row before it's sent to /scenarios/custom.
 * `name` is only meaningful for role "internal" — "web"/"db" get their name
 * forced server-side (see build_custom_scenario), so we just display that
 * fixed name for those roles instead of taking free text. */
interface EditableService {
  key: string;
  name: string;
  role: ServiceRole;
  vulnerabilityIds: string[];
  exposedTo: string[];
}

function newService(role: ServiceRole = "internal"): EditableService {
  return { key: crypto.randomUUID(), name: "", role, vulnerabilityIds: [], exposedTo: [] };
}

function resolvedName(s: EditableService): string {
  if (s.role === "web") return "web";
  if (s.role === "db") return "db";
  return s.name.trim();
}

/** Remembers one API key per provider in the browser only — never sent
 * anywhere except as part of a launch-run request the user triggers. */
function useStoredApiKey(provider: LLMProvider | ""): [string, (v: string) => void] {
  const storageKey = provider ? `cyber-range:api-key:${provider}` : null;
  const [value, setValue] = useState(() => (storageKey ? localStorage.getItem(storageKey) ?? "" : ""));

  useEffect(() => {
    setValue(storageKey ? localStorage.getItem(storageKey) ?? "" : "");
  }, [storageKey]);

  const update = useCallback(
    (v: string) => {
      setValue(v);
      if (storageKey) {
        if (v) localStorage.setItem(storageKey, v);
        else localStorage.removeItem(storageKey);
      }
    },
    [storageKey]
  );

  return [value, update];
}

function LlmTeamSettings({
  label,
  provider,
  setProvider,
  model,
  setModel,
  apiKey,
  setApiKey,
}: {
  label: string;
  provider: LLMProvider | "";
  setProvider: (p: LLMProvider | "") => void;
  model: string;
  setModel: (m: string) => void;
  apiKey: string;
  setApiKey: (k: string) => void;
}) {
  return (
    <div className="llm-team-settings">
      <h4>{label}</h4>
      <label>
        Provider
        <select value={provider} onChange={(e) => setProvider(e.target.value as LLMProvider | "")}>
          <option value="">Server default</option>
          {LLM_PROVIDERS.map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </select>
      </label>
      {provider && (
        <>
          <label>
            Model
            <input
              type="text"
              value={model}
              onChange={(e) => setModel(e.target.value)}
              placeholder="(provider default)"
            />
          </label>
          <label>
            API key
            <input
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="(use server key if configured)"
              autoComplete="off"
            />
          </label>
          <p className="field-hint">Stored only in this browser; sent with each run you launch.</p>
        </>
      )}
    </div>
  );
}

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

function ServiceEditor({
  service,
  otherNames,
  vulnCatalog,
  onChange,
  onRemove,
  canRemove,
}: {
  service: EditableService;
  otherNames: string[];
  vulnCatalog: Vulnerability[];
  onChange: (next: EditableService) => void;
  onRemove: () => void;
  canRemove: boolean;
}) {
  const edgeOptions = ["internet", ...otherNames];
  return (
    <div className="service-editor">
      <div className="service-editor-row">
        <select
          value={service.role}
          onChange={(e) => onChange({ ...service, role: e.target.value as ServiceRole })}
        >
          {SERVICE_ROLES.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </select>
        {service.role === "internal" ? (
          <input
            type="text"
            value={service.name}
            onChange={(e) => onChange({ ...service, name: e.target.value })}
            placeholder="service name (e.g. fileserver)"
          />
        ) : (
          <span className="service-fixed-name">{service.role} (name is fixed)</span>
        )}
        {canRemove && (
          <button type="button" className="remove-btn" onClick={onRemove}>
            Remove
          </button>
        )}
      </div>
      <div className="service-editor-vulns">
        {vulnCatalog.map((v) => (
          <label key={v.id} className="vuln-checkbox">
            <input
              type="checkbox"
              checked={service.vulnerabilityIds.includes(v.id)}
              onChange={(e) => {
                const ids = e.target.checked
                  ? [...service.vulnerabilityIds, v.id]
                  : service.vulnerabilityIds.filter((id) => id !== v.id);
                onChange({ ...service, vulnerabilityIds: ids });
              }}
            />
            {v.name}
          </label>
        ))}
      </div>
      <div className="service-editor-edges">
        <span className="field-hint">Reachable from:</span>
        {edgeOptions.map((name) => (
          <label key={name} className="vuln-checkbox">
            <input
              type="checkbox"
              checked={service.exposedTo.includes(name)}
              onChange={(e) => {
                const edges = e.target.checked
                  ? [...service.exposedTo, name]
                  : service.exposedTo.filter((n) => n !== name);
                onChange({ ...service, exposedTo: edges });
              }}
            />
            {name}
          </label>
        ))}
      </div>
    </div>
  );
}

/** Collapses a container's Docker status + health into one of a few visual
 * states the panel colours by. Health (when the image defines a healthcheck)
 * wins over the coarse run status. */
function containerState(c: RangeContainer): string {
  if (c.status === "pending") return "pending";
  if (c.health === "healthy") return "healthy";
  if (c.health === "unhealthy") return "unhealthy";
  if (c.status === "exited" || c.status === "dead") return "stopped";
  if (c.status === "running") return c.health === "starting" ? "starting" : "running";
  return "starting";
}

function containerLabel(c: RangeContainer): string {
  if (c.status === "pending") return "pending";
  if (c.health) return c.health;
  return c.status;
}

/** Live picture of the isolated range: one node per container, colour-coded by
 * state, so a user can watch the network actually come up (and confirm it's
 * isolated) rather than staring at a spinner. */
function InfrastructurePanel({ infra }: { infra: InfrastructureResponse | null }) {
  if (!infra || !infra.provisioned) {
    return <p className="section-note">Waiting for the range to start&hellip;</p>;
  }
  return (
    <div className="infra-panel">
      {infra.network && (
        <div className="infra-network">
          <span className="infra-network-name">
            network <code>{infra.network.name ?? "range"}</code>
            {infra.network.subnet && (
              <>
                {" "}
                <code>{infra.network.subnet}</code>
              </>
            )}
          </span>
          {infra.network.internal && <span className="infra-badge">isolated &middot; no internet</span>}
        </div>
      )}
      <div className="infra-grid">
        {infra.containers.map((c) => (
          <div key={c.container_name} className={`infra-node infra-${containerState(c)}`}>
            <div className="infra-node-head">
              <span className="infra-dot" aria-hidden="true" />
              <span className="infra-node-name">{c.service}</span>
            </div>
            <div className="infra-node-status">{containerLabel(c)}</div>
            {c.ip && <div className="infra-node-meta">{c.ip}</div>}
            {c.image && <div className="infra-node-meta infra-node-image">{c.image}</div>}
          </div>
        ))}
      </div>
    </div>
  );
}

function App() {
  const [difficulty, setDifficulty] = useState<Difficulty>("easy");
  const [scenario, setScenario] = useState<Scenario | null>(null);
  const [runId, setRunId] = useState<string | null>(null);

  const [scenarioSource, setScenarioSource] = useState<"generated" | "custom" | "imported">("generated");
  const [vulnCatalog, setVulnCatalog] = useState<Vulnerability[]>([]);
  const [customTitle, setCustomTitle] = useState("My custom range");
  const [customObjective, setCustomObjective] = useState("Exfiltrate the customer database");
  const [customServices, setCustomServices] = useState<EditableService[]>(() => [
    newService("web"),
    newService("db"),
  ]);

  const [importTitle, setImportTitle] = useState("My imported app");
  const [importObjective, setImportObjective] = useState("Compromise the app and exfiltrate its secret");
  const [importBuildContext, setImportBuildContext] = useState("");
  const [importAppPort, setImportAppPort] = useState(8080);
  const [importIncludeDb, setImportIncludeDb] = useState(false);
  const [importing, setImporting] = useState(false);

  const [showLlmSettings, setShowLlmSettings] = useState(false);
  const [redProvider, setRedProvider] = useState<LLMProvider | "">("");
  const [redModel, setRedModel] = useState("");
  const [redApiKey, setRedApiKey] = useStoredApiKey(redProvider);
  const [blueProvider, setBlueProvider] = useState<LLMProvider | "">("");
  const [blueModel, setBlueModel] = useState("");
  const [blueApiKey, setBlueApiKey] = useStoredApiKey(blueProvider);
  const [steps, setSteps] = useState<TrajectoryStep[]>([]);
  const [phase, setPhase] = useState<RunPhase>("pending");
  const [maxSteps, setMaxSteps] = useState(RED_MAX_STEPS);
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const [runStatus, setRunStatus] = useState<RunStatusResponse | null>(null);
  const [infra, setInfra] = useState<InfrastructureResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const unsubscribeRef = useRef<(() => void) | null>(null);
  const startTimeRef = useRef<number | null>(null);

  useEffect(() => () => unsubscribeRef.current?.(), []);

  useEffect(() => {
    getVulnerabilityCatalog()
      .then(setVulnCatalog)
      .catch((err) => setError(err instanceof Error ? err.message : String(err)));
  }, []);

  useEffect(() => {
    if (phase === "done" || phase === "pending") return;
    const interval = setInterval(() => {
      if (startTimeRef.current !== null) {
        setElapsedSeconds(Math.floor((Date.now() - startTimeRef.current) / 1000));
      }
    }, 1000);
    return () => clearInterval(interval);
  }, [phase]);

  // Poll live container/network state while the range is up. The WebSocket
  // carries agent reasoning; this is the orthogonal "is the infra actually
  // there" signal, so it gets its own lightweight poll rather than riding the
  // step stream.
  useEffect(() => {
    if (!runId || phase === "done" || phase === "pending") return;
    let cancelled = false;
    const tick = async () => {
      try {
        const data = await getInfrastructure(runId);
        if (!cancelled) setInfra(data);
      } catch {
        // transient (e.g. mid-teardown) — keep the last good snapshot
      }
    };
    void tick();
    const interval = setInterval(() => void tick(), 1500);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [runId, phase]);

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

  const handleBuildCustom = useCallback(async () => {
    setError(null);
    setBusy(true);
    try {
      const services: CustomServiceSpec[] = customServices.map((s) => ({
        name: resolvedName(s),
        role: s.role,
        vulnerability_ids: s.vulnerabilityIds,
        exposed_to: s.exposedTo,
      }));
      const built = await createCustomScenario({ title: customTitle, objective: customObjective, services });
      setScenario(built);
      setRunId(null);
      setSteps([]);
      setRunStatus(null);
      setPhase("pending");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }, [customTitle, customObjective, customServices]);

  const handleImport = useCallback(async () => {
    setError(null);
    setImporting(true);
    try {
      const built = await createImportedScenario({
        title: importTitle,
        objective: importObjective,
        build_context: importBuildContext,
        app_port: importAppPort,
        include_db: importIncludeDb,
      });
      setScenario(built);
      setRunId(null);
      setSteps([]);
      setRunStatus(null);
      setPhase("pending");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setImporting(false);
    }
  }, [importTitle, importObjective, importBuildContext, importAppPort, importIncludeDb]);

  const handleLaunch = useCallback(async () => {
    if (!scenario) return;
    setError(null);
    setBusy(true);
    setSteps([]);
    setRunStatus(null);
    setInfra(null);
    setPhase("pending");
    setMaxSteps(RED_MAX_STEPS);
    setElapsedSeconds(0);
    startTimeRef.current = Date.now();
    try {
      const redLlm: LLMSelection | null = redProvider
        ? { provider: redProvider, model: redModel || null, api_key: redApiKey || null }
        : null;
      const blueLlm: LLMSelection | null = blueProvider
        ? { provider: blueProvider, model: blueModel || null, api_key: blueApiKey || null }
        : null;
      const { run_id } = await launchRun(scenario.id, RED_MAX_STEPS, { redLlm, blueLlm });
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
  }, [scenario, redProvider, redModel, redApiKey, blueProvider, blueModel, blueApiKey]);

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
        <div className="source-toggle">
          <label>
            <input
              type="radio"
              name="scenario-source"
              checked={scenarioSource === "generated"}
              onChange={() => setScenarioSource("generated")}
            />
            Generated
          </label>
          <label>
            <input
              type="radio"
              name="scenario-source"
              checked={scenarioSource === "custom"}
              onChange={() => setScenarioSource("custom")}
            />
            Custom scenario
          </label>
          <label>
            <input
              type="radio"
              name="scenario-source"
              checked={scenarioSource === "imported"}
              onChange={() => setScenarioSource("imported")}
            />
            Imported
          </label>
        </div>

        {scenarioSource === "generated" ? (
          <>
            {/* difficulty-driven generated scenario */}
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
          </>
        ) : scenarioSource === "custom" ? (
          <div className="custom-builder">
            <label>
              Title
              <input type="text" value={customTitle} onChange={(e) => setCustomTitle(e.target.value)} />
            </label>
            <label>
              Objective
              <input
                type="text"
                value={customObjective}
                onChange={(e) => setCustomObjective(e.target.value)}
              />
            </label>
            {customServices.map((service) => (
              <ServiceEditor
                key={service.key}
                service={service}
                otherNames={customServices
                  .filter((s) => s.key !== service.key)
                  .map(resolvedName)
                  .filter(Boolean)}
                vulnCatalog={vulnCatalog}
                canRemove={customServices.length > 1}
                onChange={(next) =>
                  setCustomServices((prev) => prev.map((s) => (s.key === next.key ? next : s)))
                }
                onRemove={() => setCustomServices((prev) => prev.filter((s) => s.key !== service.key))}
              />
            ))}
            <div className="custom-builder-actions">
              <button type="button" onClick={() => setCustomServices((prev) => [...prev, newService()])}>
                + Add service
              </button>
              <button onClick={handleBuildCustom} disabled={busy}>
                Build Scenario
              </button>
            </div>
          </div>
        ) : (
          <div className="custom-builder import-builder">
            <p className="import-hint">
              Point this at a local folder containing a <code>Dockerfile</code>. It's built on your
              Docker daemon and run as the target <code>web</code> service on the isolated network.
              To make a win detectable, have your app read the <code>SUCCESS_MARKER</code> env var
              and surface it somewhere only a compromise would reach.
            </p>
            <label>
              Title
              <input type="text" value={importTitle} onChange={(e) => setImportTitle(e.target.value)} />
            </label>
            <label>
              Objective
              <input
                type="text"
                value={importObjective}
                onChange={(e) => setImportObjective(e.target.value)}
              />
            </label>
            <label>
              Build context (folder with Dockerfile)
              <input
                type="text"
                placeholder="/home/you/my-app"
                value={importBuildContext}
                onChange={(e) => setImportBuildContext(e.target.value)}
              />
            </label>
            <label>
              App port
              <input
                type="number"
                min={1}
                max={65535}
                value={importAppPort}
                onChange={(e) => setImportAppPort(Number(e.target.value))}
              />
            </label>
            <label className="checkbox">
              <input
                type="checkbox"
                checked={importIncludeDb}
                onChange={(e) => setImportIncludeDb(e.target.checked)}
              />
              Attach a Postgres <code>db</code> service
            </label>
            <div className="custom-builder-actions">
              <button onClick={handleImport} disabled={importing || !importBuildContext.trim()}>
                {importing ? "Building image…" : "Build & Import"}
              </button>
            </div>
          </div>
        )}

        <button
          type="button"
          className="link-btn"
          onClick={() => setShowLlmSettings((v) => !v)}
        >
          {showLlmSettings ? "Hide" : "Show"} model settings
        </button>
        {showLlmSettings && (
          <div className="llm-settings">
            <LlmTeamSettings
              label="Red team"
              provider={redProvider}
              setProvider={setRedProvider}
              model={redModel}
              setModel={setRedModel}
              apiKey={redApiKey}
              setApiKey={setRedApiKey}
            />
            <LlmTeamSettings
              label="Blue team"
              provider={blueProvider}
              setProvider={setBlueProvider}
              model={blueModel}
              setModel={setBlueModel}
              apiKey={blueApiKey}
              setApiKey={setBlueApiKey}
            />
          </div>
        )}

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
          <h2>Range Infrastructure</h2>
          <p className="section-note">
            Live view of the containers and isolated network for this run &mdash; watch them come up,
            then get attacked.
          </p>
          <InfrastructurePanel infra={infra} />
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

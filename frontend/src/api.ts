import type {
  CustomScenarioRequest,
  Difficulty,
  ImportedScenarioRequest,
  InfrastructureResponse,
  LLMSelection,
  RunPhase,
  RunStatus,
  RunStatusResponse,
  Scenario,
  TrajectoryStep,
  Vulnerability,
} from "./types";

const API_BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8000";
const WS_BASE = API_BASE.replace(/^http/, "ws");

async function readError(res: Response, fallback: string): Promise<never> {
  let detail = fallback;
  try {
    const body = await res.json();
    if (body?.detail) detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
  } catch {
    // response wasn't JSON — stick with fallback
  }
  throw new Error(detail);
}

export async function generateScenario(difficulty: Difficulty): Promise<Scenario> {
  const res = await fetch(`${API_BASE}/scenarios/generate?difficulty=${difficulty}`, {
    method: "POST",
  });
  if (!res.ok) return readError(res, `Failed to generate scenario: ${res.status}`);
  return res.json();
}

export async function getVulnerabilityCatalog(): Promise<Vulnerability[]> {
  const res = await fetch(`${API_BASE}/vulnerabilities`);
  if (!res.ok) return readError(res, `Failed to load vulnerability catalog: ${res.status}`);
  return res.json();
}

export async function createCustomScenario(request: CustomScenarioRequest): Promise<Scenario> {
  const res = await fetch(`${API_BASE}/scenarios/custom`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  });
  if (!res.ok) return readError(res, `Failed to create custom scenario: ${res.status}`);
  return res.json();
}

export async function createImportedScenario(request: ImportedScenarioRequest): Promise<Scenario> {
  const res = await fetch(`${API_BASE}/scenarios/imported`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  });
  if (!res.ok) return readError(res, `Failed to import scenario: ${res.status}`);
  return res.json();
}

export interface LaunchRunOptions {
  redLlm?: LLMSelection | null;
  blueLlm?: LLMSelection | null;
}

export async function launchRun(
  scenarioId: string,
  maxSteps: number,
  options: LaunchRunOptions = {}
): Promise<{ run_id: string }> {
  const res = await fetch(`${API_BASE}/runs`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      scenario_id: scenarioId,
      mode: "agentic",
      max_steps: maxSteps,
      red_llm: options.redLlm ?? null,
      blue_llm: options.blueLlm ?? null,
    }),
  });
  if (!res.ok) return readError(res, `Failed to launch run: ${res.status}`);
  return res.json();
}

export async function getRun(runId: string): Promise<RunStatusResponse> {
  const res = await fetch(`${API_BASE}/runs/${runId}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch run: ${res.status}`);
  }
  return res.json();
}

export async function getInfrastructure(runId: string): Promise<InfrastructureResponse> {
  const res = await fetch(`${API_BASE}/runs/${runId}/infrastructure`);
  if (!res.ok) throw new Error(`Failed to fetch infrastructure: ${res.status}`);
  return res.json();
}

export interface RunSubscriptionHandlers {
  onStep: (step: TrajectoryStep) => void;
  onPhase: (phase: RunPhase, maxSteps?: number) => void;
  onComplete: (status: RunStatus) => void;
}

export function subscribeToRun(runId: string, handlers: RunSubscriptionHandlers): () => void {
  const ws = new WebSocket(`${WS_BASE}/runs/${runId}/live`);

  ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    if (data.event === "run_complete") {
      handlers.onComplete(data.status);
      ws.close();
      return;
    }
    if (data.event === "phase") {
      handlers.onPhase(data.phase, data.max_steps);
      return;
    }
    handlers.onStep(data as TrajectoryStep);
  };

  return () => ws.close();
}

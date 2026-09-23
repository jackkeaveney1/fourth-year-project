import type { Difficulty, RunStatusResponse, Scenario, TrajectoryStep } from "./types";

const API_BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8000";
const WS_BASE = API_BASE.replace(/^http/, "ws");

export async function generateScenario(difficulty: Difficulty): Promise<Scenario> {
  const res = await fetch(`${API_BASE}/scenarios/generate?difficulty=${difficulty}`, {
    method: "POST",
  });
  if (!res.ok) {
    throw new Error(`Failed to generate scenario: ${res.status}`);
  }
  return res.json();
}

export async function launchRun(scenarioId: string, maxSteps: number): Promise<{ run_id: string }> {
  const res = await fetch(`${API_BASE}/runs`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scenario_id: scenarioId, mode: "agentic", max_steps: maxSteps }),
  });
  if (!res.ok) {
    throw new Error(`Failed to launch run: ${res.status}`);
  }
  return res.json();
}

export async function getRun(runId: string): Promise<RunStatusResponse> {
  const res = await fetch(`${API_BASE}/runs/${runId}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch run: ${res.status}`);
  }
  return res.json();
}

export function subscribeToRun(
  runId: string,
  onStep: (step: TrajectoryStep) => void,
  onComplete: (status: string) => void,
): () => void {
  const ws = new WebSocket(`${WS_BASE}/runs/${runId}/live`);

  ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    if (data.event === "run_complete") {
      onComplete(data.status);
      ws.close();
      return;
    }
    onStep(data as TrajectoryStep);
  };

  return () => ws.close();
}

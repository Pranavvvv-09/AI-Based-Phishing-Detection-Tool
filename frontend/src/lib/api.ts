// Typed client for the PhishGuard FastAPI backend (src/phishguard/web.py).
// Every request is same-origin and carries the session cookie; POSTs also carry the
// CSRF token the server hands out in /api/session.

export type ReasonSource = "text" | "header" | "link" | "sender" | "trust" | "system";

export interface Reason {
  source: ReasonSource;
  code: string;
  detail: string;
  weight: number; // signed log-odds: + towards phishing, - towards legitimate
}

export type RowStatus = "held" | "restoring" | "restored";

export interface QuarantineRow {
  incident_id: string;
  quarantined_at: string | null;
  from: string;
  subject: string;
  score: number | null;
  status: RowStatus;
  restored_at: string | null;
  restored_by: string | null;
  kind: "email" | "sms" | "text";
  reasons: Reason[];
}

export interface Kpis {
  scanned: number;
  quarantined: number;
  restored: number;
  held: number;
}

export interface Session {
  user: string;
  csrf: string;
  mode: "monitor" | "quarantine";
  threshold: number;
  poller: {
    state: "ok" | "warn" | "error" | "off";
    text: string;
    mailbox: string;
    last_poll_at: string | null;
    error: string;
  };
}

export interface RestoreResult {
  incident_id: string;
  status: "restored";
  restored_at: string;
  restored_by: string;
  to_folder: string;
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, {
      credentials: "same-origin",
      ...init,
      headers: { Accept: "application/json", ...init.headers },
    });
  } catch {
    throw new ApiError(0, "Cannot reach PhishGuard. Check that the server is running.");
  }
  if (response.status === 401) {
    // Session expired: back to the login page, then return here.
    window.location.assign(`/login?next=${encodeURIComponent(window.location.pathname)}`);
    throw new ApiError(401, "Your session expired. Please log in again.");
  }
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new ApiError(response.status, body.error ?? `Request failed (${response.status}).`);
  }
  return body as T;
}

export const api = {
  session: () => request<Session>("/api/session"),
  quarantine: () => request<{ rows: QuarantineRow[]; kpis: Kpis }>("/api/quarantine"),
  restore: (incidentId: string, csrf: string) =>
    request<RestoreResult>(`/api/restore/${encodeURIComponent(incidentId)}`, {
      method: "POST",
      headers: { "X-CSRF-Token": csrf },
    }),
};

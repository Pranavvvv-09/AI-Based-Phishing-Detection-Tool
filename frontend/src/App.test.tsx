import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import type { QuarantineRow } from "./lib/api";

const ROW: QuarantineRow = {
  incident_id: "20261008T165554Z-66cb4d85",
  quarantined_at: new Date(Date.now() - 5 * 60_000).toISOString(),
  from: "md.office.desk@gmail.com",
  subject: "Quick task - are you at your desk?",
  score: 0.9966,
  status: "held",
  restored_at: null,
  restored_by: null,
  kind: "email",
  reasons: [
    { source: "text", code: "text_model", detail: "Wording resembles phishing (96%)", weight: 3.27 },
    { source: "header", code: "display_name_other_email", detail: "Display name shows another address", weight: 1.2 },
    { source: "header", code: "undisclosed_recipients", detail: "No visible recipients", weight: 0.2 },
    { source: "trust", code: "verified_sender", detail: "Verified sender", weight: -2.0 },
  ],
};

function json(body: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } }));
}

let restoreResponse: () => Promise<Response>;
let serverRow: QuarantineRow; // the backend's view, updated when a restore succeeds
const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
  const url = String(input);
  if (url === "/api/session") {
    return json({ user: "admin", csrf: "csrf-123", mode: "quarantine", threshold: 0.8, poller: { state: "ok", text: "Watching" } });
  }
  if (url === "/api/quarantine") {
    const restored = serverRow.status === "restored" ? 1 : 0;
    return json({ rows: [serverRow], kpis: { scanned: 7, quarantined: 5, restored, held: 5 - restored } });
  }
  if (url.startsWith("/api/restore/") && init?.method === "POST") {
    return restoreResponse().then((response) => {
      if (response.ok) serverRow = { ...serverRow, status: "restored", restored_at: new Date().toISOString() };
      return response;
    });
  }
  return json({ error: "unexpected" }, 500);
});

beforeEach(() => {
  window.history.replaceState(null, "", "/");
  fetchMock.mockClear();
  serverRow = { ...ROW };
  vi.stubGlobal("fetch", fetchMock);
  restoreResponse = () =>
    json({ incident_id: ROW.incident_id, status: "restored", restored_at: new Date().toISOString(), restored_by: "web:admin", to_folder: "INBOX" });
});
afterEach(() => vi.unstubAllGlobals());

async function renderLoaded() {
  render(<App />);
  return screen.findByText("md.office.desk@gmail.com");
}

describe("quarantine table", () => {
  it("shows the required columns and the KPI strip", async () => {
    await renderLoaded();
    for (const name of ["Time", "Type", "Sender", "Score", "Status"]) {
      expect(screen.getByRole("columnheader", { name })).toBeInTheDocument();
    }
    expect(screen.getByText("Email")).toBeInTheDocument();
    expect(screen.getByText("99.7%")).toBeInTheDocument();
    expect(screen.getByText("5 still held")).toBeInTheDocument();
  });

  it("colours explainability chips by direction and strength", async () => {
    await renderLoaded();
    const row = screen.getByText("md.office.desk@gmail.com").closest("tr")!;
    const chip = within(row).getByText("Text model").closest("[data-direction]")!;
    expect(chip).toHaveAttribute("data-direction", "phishing");
    expect(chip).toHaveAttribute("data-strength", "strong");
    await userEvent.click(within(row).getByRole("button", { name: "+1 more" }));
    const safe = screen.getAllByText("Verified sender")[0].closest("[data-direction]")!;
    expect(safe).toHaveAttribute("data-direction", "safe");
  });
});

describe("restore to inbox", () => {
  it("confirms, shows a spinner while restoring, then updates the row", async () => {
    let release!: (value: Response) => void;
    restoreResponse = () => new Promise((resolve) => (release = resolve));
    await renderLoaded();

    await userEvent.click(screen.getByRole("button", { name: /Restore to Inbox: Quick task/ }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText("Restore to Inbox?")).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Restore to Inbox" }));

    const busy = await screen.findByRole("button", { name: /Restoring Quick task/ });
    expect(busy).toBeDisabled();
    expect(busy).toHaveAttribute("aria-busy", "true");
    expect(busy).toHaveTextContent("Restoring…");
    const call = fetchMock.mock.calls.find(([url]) => String(url).startsWith("/api/restore/"))!;
    expect((call[1]?.headers as Record<string, string>)["X-CSRF-Token"]).toBe("csrf-123");

    release(await json({ incident_id: ROW.incident_id, status: "restored", restored_at: new Date().toISOString(), restored_by: "web:admin", to_folder: "INBOX" }));
    await waitFor(() =>
      expect(screen.queryByRole("button", { name: /Restore to Inbox:|Restoring / })).not.toBeInTheDocument(),
    );
    expect(await screen.findByText("Restored to Inbox")).toBeInTheDocument();
  });

  it("cancel sends nothing", async () => {
    await renderLoaded();
    await userEvent.click(screen.getByRole("button", { name: /Restore to Inbox: Quick task/ }));
    await userEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Cancel" }));
    expect(fetchMock.mock.calls.some(([url]) => String(url).startsWith("/api/restore/"))).toBe(false);
  });

  it("shows the server's reason inline when the mail server fails", async () => {
    restoreResponse = () => json({ error: "Mail server: cannot connect to imap.gmail.com:993 (OSError)" }, 502);
    await renderLoaded();
    await userEvent.click(screen.getByRole("button", { name: /Restore to Inbox: Quick task/ }));
    await userEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Restore to Inbox" }));
    const row = screen.getByText("md.office.desk@gmail.com").closest("tr")!;
    expect(await within(row).findByText(/cannot connect to imap.gmail.com/)).toBeInTheDocument();
    expect(within(row).getByRole("button", { name: /Restore to Inbox: Quick task/ })).toBeEnabled();
  });
});

describe("filter", () => {
  it("keeps the chosen status in the URL", async () => {
    await renderLoaded();
    await userEvent.click(screen.getByRole("button", { name: /Restored/ }));
    expect(window.location.search).toBe("?status=restored");
    expect(screen.getByText("No restored messages yet")).toBeInTheDocument();
  });
});

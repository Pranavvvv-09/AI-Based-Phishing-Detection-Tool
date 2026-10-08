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
  if (url.startsWith("/api/overview?days=")) {
    const days = Number(url.split("=")[1]);
    const restored = serverRow.status === "restored" ? 1 : 0;
    const series = Array.from({ length: days }, (_, i) => ({
      date: new Date(Date.UTC(2026, 9, 8 - (days - 1 - i))).toISOString().slice(0, 10),
      scanned: i === days - 1 ? 250 : 0,
      quarantined: i === days - 1 ? 5 : 0,
      restored: i === days - 1 ? restored : 0,
    }));
    return json({
      days,
      series,
      current: { scanned: 250, quarantined: 5, restored, released: restored, mean_score: 0.991 },
      previous: { scanned: 200, quarantined: 4, restored: 0, released: 0, mean_score: 0.98 },
      held: 5 - restored,
      signals: [
        { code: "text_model", count: 5 },
        { code: "dmarc_fail", count: 2 },
      ],
    });
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
  it("shows the required columns and the security KPI cards", async () => {
    await renderLoaded();
    for (const name of ["Time", "Type", "Sender", "Score", "Status"]) {
      expect(screen.getByRole("columnheader", { name })).toBeInTheDocument();
    }
    expect(within(screen.getByRole("table", { name: /Quarantined messages/ })).getByText("Email")).toBeInTheDocument();
    expect(screen.getByText("99.7%")).toBeInTheDocument();
    expect(await screen.findByText("5 active isolations")).toBeInTheDocument();
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

describe("visual layer", () => {
  it("explains a chip in a tooltip on hover and on keyboard focus", async () => {
    await renderLoaded();
    const row = screen.getByText("md.office.desk@gmail.com").closest("tr")!;
    const chip = within(row).getByText("Text model").closest("[data-direction]") as HTMLElement;
    expect(screen.queryByRole("tooltip")).not.toBeInTheDocument();

    await userEvent.hover(chip);
    const tip = screen.getByRole("tooltip");
    expect(tip).toHaveTextContent("Wording resembles phishing (96%)");
    expect(tip).toHaveTextContent("Strong evidence towards phishing, text layer");
    expect(chip).toHaveAttribute("aria-describedby", tip.id);
    await userEvent.unhover(chip);
    expect(screen.queryByRole("tooltip")).not.toBeInTheDocument();

    chip.focus();
    expect(await screen.findByRole("tooltip")).toHaveTextContent("Wording resembles phishing");
    await userEvent.keyboard("{Escape}");
    expect(screen.queryByRole("tooltip")).not.toBeInTheDocument();
  });

  it("shows the poller as a live beacon", async () => {
    await renderLoaded();
    const beacon = document.querySelector(".beacon")!;
    expect(beacon).toHaveAttribute("data-state", "ok");
    expect(beacon).toHaveAttribute("aria-hidden", "true");
    expect(screen.getByText("Live")).toBeInTheDocument();
    expect(screen.getByText("Watching inbox · Active")).toBeInTheDocument();
  });

  it("tilts the KPI cards from the pointer without re-rendering", async () => {
    vi.stubGlobal("requestAnimationFrame", (callback: FrameRequestCallback) => {
      callback(0);
      return 1;
    });
    await renderLoaded();
    const card = (await screen.findByText("Total emails analyzed")).closest(".tilt-card") as HTMLElement;
    card.getBoundingClientRect = () => DOMRect.fromRect({ x: 0, y: 0, width: 200, height: 100 });
    card.dispatchEvent(new PointerEvent("pointermove", { bubbles: true, clientX: 200, clientY: 0, pointerType: "mouse" }));
    expect(card.style.getPropertyValue("--tilt-y")).toBe("2.50deg");
    expect(card.style.getPropertyValue("--tilt-x")).toBe("2.50deg");
    await userEvent.unhover(card);
    expect(card.style.getPropertyValue("--tilt-y")).toBe("");
  });
});

describe("security overview", () => {
  it("shows analyzed mail, false positive rate, threats and precision with trends", async () => {
    await renderLoaded();
    const value = async (label: string) => (await screen.findByText(label)).closest(".tilt-card")!;
    expect(await value("Total emails analyzed")).toHaveTextContent("250");
    expect(await value("Total emails analyzed")).toHaveTextContent("+25%");
    expect(await value("False positive rate")).toHaveTextContent("0%");
    expect(await value("Quarantined threats")).toHaveTextContent("5");
    expect(await value("Model precision")).toHaveTextContent("100%");
    expect(await value("Model precision")).toHaveTextContent("99.1% mean detection confidence");
  });

  it("names the top threat vectors with their share of quarantined mail", async () => {
    await renderLoaded();
    const vectors = (await screen.findByText("Top Threat Vectors")).closest("section")!;
    expect(await within(vectors).findByText("Phishing language (ML)")).toBeInTheDocument();
    expect(within(vectors).getByText("DMARC failures")).toBeInTheDocument();
    expect(vectors).toHaveTextContent("2 of 5");
  });

  it("keeps the range in the URL and refetches for it", async () => {
    await renderLoaded();
    await userEvent.click(screen.getByRole("button", { name: "7 days" }));
    expect(window.location.search).toBe("?range=7d");
    await waitFor(() =>
      expect(fetchMock.mock.calls.some(([url]) => String(url) === "/api/overview?days=7")).toBe(true),
    );
    expect(screen.getByRole("button", { name: "7 days" })).toHaveAttribute("aria-pressed", "true");
  });

  it("updates the false positive rate after a restore", async () => {
    await renderLoaded();
    await userEvent.click(screen.getByRole("button", { name: /Restore to Inbox: Quick task/ }));
    await userEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Restore to Inbox" }));
    const card = (await screen.findByText("False positive rate")).closest(".tilt-card")!;
    await waitFor(() => expect(card).toHaveTextContent("0.4%"));
    expect(card).toHaveTextContent("1 restored to inbox");
  });

  it("offers a Quick Scan sandbox that posts to /scan with the CSRF token", async () => {
    await renderLoaded();
    const box = screen.getByText("Message to scan").closest("form")!;
    expect(box).toHaveAttribute("action", "/scan");
    expect(box).toHaveAttribute("method", "post");
    expect(box.querySelector('input[name="csrf_token"]')).toHaveValue("csrf-123");
    expect(within(box).getByRole("radio", { name: "Email" })).toBeChecked();
    expect(within(box).getByRole("button", { name: "Run Scan" })).toBeEnabled();
  });
});

describe("motion", () => {
  it("slides a restored row out of the Held list before removing it", async () => {
    await renderLoaded();
    await userEvent.click(screen.getByRole("button", { name: /Restore to Inbox: Quick task/ }));
    await userEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Restore to Inbox" }));
    const leaving = await waitFor(() => {
      const row = document.querySelector(`tr[data-incident="${ROW.incident_id}"]`);
      expect(row).toHaveClass("is-leaving");
      return row!;
    });
    expect(within(leaving as HTMLElement).getByText("Restored")).toBeInTheDocument(); // no Restore button flash
    await waitFor(() => expect(document.querySelector(`tr[data-incident="${ROW.incident_id}"]`)).toBeNull());
  });

  it("pops only the digits of a KPI that changed", async () => {
    await renderLoaded();
    await userEvent.click(screen.getByRole("button", { name: /Restore to Inbox: Quick task/ }));
    await userEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Restore to Inbox" }));
    const card = (await screen.findByText("Quarantined threats")).closest(".tilt-card")!;
    await waitFor(() => expect(card).toHaveTextContent("4 active isolations"));
    const fp = (await screen.findByText("False positive rate")).closest(".tilt-card")!;
    await waitFor(() => expect(fp.querySelector(".t-digit-group")).toHaveClass("is-animating"));
    const digits = [...fp.querySelectorAll(".t-digit")];
    expect(digits.map((d) => d.textContent).join("")).toBe("0.4%");
    expect(digits[0]).toHaveAttribute("data-same"); // the leading "0" stays still
    expect(digits[1]).not.toHaveAttribute("data-same");
  });

  it("opens toasts on the next frame and plays the close before removing them", async () => {
    await renderLoaded();
    await userEvent.click(screen.getByRole("button", { name: /Restore to Inbox: Quick task/ }));
    await userEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Restore to Inbox" }));
    const toast = (await screen.findByText("Restored to Inbox")).closest(".t-toast")!;
    await waitFor(() => expect(toast).toHaveClass("is-open"));
    await userEvent.click(within(toast as HTMLElement).getByRole("button", { name: "Dismiss notification" }));
    expect(toast).not.toHaveClass("is-open");
    expect(toast).toBeInTheDocument(); // still closing
    await waitFor(() => expect(toast).not.toBeInTheDocument());
  });

  it("animates the confirm dialog closed on Escape and sends nothing", async () => {
    await renderLoaded();
    await userEvent.click(screen.getByRole("button", { name: /Restore to Inbox: Quick task/ }));
    const dialog = screen.getByRole("dialog");
    await waitFor(() => expect(dialog).toHaveClass("is-open"));
    dialog.dispatchEvent(new Event("cancel", { cancelable: true }));
    expect(dialog).toHaveClass("is-closing");
    await waitFor(() => expect((dialog as HTMLDialogElement).open).toBe(false));
    expect(fetchMock.mock.calls.some(([url]) => String(url).startsWith("/api/restore/"))).toBe(false);
  });

  it("moves the nav indicator to the section chosen", async () => {
    await renderLoaded();
    // jsdom has no layout, so only the click path is checked here (scroll-spy runs in e2e).
    const nav = screen.getAllByRole("navigation", { name: "Main" })[0];
    await userEvent.click(within(nav).getByRole("link", { name: /Quarantine/ }));
    expect(within(nav).getByRole("link", { name: /Quarantine/ })).toHaveAttribute("aria-current", "location");
    await userEvent.click(within(nav).getByRole("link", { name: /Threat Overview/ }));
    expect(within(nav).getByRole("link", { name: /Threat Overview/ })).toHaveAttribute("aria-current", "location");
    expect(within(nav).getByRole("link", { name: /Quarantine/ })).not.toHaveAttribute("aria-current");
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
    const table = screen.getByRole("table", { name: /Quarantined messages/ });
    const row = within(table).getByText("md.office.desk@gmail.com").closest("tr")!;
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

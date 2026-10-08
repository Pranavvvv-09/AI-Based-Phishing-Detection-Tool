// PhishGuard dashboard: Restore buttons and live quarantine table.
// Loaded as an external file (the CSP forbids inline script). All message-derived
// text is inserted with textContent, never innerHTML.
"use strict";

(function () {
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";
  const table = document.getElementById("quarantine");
  const status = document.getElementById("restore-status");
  const REFRESH_MS = 30000;

  function say(text, isError) {
    if (!status) return;
    status.textContent = text;
    status.classList.toggle("bad", Boolean(isError));
  }

  function el(tag, attrs, text) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs || {})) node.setAttribute(key, value);
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  // "2026-10-08T16:16:46Z" -> "2026-10-08 16:16 UTC" (same as the server's |when filter)
  function when(ts) {
    return ts ? String(ts).replace("T", " ").slice(0, 16) + " UTC" : "";
  }

  function weightChip(reason) {
    const sign = reason.weight > 0 ? "+" : "";
    return el("span", { class: "weight " + (reason.weight > 0 ? "up" : "down"),
                        title: reason.detail || "" },
              reason.code + " " + sign + Number(reason.weight).toFixed(1));
  }

  function row(q) {
    const tr = el("tr", { "data-incident": q.incident_id });
    const date = el("td", { class: "when" });
    date.append(el("a", { href: "/incidents/" + encodeURIComponent(q.incident_id) },
                    when(q.quarantined_at) || q.incident_id));
    const who = el("td", { class: "who" });
    who.append(el("div", {}, q.from), el("div", { class: "hint" }, q.subject));
    const weights = el("td");
    const chips = el("div", { class: "chips" });
    (q.reasons || []).forEach((r) => chips.append(weightChip(r)));
    weights.append(chips);
    const state = el("td", { class: "status" },
                     q.status === "restored" ? "restored " + when(q.restored_at) : q.status);
    const action = el("td");
    if (q.status !== "restored") {
      action.append(el("button", { type: "button", class: "restore",
                                   "data-restore": q.incident_id }, "Restore"));
    }
    tr.append(date, who, el("td", { class: "num" }, q.score_text), weights, state, action);
    return tr;
  }

  async function refreshTable() {
    if (!table) return;
    const response = await fetch("/api/quarantine", { credentials: "same-origin",
                                                      headers: { Accept: "application/json" } });
    if (response.status === 401) { window.location.assign("/login?next=/dashboard"); return; }
    if (!response.ok) throw new Error("refresh failed (" + response.status + ")");
    const data = await response.json();
    const body = table.tBodies[0];
    body.replaceChildren(...data.rows.map(row));
    if (!data.rows.length) {
      const empty = el("tr", { class: "empty" });
      empty.append(el("td", { colspan: "6", class: "hint" }, table.dataset.empty));
      body.append(empty);
    }
    for (const [key, value] of Object.entries(data.stats || {})) {
      const tile = document.querySelector('[data-stat="' + key + '"]');
      if (tile) tile.textContent = String(value);
    }
  }

  async function restore(button) {
    const id = button.dataset.restore;
    if (!window.confirm("Move this message back to your inbox?\n\n" +
                        "Only do this if you are sure it is not phishing.")) return;
    button.disabled = true;
    button.textContent = "Restoring…";
    say("Restoring " + id + "…");
    let data = {};
    let response;
    try {
      response = await fetch("/api/restore/" + encodeURIComponent(id), {
        method: "POST", credentials: "same-origin",
        headers: { "X-CSRF-Token": csrf, Accept: "application/json" },
      });
      data = await response.json().catch(() => ({}));
    } catch (err) {
      response = null;
    }
    if (response && response.status === 401) {
      window.location.assign("/login?next=" + encodeURIComponent(window.location.pathname));
      return;
    }
    if (response && response.ok) {
      say("Restored to " + data.to_folder + " at " + when(data.restored_at) + ".");
      const holder = button.closest("[data-incident]");
      const state = holder && holder.querySelector(".status");
      if (state) state.textContent = "restored " + when(data.restored_at);
      button.remove();
    } else {
      const reason = (data && data.error) || "network error";
      say("Could not restore: " + reason, true);
      button.disabled = false;
      button.textContent = "Restore";
    }
    // 409 (already restored elsewhere) also lands here: the refresh shows the truth.
    try { await refreshTable(); } catch (err) { /* keep the current table */ }
  }

  document.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-restore]");
    if (button && !button.disabled) restore(button);
  });

  if (table) {
    window.setInterval(() => {
      if (document.visibilityState === "visible") refreshTable().catch(() => {});
    }, REFRESH_MS);
  }
})();

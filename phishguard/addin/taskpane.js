/* PhishGuard Outlook task pane.
 * Reads the open message with Office.js and sends it to the PhishGuard API
 * (same origin that serves this page). Everything rendered from the API response
 * goes through textContent, never innerHTML, because it contains attacker-controlled text.
 */
(function () {
  "use strict";

  const API = new URL("../api/v1/analyze/email", window.location.href).toString();
  const SETTINGS_KEY = "phishguardApiKey";
  const $ = (id) => document.getElementById(id);

  function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  function show(which) {
    ["loading", "result", "error"].forEach((id) => $(id).classList.toggle("hidden", id !== which));
  }

  function asPromise(fn) {
    return new Promise((resolve, reject) =>
      fn((res) => (res.status === Office.AsyncResultStatus.Succeeded ? resolve(res.value) : reject(res.error))));
  }

  function base64ToUtf8(b64) {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder("utf-8").decode(bytes);
  }

  // Best source: the full original message (Mailbox 1.14+). Falls back to headers + body (1.8+).
  async function readMessage() {
    const item = Office.context.mailbox.item;
    if (item.getAsFileAsync && Office.context.requirements.isSetSupported("Mailbox", "1.14")) {
      try {
        const b64 = await asPromise((cb) => item.getAsFileAsync(cb));
        return { raw: base64ToUtf8(b64) };
      } catch (e) { /* fall through */ }
    }
    const [headers, html] = await Promise.all([
      asPromise((cb) => item.getAllInternetHeadersAsync(cb)).catch(() => ""),
      asPromise((cb) => item.body.getAsync(Office.CoercionType.Html, cb)).catch(() => ""),
    ]);
    if (headers) {
      // Rebuild a minimal RFC 822 message so the server sees real auth headers.
      const head = headers.replace(/^content-(type|transfer-encoding):.*(\r?\n[ \t].*)*\r?\n?/gim, "").trimEnd();
      return { raw: `${head}\r\nContent-Type: text/html; charset=utf-8\r\n\r\n${html}` };
    }
    const from = item.from ? `${item.from.displayName} <${item.from.emailAddress}>` : "";
    return { sender: from, subject: item.subject || "", html };
  }

  function apiKey() {
    try { return Office.context.roamingSettings.get(SETTINGS_KEY) || ""; } catch (e) { return ""; }
  }

  function render(r) {
    const out = $("result");
    out.replaceChildren();
    const color = { safe: "var(--safe)", suspicious: "var(--sus)", phishing: "var(--phish)" }[r.verdict];
    const label = { safe: "Looks safe", suspicious: "Be careful", phishing: "Phishing detected" }[r.verdict];
    out.append(el("div", "verdict " + r.verdict, label));
    const meter = el("div", "meter");
    const bar = el("div");
    bar.style.width = "0%";
    bar.style.background = color;
    meter.append(bar);
    out.append(meter, el("div", "status", `Risk ${r.risk_score}/100`));
    requestAnimationFrame(() => (bar.style.width = r.risk_score + "%"));

    const advice = {
      safe: "No signs of phishing were found. Stay alert for unexpected requests for money or passwords.",
      suspicious: "Don't click links, open attachments or reply with sensitive information until you've confirmed the sender another way.",
      phishing: "Don't click any links, open attachments or reply. Report it to your IT/security team and delete it.",
    }[r.verdict];
    out.append(el("div", "advice", r.llm && r.llm.recommended_action ? r.llm.recommended_action : advice));

    if (r.llm && r.llm.reasons && r.llm.reasons.length) {
      out.append(el("h2", null, "Why"));
      const ul = el("ul");
      r.llm.reasons.slice(0, 5).forEach((x) => ul.append(el("li", null, x)));
      out.append(ul);
    }
    const signals = (r.findings || []).filter((f) => f.severity !== "info").slice(0, 8);
    if (signals.length) {
      out.append(el("h2", null, "Warning signs"));
      const ul = el("ul");
      signals.forEach((f) => {
        const li = el("li");
        li.append(el("span", "sev sev-" + f.severity, f.severity), document.createTextNode(f.description));
        ul.append(li);
      });
      out.append(ul);
    }
    show("result");
  }

  function fail(message, offerSettings) {
    const box = $("error");
    box.replaceChildren(el("p", "phishing", message));
    if (offerSettings) $("settings").classList.remove("hidden");
    show("error");
  }

  async function check() {
    show("loading");
    try {
      const payload = await readMessage();
      const headers = { "Content-Type": "application/json" };
      const key = apiKey();
      if (key) headers["X-API-Key"] = key;
      const resp = await fetch(API, { method: "POST", headers, body: JSON.stringify(payload) });
      if (resp.status === 401) return fail("This organization requires an access key. Enter it in Settings.", true);
      if (!resp.ok) return fail(`PhishGuard couldn't check this email (error ${resp.status}). Try again in a moment.`);
      render(await resp.json());
    } catch (e) {
      fail("PhishGuard couldn't read or check this email. " + (e && e.message ? e.message : ""));
    }
  }

  Office.onReady(() => {
    $("apikey").value = apiKey();
    $("recheck").addEventListener("click", check);
    $("toggleSettings").addEventListener("click", () => $("settings").classList.toggle("hidden"));
    $("save").addEventListener("click", () => {
      Office.context.roamingSettings.set(SETTINGS_KEY, $("apikey").value.trim());
      Office.context.roamingSettings.saveAsync(() => { $("settings").classList.add("hidden"); check(); });
    });
    // Re-check automatically when the user selects a different email (pinned task pane).
    if (Office.context.mailbox.addHandlerAsync) {
      Office.context.mailbox.addHandlerAsync(Office.EventType.ItemChanged, () => Office.context.mailbox.item && check());
    }
    check();
  });
})();

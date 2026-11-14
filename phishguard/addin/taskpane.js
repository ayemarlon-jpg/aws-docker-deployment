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

  const NS = "http://www.w3.org/2000/svg";
  function icon(id) {
    const svg = document.createElementNS(NS, "svg");
    const use = document.createElementNS(NS, "use");
    use.setAttribute("href", "#" + id);
    svg.append(use);
    return svg;
  }

  function ring(score) {
    const R = 31, C = 2 * Math.PI * R;
    const svg = document.createElementNS(NS, "svg");
    svg.setAttribute("viewBox", "0 0 76 76");
    const mk = (stroke, dash) => {
      const c = document.createElementNS(NS, "circle");
      [["cx", 38], ["cy", 38], ["r", R], ["fill", "none"], ["stroke", stroke], ["stroke-width", 8], ["stroke-linecap", "round"]].forEach(([k, v]) => c.setAttribute(k, v));
      if (dash) { c.setAttribute("stroke-dasharray", C); c.setAttribute("stroke-dashoffset", C); c.style.transition = "stroke-dashoffset 1s cubic-bezier(.2,.8,.2,1)"; }
      return c;
    };
    const track = mk("color-mix(in srgb, var(--v) 18%, transparent)");
    const arc = mk("var(--v)", true);
    svg.append(track, arc);
    const n = el("div", "n");
    const num = el("div", null, "0");
    n.append(el("div"));
    n.firstChild.append(num, el("small", null, "RISK"));
    const wrap = el("div", "ring");
    wrap.append(svg, n);
    requestAnimationFrame(() => requestAnimationFrame(() => (arc.style.strokeDashoffset = C * (1 - score / 100))));
    const t0 = performance.now();
    const step = (t) => { const p = Math.min(1, (t - t0) / 1000); num.textContent = Math.round(score * (1 - Math.pow(1 - p, 3))); if (p < 1) requestAnimationFrame(step); };
    requestAnimationFrame(step);
    return wrap;
  }

  const VERDICT = {
    safe: { title: "Looks safe", sub: "No meaningful phishing signals.", advice: "No signs of phishing found. Still be careful with unexpected requests for money, passwords or codes." },
    suspicious: { title: "Be careful", sub: "Some warning signs found.", advice: "Don't click links, open attachments or share information until you've confirmed the sender another way." },
    phishing: { title: "Phishing detected", sub: "Strong signs of an attack.", advice: "Don't click links, open attachments or reply. Report it to your IT/security team and delete it." },
  };

  function render(r) {
    const v = VERDICT[r.verdict];
    const out = $("result");
    out.className = "fade v-" + r.verdict;
    out.replaceChildren();

    const hero = el("div", "hero");
    const txt = el("div");
    txt.append(el("div", "title", v.title), el("div", "sub", v.sub));
    hero.append(ring(r.risk_score), txt);
    out.append(hero);

    const advice = el("div", "advice");
    advice.append(icon(r.verdict === "safe" ? "i-shield" : "i-alert"), el("div", null, r.llm && r.llm.recommended_action ? r.llm.recommended_action : v.advice));
    out.append(advice);

    if (r.llm) {
      const h = el("h2"); h.append(icon("i-sparkle"), document.createTextNode("AI assessment"));
      const box = el("div", "ai");
      const tags = el("div", "tags");
      tags.append(el("span", "tag", `${Math.round(r.llm.confidence * 100)}% confident`));
      if (r.llm.attack_type && r.llm.attack_type !== "none") tags.append(el("span", "tag", r.llm.attack_type.replace(/_/g, " ")));
      if (r.llm.impersonated_brand && r.llm.impersonated_brand.toLowerCase() !== "none") tags.append(el("span", "tag", "Impersonating " + r.llm.impersonated_brand));
      const ul = el("ul");
      (r.llm.reasons || []).slice(0, 5).forEach((x) => ul.append(el("li", null, x)));
      box.append(tags, ul);
      out.append(h, box);
    }

    const signals = (r.findings || []).filter((f) => f.severity !== "info").slice(0, 8);
    if (signals.length) {
      const h = el("h2"); h.append(icon("i-alert"), document.createTextNode(`Warning signs · ${signals.length}`));
      const ul = el("ul", "list");
      signals.forEach((f, i) => {
        const li = el("li");
        li.style.animationDelay = i * 40 + "ms";
        li.append(el("span", "sd sd-" + f.severity), el("span", null, f.description));
        ul.append(li);
      });
      out.append(h, ul);
    }
    if (!r.llm && r.llm_status !== "disabled") out.append(el("p", "muted", "AI analysis was unavailable, so this verdict uses security rules only."));
    show("result");
  }

  function fail(message, offerSettings) {
    const box = $("error");
    box.replaceChildren();
    const inner = el("div", "error fade");
    inner.append(icon("i-alert"), el("div", null, message));
    box.append(inner);
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

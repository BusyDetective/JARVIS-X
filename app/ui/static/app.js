"use strict";
// JARVIS-X dashboard. Every dynamic value is inserted with textContent / createElement (never innerHTML),
// so model output, page text and tool results cannot inject markup or script.
(() => {
  const $ = (id) => document.getElementById(id);
  const state = { sessionId: null, conversationId: null, lastSeq: 0, runId: null, sessions: [], settings: null,
                  voice: null, speaking: false, speakQueue: [], audio: null, recorder: null, recognition: null, polling: null };

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }
  function toast(msg) {
    const t = $("toast"); t.textContent = msg; t.classList.remove("hidden");
    clearTimeout(toast.h); toast.h = setTimeout(() => t.classList.add("hidden"), 6000);
  }
  async function api(method, path, body, raw) {
    const headers = { "X-JarvisX-Client": "dashboard" };
    let payload;
    if (raw) { payload = raw.body; headers["Content-Type"] = raw.type; }
    else if (body !== undefined) { payload = JSON.stringify(body); headers["Content-Type"] = "application/json"; }
    const res = await fetch(path, { method, headers, body: payload, credentials: "same-origin" });
    if (res.status === 401 && !path.startsWith("/api/auth/login")) { showLogin(); throw new Error("Locked: enter the access token"); }
    if (!res.ok) {
      let msg = res.statusText;
      try { const j = await res.json(); msg = j.error || msg; if (j.details) msg += " (" + j.details.join("; ") + ")"; } catch (_) {}
      throw new Error(msg);
    }
    const ct = res.headers.get("content-type") || "";
    return ct.includes("application/json") ? res.json() : res;
  }
  const guard = (fn) => async (...a) => { try { return await fn(...a); } catch (e) { toast(e.message || String(e)); } };

  // ---------- login ----------
  function showLogin() { $("app").classList.add("hidden"); $("login").classList.remove("hidden"); stopPolling(); }
  async function doLogin() {
    $("login-error").textContent = "";
    try { await api("POST", "/api/auth/login", { token: $("login-token").value }); $("login-token").value = ""; await boot(); }
    catch (e) { $("login-error").textContent = e.message; }
  }

  // ---------- sessions ----------
  async function loadSessions() {
    const { sessions } = await api("GET", "/api/sessions");
    state.sessions = sessions;
    const ul = $("session-list"); ul.replaceChildren();
    for (const s of sessions) {
      const li = el("li", (s.id === state.sessionId ? "active " : "") + (s.active ? "" : "closed"), s.title || "Untitled session");
      li.title = s.id; li.addEventListener("click", () => selectSession(s.id)); ul.appendChild(li);
    }
  }
  const newSession = guard(async () => {
    const r = await api("POST", "/api/sessions", {});
    await loadSessions(); await selectSession(r.session.id);
  });
  async function selectSession(id) {
    state.sessionId = id; state.lastSeq = 0; state.runId = null; $("messages").replaceChildren();
    const r = await api("GET", "/api/sessions/" + id);
    const convs = r.conversations;
    state.conversationId = convs.length ? convs[convs.length - 1].id : (await api("POST", "/api/sessions/" + id + "/conversations")).conversation.id;
    $("chat-title").textContent = (r.session.title || "Untitled session") + (r.session.active ? "" : " (closed)");
    await loadSessions(); await loadMessages(); startPolling();
  }

  // ---------- messages ----------
  function renderMessage(m) {
    const box = $("messages");
    if (m.role === "tool") {
      const d = el("details", "tool"); d.appendChild(el("summary", null, "🔧 " + (m.tool_name || "tool") + " — result"));
      let shown = m.content;
      try { const j = JSON.parse(m.content);
        const shot = j.screenshot || (j.result && j.result.screenshot) || (j.output && j.output.screenshot);
        if (shot && shot.screenshot_id) { const img = document.createElement("img"); img.alt = "Browser screenshot"; img.src = "/api/browser/screenshots/" + encodeURIComponent(shot.screenshot_id); d.appendChild(img); }
        shown = JSON.stringify(j, null, 2); } catch (_) {}
      d.appendChild(el("pre", null, shown)); box.appendChild(d); return;
    }
    const div = el("div", "msg " + m.role); div.appendChild(el("div", "who", m.role === "user" ? "You" : "JARVIS-X"));
    div.appendChild(el("div", null, m.content || ""));
    box.appendChild(div);
    if (m.tool_calls && m.tool_calls.length) {
      for (const c of m.tool_calls) {
        const d = el("details", "tool"); d.appendChild(el("summary", null, "⚙ requested: " + c.name));
        d.appendChild(el("pre", null, JSON.stringify(c.arguments, null, 2))); box.appendChild(d);
      }
    }
  }
  async function loadMessages() {
    if (!state.conversationId) return null;
    const cid = state.conversationId;
    const r = await api("GET", "/api/conversations/" + cid + "/messages?after=" + state.lastSeq);
    if (cid !== state.conversationId) return null;
    const box = $("messages"); const nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 80;
    for (const m of r.messages) { renderMessage(m); state.lastSeq = Math.max(state.lastSeq, m.sequence); }
    if (r.messages.length && nearBottom) box.scrollTop = box.scrollHeight;
    return r;
  }
  async function sendText(text, source, confirmed) {
    if (!state.conversationId) { toast("Create or select a session first"); return; }
    const r = await api("POST", "/api/conversations/" + state.conversationId + "/messages", { text, source, confirmed });
    state.runId = r.run_id; setBusy(true); await loadMessages(); startPolling();
  }
  const onSend = guard(async () => {
    const text = $("input").value.trim(); if (!text) return;
    $("input").value = ""; updateCount(); await sendText(text, "text", false);
  });
  function setBusy(b) { $("send").disabled = b; $("input").disabled = b; }
  function updateCount() { const n = $("input").value.length; const max = state.settings ? state.settings.ui.max_message_chars : 0;
    $("char-count").textContent = max ? n + " / " + max : ""; }

  // ---------- polling ----------
  function stopPolling() { clearInterval(state.polling); state.polling = null; }
  function startPolling() { stopPolling(); state.polling = setInterval(tick, 1200); tick(); }
  let ticking = false;
  async function tick() {
    if (ticking) return; ticking = true;
    try {
      const r = state.conversationId ? await loadMessages() : null;
      const run = r && r.active_run;
      const rs = $("run-status");
      if (run) { setBusy(true); rs.textContent = run.state === "awaiting_approval" ? "⏸ Waiting for your approval…" : "⏳ JARVIS-X is working…"; state.runId = run.id; }
      else if (state.runId) {
        const done = await api("GET", "/api/runs/" + state.runId); const rr = done.run; state.runId = null; setBusy(false);
        if (rr.state === "failed") { rs.textContent = "✖ Run failed" + (rr.error ? ": " + rr.error : ""); }
        else { rs.textContent = "✔ Done" + (rr.model ? " · " + rr.provider + "/" + rr.model : ""); await loadMessages(); if (rr.final_response) maybeSpeak(rr.final_response); }
        loadTasks();
      } else { setBusy(false); }
      await loadApprovals();
    } catch (e) { /* surfaced via toast in api() callers; keep polling */ }
    finally { ticking = false; }
  }

  // ---------- approvals ----------
  async function loadApprovals() {
    const r = await api("GET", "/api/approvals");
    const pane = $("tab-approvals"); pane.replaceChildren();
    const pill = $("approval-count"); pill.textContent = r.pending.length; pill.classList.toggle("hidden", r.pending.length === 0);
    if (!r.pending.length) pane.appendChild(el("div", "muted", "No pending approvals. Sensitive tools ask here before they run."));
    for (const a of r.pending) {
      const c = el("div", "card warn"); c.appendChild(el("h3", null, a.tool_name + "  [" + a.level + "]"));
      for (const [k, v] of Object.entries(a.arguments)) { const kv = el("div", "kv"); kv.appendChild(el("b", null, k + ": ")); kv.appendChild(document.createTextNode(v)); c.appendChild(kv); }
      if (a.context) for (const [k, v] of Object.entries(a.context)) { const kv = el("div", "kv"); kv.appendChild(el("b", null, "▶ " + k + ": ")); kv.appendChild(document.createTextNode(String(v))); c.appendChild(kv); }
      c.appendChild(el("div", "muted", "Expires in " + a.expires_in + "s (no decision = denied)"));
      let ack = null;
      if (a.requires_acknowledgement) { const lab = el("label", "kv"); ack = document.createElement("input"); ack.type = "checkbox"; lab.appendChild(ack); lab.appendChild(document.createTextNode(" I understand this action is DANGEROUS")); c.appendChild(lab); }
      const row = el("div", "row"); const yes = el("button", "primary", "Approve"); const no = el("button", "danger", "Deny");
      yes.addEventListener("click", guard(async () => { await api("POST", "/api/approvals/" + a.id + "/decision", { decision: "approve", acknowledged: !!(ack && ack.checked) }); loadApprovals(); }));
      no.addEventListener("click", guard(async () => { await api("POST", "/api/approvals/" + a.id + "/decision", { decision: "deny" }); loadApprovals(); }));
      row.append(yes, no); c.appendChild(row); pane.appendChild(c);
    }
  }

  // ---------- tasks ----------
  const loadTasks = guard(async () => {
    const r = await api("GET", "/api/tasks?limit=20"); const pane = $("tab-tasks"); pane.replaceChildren();
    if (!r.tasks.length) pane.appendChild(el("div", "muted", "No tasks yet."));
    for (const t of r.tasks) {
      const c = el("div", "card"); const h = el("h3", null, t.user_request); c.appendChild(h);
      c.appendChild(el("div", "kv status-" + t.status, "status: " + t.status));
      if (t.error) c.appendChild(el("div", "kv", "error: " + t.error));
      c.appendChild(el("div", "muted", new Date(t.created_at).toLocaleString())); pane.appendChild(c);
    }
  });

  // ---------- settings / capabilities ----------
  const loadSettings = guard(async () => {
    const [s, caps, si, br] = await Promise.all([api("GET", "/api/settings"), api("GET", "/api/capabilities"), api("GET", "/api/self-improvement"), api("GET", "/api/browser/status")]);
    state.settings = s; state.voice = s.voice; updateCount();
    const badges = $("badges"); badges.replaceChildren();
    badges.appendChild(el("span", "badge " + (si.config_enabled ? "off" : "ok"), si.config_enabled ? "Self-improvement: configured" : "Self-improvement: DISABLED"));
    badges.appendChild(el("span", "badge " + (br.available ? "ok" : "off"), "Browser: " + (br.available ? "available" : "off")));
    badges.appendChild(el("span", "badge " + (s.voice.input.enabled ? "ok" : "off"), "Voice in: " + s.voice.input.provider));
    badges.appendChild(el("span", "badge " + (s.voice.output.enabled ? "ok" : "off"), "Voice out: " + s.voice.output.provider));
    $("mic").classList.toggle("hidden", !s.voice.input.enabled);
    $("speak-wrap").classList.toggle("hidden", !s.voice.output.enabled);
    const pane = $("tab-settings"); pane.replaceChildren();
    const siCard = el("div", "card" + (si.config_enabled ? " warn" : "")); siCard.appendChild(el("h3", null, "Self-improvement"));
    siCard.appendChild(el("div", "kv", si.message)); pane.appendChild(siCard);
    const prov = el("div", "card"); prov.appendChild(el("h3", null, "Providers (keys are never sent to the browser)"));
    for (const [k, v] of Object.entries(s.providers.configured)) prov.appendChild(el("div", "kv", k + ": " + (v ? "configured" : "no key")));
    prov.appendChild(el("div", "kv", "order: " + s.providers.order.join(" → "))); pane.appendChild(prov);
    const bc = el("div", "card"); bc.appendChild(el("h3", null, "Browser"));
    bc.appendChild(el("div", "kv", br.available ? ("active: " + br.active + (br.url ? " · " + br.url : "") + " · actions used " + br.actions_used) : ("unavailable: " + (br.reason || ""))));
    if (br.available) { const b = el("button", "ghost", "Close browser"); b.addEventListener("click", guard(async () => { await api("POST", "/api/browser/close", {}); loadSettings(); })); bc.appendChild(b); }
    pane.appendChild(bc);
    const vc = el("div", "card"); vc.appendChild(el("h3", null, "Voice"));
    for (const side of ["input", "output"]) { const v = s.voice[side];
      vc.appendChild(el("div", "kv", side + ": " + (v.enabled ? v.provider + " (" + v.location + ")" : "off — " + (v.reason || ""))));
      if (v.privacy_note) vc.appendChild(el("div", "muted", v.privacy_note)); }
    vc.appendChild(el("div", "muted", "Voice never approves actions and no audio is stored.")); pane.appendChild(vc);
    for (const c of caps.capabilities) {
      const card = el("div", "card"); card.appendChild(el("h3", null, c.name + " (" + c.id + ")"));
      card.appendChild(el("div", "kv", c.description));
      card.appendChild(el("div", "kv", "max permission: " + c.effective_max_permission + " · " + c.tools.length + " tools"));
      const row = el("div", "row"); row.appendChild(el("span", "badge " + (c.enabled ? "ok" : "off"), c.enabled ? "enabled" : "disabled"));
      if (!(c.id === "self_improvement" && !c.enabled)) {
        const b = el("button", "ghost", c.enabled ? "Disable" : "Enable");
        b.addEventListener("click", guard(async () => { await api("POST", "/api/capabilities/" + c.id + "/enabled", { enabled: !c.enabled }); loadSettings(); }));
        row.appendChild(b); }
      card.appendChild(row); pane.appendChild(card);
    }
  });

  // ---------- voice input (push-to-talk, explicit, transcript must be confirmed) ----------
  function offerTranscript(text) { $("voice-text").value = text; $("voice-confirm").classList.remove("hidden"); $("voice-text").focus(); }
  function micIdle() { $("mic").textContent = "🎤 Voice"; state.recorder = null; state.recognition = null; }
  const onMic = guard(async () => {
    if (state.recorder) { state.recorder.stop(); return; }
    if (state.recognition) { state.recognition.stop(); return; }
    const v = state.voice && state.voice.input; if (!v || !v.enabled) { toast("Voice input is disabled"); return; }
    if (v.client_side) {
      const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
      if (!SR) { toast("This browser has no speech recognition; use text or a local provider."); return; }
      const r = new SR(); r.interimResults = false; r.maxAlternatives = 1; r.continuous = false;
      r.onresult = (ev) => offerTranscript(ev.results[0][0].transcript);
      r.onerror = (ev) => { toast("Speech recognition failed: " + ev.error); micIdle(); };
      r.onend = micIdle; state.recognition = r; $("mic").textContent = "⏹ Stop"; r.start();
    } else {
      if (!navigator.mediaDevices || !window.MediaRecorder) { toast("Audio recording is not supported in this browser."); return; }
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });  // explicit permission prompt
      const rec = new MediaRecorder(stream); const chunks = []; state.recorder = rec; $("mic").textContent = "⏹ Stop";
      const cap = setTimeout(() => rec.state === "recording" && rec.stop(), 30000);
      rec.ondataavailable = (e) => chunks.push(e.data);
      rec.onstop = guard(async () => {
        clearTimeout(cap); stream.getTracks().forEach((t) => t.stop()); micIdle();
        const blob = new Blob(chunks, { type: rec.mimeType || "audio/webm" });
        const out = await api("POST", "/api/voice/transcribe", undefined, { body: blob, type: blob.type || "application/octet-stream" });
        offerTranscript(out.transcript);
      });
      rec.start();
    }
  });
  const onVoiceSend = guard(async () => {
    const text = $("voice-text").value.trim(); if (!text) return;
    $("voice-confirm").classList.add("hidden"); await sendText(text, "voice", true);
  });

  // ---------- spoken replies (optional, stoppable, non-blocking) ----------
  function stopSpeech() { state.speakQueue = []; if (window.speechSynthesis) speechSynthesis.cancel(); if (state.audio) { state.audio.pause(); state.audio = null; } state.speaking = false; $("stop-speech").classList.add("hidden"); }
  async function maybeSpeak(text) {
    if (!$("speak-toggle").checked || !state.voice || !state.voice.output.enabled) return;
    try {
      const plan = await api("POST", "/api/voice/speech-plan", { text }); stopSpeech(); state.speaking = true; $("stop-speech").classList.remove("hidden");
      state.speakQueue = plan.chunks.slice(); nextChunk(plan.client_side);
    } catch (e) { toast("Speech unavailable: " + e.message); }
  }
  async function nextChunk(clientSide) {
    if (!state.speaking || !state.speakQueue.length) { stopSpeech(); return; }
    const chunk = state.speakQueue.shift();
    try {
      if (clientSide) { const u = new SpeechSynthesisUtterance(chunk); u.onend = () => nextChunk(true); u.onerror = () => { toast("Audio playback failed"); stopSpeech(); }; speechSynthesis.speak(u); }
      else {
        const res = await api("POST", "/api/voice/synthesize", { text: chunk }); const url = URL.createObjectURL(await res.blob());
        const a = new Audio(url); state.audio = a; a.onended = () => { URL.revokeObjectURL(url); nextChunk(false); };
        a.onerror = () => { URL.revokeObjectURL(url); toast("Audio playback failed"); stopSpeech(); }; await a.play();
      }
    } catch (e) { toast("Speech failed: " + e.message); stopSpeech(); }
  }

  // ---------- boot ----------
  async function boot() {
    $("login").classList.add("hidden"); $("app").classList.remove("hidden");
    await Promise.all([loadSettings(), loadSessions(), loadTasks(), loadApprovals()]);
    if (state.sessions.length && !state.sessionId) await selectSession(state.sessions[0].id); else startPolling();
  }
  function wire() {
    $("login-btn").addEventListener("click", doLogin);
    $("login-token").addEventListener("keydown", (e) => e.key === "Enter" && doLogin());
    $("logout-btn").addEventListener("click", guard(async () => { await api("POST", "/api/auth/logout", {}); showLogin(); }));
    $("new-session").addEventListener("click", newSession);
    $("send").addEventListener("click", onSend);
    $("input").addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); onSend(); } });
    $("input").addEventListener("input", updateCount);
    $("mic").addEventListener("click", onMic);
    $("voice-send").addEventListener("click", onVoiceSend);
    $("voice-discard").addEventListener("click", () => { $("voice-confirm").classList.add("hidden"); $("voice-text").value = ""; });
    $("stop-speech").addEventListener("click", stopSpeech);
    $("speak-toggle").addEventListener("change", () => { if (!$("speak-toggle").checked) stopSpeech(); });
    for (const t of document.querySelectorAll(".tab")) t.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((x) => x.classList.toggle("active", x === t));
      for (const p of ["approvals", "tasks", "settings"]) $("tab-" + p).classList.toggle("hidden", p !== t.dataset.tab);
      if (t.dataset.tab === "tasks") loadTasks(); if (t.dataset.tab === "settings") loadSettings();
    });
  }
  wire();
  api("GET", "/api/auth/status").then(boot).catch(showLogin);
})();

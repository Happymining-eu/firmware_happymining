"use strict";
(function () {
  const $ = (id) => document.getElementById(id);
  const REFRESH_MS = 5000;
  let unlocked = false;
  let paired = null;

  function text(id, value, cls) {
    const el = $(id);
    el.textContent = value === undefined || value === null || value === "" ? "—" : String(value);
    el.className = cls || "";
  }
  function bytes(n) {
    if (n === null || n === undefined) return "—";
    const u = ["B", "KiB", "MiB", "GiB", "TiB"];
    let i = 0, v = Number(n);
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return (i === 0 ? v : v.toFixed(1)) + " " + u[i];
  }
  function duration(s) {
    if (s === null || s === undefined) return "—";
    const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
    return (d ? d + "d " : "") + h + "h " + m + "m";
  }
  function ago(iso) {
    if (!iso) return "never (since the agent started)";
    const sec = Math.round((Date.now() - Date.parse(iso)) / 1000);
    if (isNaN(sec)) return iso;
    if (sec < 90) return sec + " s ago";
    if (sec < 5400) return Math.round(sec / 60) + " min ago";
    return Math.round(sec / 3600) + " h ago";
  }
  function stateClass(state) {
    if (/^(ok|active|running|healthy)$/i.test(state)) return "state-ok";
    if (/^(failed|error|revoked)$/i.test(state)) return "state-bad";
    return "state-warn";
  }

  async function api(path, body) {
    const opts = body ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) } : {};
    const r = await fetch(path, opts);
    let data = null;
    try { data = await r.json(); } catch (e) { data = null; }
    if (!r.ok) throw new Error((data && data.error) || ("HTTP " + r.status));
    return data;
  }

  function renderPairing(st) {
    const card = $("pairing-card");
    paired = st.paired;
    unlocked = st.unlocked;
    card.classList.toggle("paired", st.paired);
    card.classList.toggle("unpaired", !st.paired);
    $("unlock-form").hidden = true; $("pair-form").hidden = true; $("locked-note").hidden = true; $("pair-ids").hidden = true;
    if (st.paired) {
      $("pair-title").textContent = "Paired with HappyMining";
      $("pair-text").textContent = "This machine reports to your organisation. Credential " + (st.credential_id || "");
      $("device-id").textContent = st.device_id || "";
      $("machine-id").textContent = st.machine_id || "";
      $("pair-ids").hidden = false;
      return;
    }
    $("pair-title").textContent = "Not paired yet";
    $("pair-text").textContent = st.credential_error
      ? st.credential_error
      : "Pair it with a single-use code from your HappyMining administrator. Nothing else on this page changes the machine.";
    if (unlocked) {
      $("pair-form").hidden = false;
    } else if (st.unlock_available) {
      $("unlock-form").hidden = false;
    } else {
      $("locked-note").hidden = false;
    }
  }

  function renderAgent(st) {
    text("agent-state", st.agent_state, stateClass(st.agent_state));
    text("heartbeat", ago(st.last_heartbeat_ok));
    text("api", (st.api_reachable ? "reachable" : "NOT reachable") + (st.api_detail ? " — " + st.api_detail : ""),
      st.api_reachable ? "state-ok" : "state-bad");
    text("spool", st.spool_samples + " sample(s), " + bytes(st.spool_bytes) + " of " + bytes(st.spool_quota_bytes));
    text("last-error", st.last_error || "none", st.last_error ? "wrap state-warn" : "wrap");
  }

  function renderHost(st) {
    const s = st.sample;
    if (!s) { text("uptime", "no sample yet"); return; }
    text("uptime", duration(s.uptime_s));
    const cpu = s.cpu || {};
    text("cpu", [cpu.model, cpu.cores ? cpu.cores + " cores" : null, cpu.load1 !== null && cpu.load1 !== undefined ? "load " + cpu.load1 : null,
      cpu.util_pct !== null && cpu.util_pct !== undefined ? Math.round(cpu.util_pct) + "% busy" : null].filter(Boolean).join(" · "));
    const m = s.memory || {};
    if (m.total_bytes) {
      const used = m.total_bytes - (m.available_bytes || 0);
      text("memory", bytes(used) + " used of " + bytes(m.total_bytes));
    } else { text("memory", "—"); }
    text("vast", s.vast && s.vast.daemon_installed ? "installed" : "not installed (manual step)", s.vast && s.vast.daemon_installed ? "state-ok" : "state-warn");

    const disks = $("disks"); disks.innerHTML = "";
    (s.disks || []).forEach((d) => {
      if (!d.total_bytes) return;
      const used = d.total_bytes - (d.avail_bytes || 0), pct = Math.round(100 * used / d.total_bytes);
      const el = document.createElement("div"); el.className = "bar";
      el.innerHTML = '<div class="lbl"><span></span><span></span></div><div class="track"><div class="fill"></div></div>';
      el.querySelector(".lbl span:first-child").textContent = d.mount + " (" + d.fs + ")";
      el.querySelector(".lbl span:last-child").textContent = bytes(used) + " / " + bytes(d.total_bytes) + " · " + pct + "%";
      const fill = el.querySelector(".fill"); fill.style.width = pct + "%"; if (pct >= 90) fill.classList.add("hot");
      disks.appendChild(el);
    });

    const svc = $("services"); svc.innerHTML = "";
    Object.keys(s.services || {}).sort().forEach((unit) => {
      const li = document.createElement("li");
      const name = document.createElement("span"); name.textContent = unit;
      const pill = document.createElement("span"); pill.className = "pill " + (s.services[unit] || ""); pill.textContent = s.services[unit];
      li.appendChild(name); li.appendChild(pill); svc.appendChild(li);
    });

    const body = $("gpus").querySelector("tbody"); body.innerHTML = "";
    const gpus = s.gpus || [];
    $("gpu-count").textContent = gpus.length ? gpus.length : "";
    $("gpu-empty").hidden = gpus.length > 0;
    gpus.forEach((g) => {
      const tr = document.createElement("tr");
      const cells = [g.index, g.name, g.util_pct == null ? "—" : g.util_pct + "%",
        g.vram_total_mib == null ? "—" : (g.vram_used_mib == null ? "?" : g.vram_used_mib) + " / " + g.vram_total_mib + " MiB",
        g.temp_c == null ? "—" : g.temp_c + " °C", g.power_w == null ? "—" : Math.round(g.power_w) + " W", g.fan_pct == null ? "—" : g.fan_pct + "%"];
      cells.forEach((c, i) => { const td = document.createElement("td"); if (i >= 2) td.className = "num"; td.textContent = c; tr.appendChild(td); });
      body.appendChild(tr);
    });
  }

  async function refresh() {
    try {
      const st = await api("/api/status");
      $("hostname").textContent = st.hostname || "(no host name)";
      $("addresses").textContent = (st.addresses || []).join("  ");
      $("version").textContent = "HappyMining agent " + st.version;
      renderPairing(st); renderAgent(st); renderHost(st);
      $("dot").className = "dot ok"; $("updated").textContent = "updated " + new Date().toLocaleTimeString();
      $("preflight-btn").disabled = !st.preflight_available;
    } catch (e) {
      $("dot").className = "dot bad"; $("updated").textContent = "no answer from the machine (" + e.message + ")";
    }
  }

  $("unlock-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const btn = ev.target.querySelector("button"), msg = $("unlock-msg");
    btn.disabled = true; msg.className = "msg"; msg.textContent = "Checking…";
    try {
      await api("/api/unlock", { code: $("unlock-code").value.trim() });
      msg.className = "msg ok"; msg.textContent = "Unlocked for 30 minutes.";
      $("unlock-code").value = "";
      await refresh();
      $("pair-code").focus();
    } catch (e) { msg.className = "msg bad"; msg.textContent = e.message; await refresh(); }
    btn.disabled = false;
  });

  $("pair-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const btn = ev.target.querySelector("button"), msg = $("pair-msg");
    btn.disabled = true; msg.className = "msg"; msg.textContent = "Pairing… (up to 45 s)";
    try {
      const r = await api("/api/pair", { code: $("pair-code").value.trim() });
      msg.className = "msg ok"; msg.textContent = "Paired. Device " + r.device_id + ". The agent picks the credential up within about ten seconds.";
      $("pair-code").value = "";
      await refresh();
    } catch (e) { msg.className = "msg bad"; msg.textContent = e.message; }
    btn.disabled = false;
  });

  $("lock-btn").addEventListener("click", async () => { try { await api("/api/lock", {}); } catch (e) { /* ignore */ } await refresh(); });

  $("preflight-btn").addEventListener("click", async () => {
    const btn = $("preflight-btn"), list = $("preflight-list"), sum = $("preflight-summary");
    btn.disabled = true; sum.textContent = "Running the checks… (up to two minutes)"; list.innerHTML = "";
    try {
      const rep = await api("/api/preflight");
      const s = rep.summary || {};
      sum.textContent = "Overall " + rep.overall + " — " + (s.PASS || 0) + " pass, " + (s.WARN || 0) + " warn, " + (s.FAIL || 0) + " fail, " + (s.SKIP || 0) + " skipped (" + rep.generated_at + ")";
      sum.className = "muted " + ({ PASS: "state-ok", WARN: "state-warn", FAIL: "state-bad" }[rep.overall] || "");
      (rep.checks || []).forEach((c) => {
        const li = document.createElement("li");
        const st = document.createElement("span"); st.className = "st " + c.status; st.textContent = c.status;
        const box = document.createElement("div");
        const title = document.createElement("div"); title.textContent = c.title;
        const detail = document.createElement("div"); detail.className = "detail"; detail.textContent = c.detail || "";
        box.appendChild(title); box.appendChild(detail);
        if (c.remediation && c.status !== "PASS") { const fix = document.createElement("div"); fix.className = "fix"; fix.textContent = "Fix: " + c.remediation; box.appendChild(fix); }
        li.appendChild(st); li.appendChild(box); list.appendChild(li);
      });
      $("preflight-disclaimer").textContent = rep.disclaimer || "";
    } catch (e) { sum.textContent = "Preflight could not run: " + e.message; sum.className = "muted state-bad"; }
    btn.disabled = false;
  });

  refresh();
  setInterval(refresh, REFRESH_MS);
})();

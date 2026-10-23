/*!
 * CyberFirewall Lab — interfaz
 * Copyright (c) 2026 Un Fantasma en el Sistema — Licencia MIT
 */
(function () {
  'use strict';

  const C = window.CFW;
  const $ = (id) => document.getElementById(id);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));
  const STORE_KEY = 'cfw.v2.state';
  const PREFS_KEY = 'cfw.v2.prefs';

  function esc(v) {
    return String(v === undefined || v === null ? '' : v)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  // ==========================================================================
  // ESTADO Y PERSISTENCIA (solo en este navegador)
  // ==========================================================================

  function loadState() {
    const base = C.createState();
    try {
      const raw = localStorage.getItem(STORE_KEY);
      if (raw) {
        const r = C.importConfig(base, JSON.parse(raw));
        if (r.ok) return base;
      }
    } catch (e) { /* sin almacenamiento disponible: estado por defecto */ }
    return C.createState();
  }

  function save() {
    try { localStorage.setItem(STORE_KEY, JSON.stringify(C.exportConfig(st))); } catch (e) { /* ignorar */ }
  }

  function loadPrefs() {
    try { return Object.assign({ audio: true, cli: null }, JSON.parse(localStorage.getItem(PREFS_KEY) || '{}')); } catch (e) { return { audio: true, cli: null }; }
  }

  function savePrefs() {
    try { localStorage.setItem(PREFS_KEY, JSON.stringify({ audio: ui.audio, cli: ui.cli })); } catch (e) { /* ignorar */ }
  }

  const st = loadState();
  const prefs = loadPrefs();
  const ui = {
    cli: prefs.cli || (st.engine === 'windows' ? 'powershell' : 'iptables'),
    con: 'logs', filter: 'ALL', editingId: null, tracing: false, audio: prefs.audio !== false,
    logs: [], lastResult: null,
  };

  const IFACE_LABEL = { ANY: 'cualquiera', WAN: 'eth0 · WAN', LAN: 'eth1 · LAN', DMZ: 'eth2 · DMZ' };
  const CHAIN_LABEL = {
    linux: { INPUT: 'INPUT (al firewall)', FORWARD: 'FORWARD (lo atraviesa)', OUTPUT: 'OUTPUT (sale del firewall)' },
    windows: { INPUT: 'Entrada (Inbound)', OUTPUT: 'Salida (Outbound)' },
  };
  const ACTION_LABEL = { linux: { ACCEPT: 'ACCEPT', DROP: 'DROP', REJECT: 'REJECT' }, windows: { ACCEPT: 'PERMITIR', DROP: 'BLOQUEAR', REJECT: 'BLOQUEAR' } };

  // ==========================================================================
  // UTILIDADES DE INTERFAZ
  // ==========================================================================

  let toastTimer = null;
  function toast(msg) {
    const t = $('toast');
    t.textContent = msg;
    t.classList.remove('hidden');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.add('hidden'), 3800);
  }

  let lastFocus = null;
  function openModal(id) {
    lastFocus = document.activeElement;
    const m = $(id);
    m.classList.remove('hidden');
    const f = m.querySelector('input, select, button:not([data-close])');
    if (f) f.focus();
    if (id === 'modalAudit') renderAudit();
    if (id === 'modalNmap') renderNmapTargets();
    if (id === 'modalScenarios') renderScenarios();
  }

  function closeModal(m) {
    m.classList.add('hidden');
    if (lastFocus && lastFocus.focus) lastFocus.focus();
  }

  function download(name, content, type) {
    const blob = new Blob([content], { type: type || 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  // --- sonido sintetizado (Web Audio API) ---
  let audioCtx = null;
  function beep(type) {
    if (!ui.audio) return;
    try {
      const AC = window.AudioContext || window.webkitAudioContext;
      if (!AC) return;
      if (!audioCtx) audioCtx = new AC();
      if (audioCtx.state === 'suspended') audioCtx.resume();
      const now = audioCtx.currentTime;
      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();
      osc.connect(gain); gain.connect(audioCtx.destination);
      const set = {
        accept: ['sine', 659, 880, 0.07, 0.22],
        drop: ['sine', 160, 45, 0.11, 0.2],
        reject: ['sawtooth', 320, 240, 0.07, 0.2],
        scan: ['sine', 1200, 400, 0.06, 0.15],
      }[type] || ['sine', 500, 500, 0.05, 0.1];
      osc.type = set[0];
      osc.frequency.setValueAtTime(set[1], now);
      osc.frequency.exponentialRampToValueAtTime(set[2], now + set[4] * 0.6);
      gain.gain.setValueAtTime(set[3], now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + set[4]);
      osc.start(now); osc.stop(now + set[4]);
    } catch (e) { /* sin audio */ }
  }

  // ==========================================================================
  // MOTOR Y POLÍTICAS
  // ==========================================================================

  function renderEngine() {
    const linux = st.engine === 'linux';
    $$('.engine-btn').forEach((b) => b.classList.toggle('is-active', b.dataset.engine === st.engine));
    $('headerEngineTag').textContent = linux ? 'LINUX (NETFILTER)' : 'WINDOWS DEFENDER FIREWALL';
    $('headerEngineTag').className = linux ? 'text-cyan-300 font-semibold' : 'text-blue-300 font-semibold';
    $('headerEvalMethod').textContent = linux ? 'Gana la primera coincidencia' : 'El bloqueo explícito gana';
    $('enginePedagogyText').innerHTML = linux
      ? '<strong>Linux (iptables/nftables):</strong> cada paquete recorre <em>una</em> cadena según su destino: <span class="text-cyan-300">INPUT</span> si va al firewall, <span class="text-cyan-300">FORWARD</span> si lo atraviesa y <span class="text-cyan-300">OUTPUT</span> si lo genera él. Dentro de la cadena <span class="text-amber-300 font-semibold">gana la primera regla que coincide</span>; si ninguna coincide, se aplica la política de esa cadena. El estado (NEW, ESTABLISHED…) lo calcula conntrack.'
      : '<strong>Windows Defender Firewall:</strong> el orden de la lista no importa. Si alguna regla de <span class="text-rose-300 font-semibold">bloqueo</span> coincide, gana siempre; si no, basta una de <span class="text-emerald-300 font-semibold">permiso</span>; si tampoco, se aplica la acción predeterminada de entrada o salida. Las respuestas de conexiones permitidas entran solas.';
    $('linuxPolicies').classList.toggle('hidden', !linux);
    $('linuxPolicies').classList.toggle('flex', linux);
    $('windowsPolicies').classList.toggle('hidden', linux);
    $('windowsPolicies').classList.toggle('flex', !linux);
    $('pipelineLinux').classList.toggle('hidden', !linux);
    $('pipelineWindows').classList.toggle('hidden', linux);
    $('fwNodeTitle').textContent = linux ? 'FIREWALL / ROUTER' : 'SERVIDOR WINDOWS';
    $('fwNodeTag').textContent = linux ? 'Linux · netfilter' : 'Windows Defender Firewall';
    $('btnDemoFirstMatch').classList.toggle('hidden', !linux);
    $('thChain').textContent = linux ? 'Cadena · interfaces' : 'Dirección · perfil';
    $('thState').textContent = linux ? 'Estado' : '—';
    $('rulesLegend').innerHTML = linux
      ? '<span><span class="act act-ACCEPT">ACCEPT</span> deja pasar</span><span><span class="act act-DROP">DROP</span> descarta en silencio</span><span><span class="act act-REJECT">REJECT</span> rechaza y avisa</span>'
      : '<span><span class="act act-ACCEPT">PERMITIR</span></span><span><span class="act act-DROP">BLOQUEAR</span> siempre gana</span>';
    $('rulesFooterHint').textContent = linux ? 'Usa ▲ ▼ para cambiar el orden y repite la traza.' : 'En Windows el orden de la lista no cambia nada.';
    const f = $('filterChain');
    const opts = linux ? [['ALL', 'Todas las cadenas'], ['INPUT', 'INPUT'], ['FORWARD', 'FORWARD'], ['OUTPUT', 'OUTPUT']] : [['ALL', 'Entrada y salida'], ['INPUT', 'Entrada'], ['OUTPUT', 'Salida']];
    if (!opts.some(([v]) => v === ui.filter)) ui.filter = 'ALL';
    f.innerHTML = opts.map(([v, t]) => `<option value="${v}">${t}</option>`).join('');
    f.value = ui.filter;
    renderPresets();
    renderPolicies();
  }

  function renderPolicies() {
    $$('[data-policy]').forEach((s) => { s.value = st.policies.linux[s.dataset.policy]; colorPolicy(s); });
    $$('[data-wpolicy]').forEach((s) => { s.value = st.policies.windows[s.dataset.wpolicy]; colorPolicy(s); });
    $('selectWindowsProfile').value = st.windowsProfile;
  }

  function colorPolicy(s) {
    s.classList.toggle('text-rose-300', s.value === 'DROP');
    s.classList.toggle('text-emerald-300', s.value === 'ACCEPT');
  }

  function setEngine(engine) {
    if (st.engine === engine) return;
    st.engine = engine;
    st.conntrack = [];
    ui.lastResult = null;
    if (engine === 'windows' && (ui.cli === 'iptables' || ui.cli === 'nftables')) ui.cli = 'powershell';
    if (engine === 'linux' && (ui.cli === 'powershell' || ui.cli === 'netsh')) ui.cli = 'iptables';
    save(); savePrefs();
    renderAll();
    resetVerdict();
    toast(engine === 'linux' ? 'Motor: Linux (netfilter). Conntrack vaciado.' : 'Motor: Windows Defender Firewall. Conntrack vaciado.');
  }

  // ==========================================================================
  // TABLA DE REGLAS
  // ==========================================================================

  function ruleCells(r) {
    const linux = st.engine === 'linux';
    let where;
    if (linux) {
      const ifs = [];
      if (r.inIface !== 'ANY') ifs.push(`<span class="chip chip-iface">-i ${C.IFACES[r.inIface].dev}</span>`);
      if (r.outIface !== 'ANY') ifs.push(`<span class="chip chip-iface">-o ${C.IFACES[r.outIface].dev}</span>`);
      where = `<span class="chip">${r.chain}</span> ${ifs.join(' ')}`;
    } else {
      where = `<span class="chip">${r.chain === 'INPUT' ? 'Entrada' : 'Salida'}</span> <span class="chip chip-iface">${esc(r.profile === 'Any' ? 'Todos' : r.profile)}</span>`;
    }
    const port = (p) => (p === 'ANY' ? '' : `<div class="text-slate-400 text-[10px]">puerto ${esc(p)}</div>`);
    return { where, port };
  }

  function renderRules() {
    const rules = C.rulesOf(st);
    const linux = st.engine === 'linux';
    const rel = C.analyzeRules(rules, st.engine);
    const shown = rules.filter((r) => ui.filter === 'ALL' || r.chain === ui.filter);
    $('rulesCountBadge').textContent = `${rules.length} ${rules.length === 1 ? 'regla' : 'reglas'}`;
    const body = $('rulesTableBody');
    if (!shown.length) {
      body.innerHTML = '<tr><td colspan="10" class="p-6 text-center text-slate-500 italic">No hay reglas en esta vista. Si ninguna coincide, decide la política.</td></tr>';
      return;
    }
    body.innerHTML = shown.map((r) => {
      const { where, port } = ruleCells(r);
      const pos = rules.indexOf(r);
      const a = rel[r.id];
      const flag = a ? `<span class="flag flag-${a.type}" title="${esc(flagTitle(a))}">${a.type === 'shadowed' ? 'SOMBREADA' : a.type === 'redundant' ? 'REDUNDANTE' : 'ANULADA'} por #${a.by}</span>` : '';
      return `<tr id="rule-row-${r.id}" data-id="${r.id}" class="hover:bg-slate-900/50 ${r.enabled ? '' : 'rule-off'}">
        <td class="py-2 px-2 text-center font-bold text-slate-400">
          <div class="flex items-center justify-center gap-1">
            <span title="Posición ${pos + 1}">#${r.id}</span>
            ${linux ? `<span class="flex flex-col"><button class="text-slate-400 hover:text-cyan-400 text-[10px] leading-3 p-0.5" data-move="-1" title="Subir" aria-label="Subir regla ${r.id}">▲</button><button class="text-slate-400 hover:text-cyan-400 text-[10px] leading-3 p-0.5" data-move="1" title="Bajar" aria-label="Bajar regla ${r.id}">▼</button></span>` : ''}
          </div>
        </td>
        <td class="py-2 px-2"><div class="font-semibold text-slate-200 flex items-center flex-wrap gap-1"><span>${esc(r.name)}</span>${flag}</div></td>
        <td class="py-2 px-2"><div class="flex flex-nowrap gap-1 whitespace-nowrap">${where}</div></td>
        <td class="py-2 px-2 font-bold text-cyan-300">${esc(r.protocol === 'ANY' ? 'todos' : r.protocol)}</td>
        <td class="py-2 px-2"><div class="text-amber-300 font-semibold">${esc(r.srcIp)}</div>${port(r.srcPort)}</td>
        <td class="py-2 px-2"><div class="text-emerald-300 font-semibold">${esc(r.dstIp)}</div>${port(r.dstPort)}</td>
        <td class="py-2 px-2 text-[10px] text-slate-300">${linux ? esc(r.state === 'ANY' ? '—' : r.state) : '—'}</td>
        <td class="py-2 px-2 text-center"><span class="act act-${r.action}">${ACTION_LABEL[st.engine][r.action]}</span></td>
        <td class="py-2 px-2 text-right"><span class="text-cyan-300 font-bold">${r.packets}</span> <span class="text-slate-500 text-[10px]">pkts</span><div class="text-[10px] text-slate-400">${fmtBytes(r.bytes)}</div></td>
        <td class="py-2 px-2 text-center"><div class="flex items-center justify-center gap-1">
          <button class="row-btn" data-toggle title="${r.enabled ? 'Desactivar' : 'Activar'}" aria-label="${r.enabled ? 'Desactivar' : 'Activar'} regla ${r.id}">${r.enabled ? '🟢' : '⚪'}</button>
          <button class="row-btn" data-edit title="Editar" aria-label="Editar regla ${r.id}">✎</button>
          <button class="row-btn hover:text-rose-400" data-del title="Borrar" aria-label="Borrar regla ${r.id}">🗑</button>
        </div></td>
      </tr>`;
    }).join('');
  }

  function flagTitle(a) {
    if (a.type === 'shadowed') return `La regla #${a.by} está antes y cubre todo lo que cubre esta con otra acción: esta nunca se aplicará.`;
    if (a.type === 'redundant') return `La regla #${a.by} está antes y ya hace lo mismo: esta sobra.`;
    return `La regla de bloqueo #${a.by} cubre todo este permiso y en Windows el bloqueo siempre gana.`;
  }

  function fmtBytes(b) {
    if (!b) return '0 B';
    const u = ['B', 'KB', 'MB', 'GB'];
    const i = Math.min(u.length - 1, Math.floor(Math.log(b) / Math.log(1024)));
    return `${parseFloat((b / Math.pow(1024, i)).toFixed(1))} ${u[i]}`;
  }

  function onRuleTableClick(e) {
    const btn = e.target.closest('button');
    if (!btn) return;
    const row = btn.closest('tr');
    const id = Number(row.dataset.id);
    const rules = C.rulesOf(st);
    const idx = rules.findIndex((r) => r.id === id);
    if (idx < 0) return;
    if (btn.dataset.move) {
      const to = idx + Number(btn.dataset.move);
      if (to < 0 || to >= rules.length) return;
      [rules[idx], rules[to]] = [rules[to], rules[idx]];
      toast(`Regla #${id} movida a la posición ${to + 1}. Vuelve a trazar el paquete.`);
    } else if (btn.hasAttribute('data-toggle')) {
      rules[idx].enabled = !rules[idx].enabled;
      toast(`Regla #${id} ${rules[idx].enabled ? 'activada' : 'desactivada'}`);
    } else if (btn.hasAttribute('data-edit')) {
      openRuleModal(rules[idx]);
      return;
    } else if (btn.hasAttribute('data-del')) {
      rules.splice(idx, 1);
      toast(`Regla #${id} borrada`);
    }
    save();
    renderRules();
    renderCli();
    if (btn.dataset.move) {
      const b = document.querySelector(`#rule-row-${id} [data-move="${btn.dataset.move}"]`);
      if (b) b.focus();
    }
  }

  // ==========================================================================
  // MODAL DE REGLA
  // ==========================================================================

  const TEMPLATES = {
    linux: [
      ['Respuestas (ESTABLISHED,RELATED)', { name: 'Tráfico de vuelta de conexiones aceptadas', chain: 'FORWARD', state: 'ESTABLISHED,RELATED', action: 'ACCEPT' }],
      ['Descartar INVALID', { name: 'Descartar paquetes INVALID', chain: 'FORWARD', state: 'INVALID', action: 'DROP' }],
      ['Web DMZ desde Internet', { name: 'Internet llega a la web de la DMZ', chain: 'FORWARD', inIface: 'WAN', outIface: 'DMZ', protocol: 'TCP', dstIp: '172.16.0.10', dstPort: '80,443', state: 'NEW', action: 'ACCEPT' }],
      ['SSH solo desde la LAN', { name: 'SSH de administración desde la LAN', chain: 'INPUT', inIface: 'LAN', protocol: 'TCP', srcIp: '192.168.1.0/24', dstPort: '22', state: 'NEW', action: 'ACCEPT' }],
      ['Rechazar con RST', { name: 'Rechazar TCP 8080 con RST', chain: 'INPUT', inIface: 'WAN', protocol: 'TCP', dstPort: '8080', action: 'REJECT' }],
    ],
    windows: [
      ['Permitir HTTPS', { name: 'Servidor web HTTPS', chain: 'INPUT', protocol: 'TCP', dstPort: '443', action: 'ACCEPT' }],
      ['RDP solo desde la LAN', { name: 'RDP desde la LAN', chain: 'INPUT', protocol: 'TCP', srcIp: '192.168.1.0/24', dstPort: '3389', action: 'ACCEPT' }],
      ['Bloquear SMB', { name: 'Bloquear SMB', chain: 'INPUT', protocol: 'TCP', dstPort: '445', action: 'DROP' }],
      ['Bloquear salida a un puerto', { name: 'Bloquear Telnet saliente', chain: 'OUTPUT', protocol: 'TCP', dstPort: '23', action: 'DROP' }],
    ],
  };

  function fillRuleForm(r) {
    $('ruleName').value = r.name;
    $('ruleChain').value = r.chain;
    $('ruleAction').value = st.engine === 'windows' && r.action === 'REJECT' ? 'DROP' : r.action;
    $('ruleProtocol').value = r.protocol;
    $('ruleInIface').value = r.inIface;
    $('ruleOutIface').value = r.outIface;
    $('ruleState').value = [...$('ruleState').options].some((o) => o.value === r.state) ? r.state : 'ANY';
    $('ruleSrcIp').value = r.srcIp; $('ruleSrcPort').value = r.srcPort;
    $('ruleDstIp').value = r.dstIp; $('ruleDstPort').value = r.dstPort;
    $('ruleProfile').value = r.profile;
    syncRuleForm();
  }

  function openRuleModal(rule) {
    const linux = st.engine === 'linux';
    ui.editingId = rule ? rule.id : null;
    $('modalRuleTitle').textContent = rule ? `Editar regla #${rule.id}` : 'Nueva regla';
    $('lblChain').textContent = linux ? 'Cadena' : 'Dirección';
    $('ruleChain').innerHTML = Object.entries(CHAIN_LABEL[st.engine]).map(([v, t]) => `<option value="${v}">${t}</option>`).join('');
    $('ruleAction').innerHTML = (linux ? ['ACCEPT', 'DROP', 'REJECT'] : ['ACCEPT', 'DROP']).map((a) => `<option value="${a}">${ACTION_LABEL[st.engine][a]}</option>`).join('');
    $$('.iface-select').forEach((s) => { s.innerHTML = Object.entries(IFACE_LABEL).map(([v, t]) => `<option value="${v}">${t}</option>`).join(''); });
    $$('.linux-only', $('ruleForm')).forEach((el) => el.classList.toggle('hidden', !linux));
    $$('.windows-only', $('ruleForm')).forEach((el) => el.classList.toggle('hidden', linux));
    $('ruleTemplates').innerHTML = `<span class="text-slate-400 text-[10px] uppercase mr-1">Plantillas:</span>` +
      TEMPLATES[st.engine].map(([t], i) => `<button type="button" class="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px]" data-tpl="${i}">${esc(t)}</button>`).join('');
    $('ruleErrors').classList.add('hidden');
    $$('#ruleForm .is-bad').forEach((el) => el.classList.remove('is-bad'));
    fillRuleForm(rule || C.makeRule({ name: '', chain: linux ? 'FORWARD' : 'INPUT', protocol: 'TCP', dstPort: '80', state: linux ? 'NEW' : 'ANY' }));
    openModal('modalRule');
  }

  function syncRuleForm() {
    const linux = st.engine === 'linux';
    const chain = $('ruleChain').value;
    if (linux) {
      $('ruleInIface').disabled = chain === 'OUTPUT';
      $('ruleOutIface').disabled = chain === 'INPUT';
      if (chain === 'OUTPUT') $('ruleInIface').value = 'ANY';
      if (chain === 'INPUT') $('ruleOutIface').value = 'ANY';
    }
    const portsOk = ['TCP', 'UDP'].includes($('ruleProtocol').value);
    for (const id of ['ruleSrcPort', 'ruleDstPort']) {
      $(id).disabled = !portsOk;
      if (!portsOk) $(id).value = 'ANY';
    }
    if (linux) {
      $('lblSrcIp').textContent = 'IP o red de origen (-s)';
      $('lblDstIp').textContent = 'IP o red de destino (-d)';
      $('lblSrcPort').textContent = 'Puerto de origen';
      $('lblDstPort').textContent = 'Puerto de destino';
      $('ruleHelp').innerHTML = chain === 'INPUT' ? 'INPUT: paquetes cuyo destino es una IP del propio firewall (SSH, ping, DNS del router…).'
        : chain === 'OUTPUT' ? 'OUTPUT: paquetes que genera el propio firewall.'
          : 'FORWARD: paquetes que atraviesan el firewall entre WAN, LAN y DMZ. Ojo: con DNAT, aquí ya se ve la IP interna (172.16.0.10), no la pública.';
    } else {
      const inbound = chain === 'INPUT';
      $('lblSrcIp').textContent = inbound ? 'IP remota (quien conecta)' : 'IP local (del equipo)';
      $('lblDstIp').textContent = inbound ? 'IP local (del equipo)' : 'IP remota (a dónde se conecta)';
      $('lblSrcPort').textContent = inbound ? 'Puerto remoto' : 'Puerto local';
      $('lblDstPort').textContent = inbound ? 'Puerto local' : 'Puerto remoto';
      $('ruleHelp').innerHTML = 'En Windows las reglas no tienen orden ni estado: un bloqueo que coincida gana siempre a cualquier permiso, y las respuestas de conexiones permitidas pasan sin regla.';
    }
  }

  function readRuleForm() {
    return C.makeRule({
      name: $('ruleName').value.trim(),
      chain: $('ruleChain').value,
      action: $('ruleAction').value,
      protocol: $('ruleProtocol').value,
      inIface: st.engine === 'linux' ? $('ruleInIface').value : 'ANY',
      outIface: st.engine === 'linux' ? $('ruleOutIface').value : 'ANY',
      state: st.engine === 'linux' ? $('ruleState').value : 'ANY',
      srcIp: $('ruleSrcIp').value.trim() || 'ANY', srcPort: $('ruleSrcPort').value.trim() || 'ANY',
      dstIp: $('ruleDstIp').value.trim() || 'ANY', dstPort: $('ruleDstPort').value.trim() || 'ANY',
      profile: st.engine === 'windows' ? $('ruleProfile').value : 'Any',
    });
  }

  function onRuleSubmit(e) {
    e.preventDefault();
    const r = readRuleForm();
    for (const k of ['srcIp', 'dstIp']) if (C.parseIpSpec(r[k]).any) r[k] = 'ANY';
    for (const k of ['srcPort', 'dstPort']) if (C.parsePortSpec(r[k]).any) r[k] = 'ANY';
    const errors = C.validateRule(r, st.engine);
    const fieldOf = { 'IP origen': 'ruleSrcIp', 'IP destino': 'ruleDstIp', 'Puerto origen': 'ruleSrcPort', 'Puerto destino': 'ruleDstPort', 'nombre': 'ruleName' };
    $$('#ruleForm .is-bad').forEach((el) => el.classList.remove('is-bad'));
    if (errors.length) {
      for (const err of errors) for (const [k, id] of Object.entries(fieldOf)) if (err.toLowerCase().includes(k.toLowerCase())) $(id).classList.add('is-bad');
      const box = $('ruleErrors');
      box.innerHTML = errors.map((x) => `• ${esc(x)}`).join('<br>');
      box.classList.remove('hidden');
      return;
    }
    const rules = C.rulesOf(st);
    if (ui.editingId) {
      const old = rules.find((x) => x.id === ui.editingId);
      Object.assign(old, r, { id: old.id, enabled: old.enabled, packets: old.packets, bytes: old.bytes });
      toast(`Regla #${old.id} actualizada`);
    } else {
      r.id = C.nextRuleId(rules);
      rules.push(r);
      toast(`Regla #${r.id} añadida al final${st.engine === 'linux' ? ' (súbela si debe evaluarse antes)' : ''}`);
    }
    save();
    closeModal($('modalRule'));
    renderRules();
    renderCli();
  }

  // ==========================================================================
  // PAQUETES: EJEMPLOS, FORMULARIO Y TRAZA
  // ==========================================================================

  const PRESETS = {
    linux: [
      ['LAN → web de la DMZ (SYN)', { protocol: 'TCP', flags: 'SYN', srcIp: '192.168.1.50', srcPort: 51200, dstIp: '172.16.0.10', dstPort: 80 }],
      ['LAN → web de Internet (sale con MASQUERADE)', { protocol: 'TCP', flags: 'SYN', srcIp: '192.168.1.50', srcPort: 51320, dstIp: '93.184.216.34', dstPort: 443 }],
      ['LAN → DNS público (UDP 53)', { protocol: 'UDP', srcIp: '192.168.1.50', srcPort: 53100, dstIp: '8.8.8.8', dstPort: 53 }],
      ['Internet → 203.0.113.1:443 (DNAT a la DMZ)', { protocol: 'TCP', flags: 'SYN', srcIp: '198.51.100.25', srcPort: 50500, dstIp: '203.0.113.1', dstPort: 443 }],
      ['Internet → SSH del firewall', { protocol: 'TCP', flags: 'SYN', srcIp: '198.51.100.25', srcPort: 49152, dstIp: '203.0.113.1', dstPort: 22 }],
      ['Internet → RDP de un PC de la LAN', { protocol: 'TCP', flags: 'SYN', srcIp: '198.51.100.25', srcPort: 60123, dstIp: '192.168.1.50', dstPort: 3389 }],
      ['DMZ comprometida → SMB de la LAN', { protocol: 'TCP', flags: 'SYN', srcIp: '172.16.0.10', srcPort: 38192, dstIp: '192.168.1.50', dstPort: 445 }],
      ['Ping de la LAN al firewall', { protocol: 'ICMP', icmpType: 8, srcIp: '192.168.1.50', dstIp: '192.168.1.1' }],
      ['El firewall consulta DNS (OUTPUT)', { protocol: 'UDP', srcIp: '203.0.113.1', srcPort: 40000, dstIp: '8.8.8.8', dstPort: 53 }],
      ['ACK suelto desde Internet (sondeo -sA)', { protocol: 'TCP', flags: 'ACK', srcIp: '198.51.100.99', srcPort: 41000, dstIp: '203.0.113.1', dstPort: 22 }],
      ['SYN+ACK sin conexión previa (INVALID)', { protocol: 'TCP', flags: 'SYN,ACK', srcIp: '93.184.216.34', srcPort: 443, dstIp: '192.168.1.50', dstPort: 51999 }],
      ['IP de la LAN entrando por la WAN (spoofing)', { protocol: 'TCP', flags: 'SYN', srcIp: '192.168.1.50', srcPort: 1234, dstIp: '172.16.0.10', dstPort: 22, inIface: 'WAN' }],
    ],
    windows: [
      ['Internet → HTTPS del servidor', { protocol: 'TCP', flags: 'SYN', srcIp: '198.51.100.25', srcPort: 50500, dstIp: '203.0.113.1', dstPort: 443 }],
      ['Internet → SMB (445)', { protocol: 'TCP', flags: 'SYN', srcIp: '198.51.100.25', srcPort: 50501, dstIp: '203.0.113.1', dstPort: 445 }],
      ['Internet → RDP (3389)', { protocol: 'TCP', flags: 'SYN', srcIp: '198.51.100.25', srcPort: 50503, dstIp: '203.0.113.1', dstPort: 3389 }],
      ['LAN → RDP (3389)', { protocol: 'TCP', flags: 'SYN', srcIp: '192.168.1.50', srcPort: 50502, dstIp: '192.168.1.1', dstPort: 3389 }],
      ['Ping desde la LAN', { protocol: 'ICMP', icmpType: 8, srcIp: '192.168.1.50', dstIp: '192.168.1.1' }],
      ['El servidor abre Telnet hacia fuera', { protocol: 'TCP', flags: 'SYN', srcIp: '203.0.113.1', srcPort: 50504, dstIp: '93.184.216.34', dstPort: 23 }],
      ['El servidor navega (HTTPS saliente)', { protocol: 'TCP', flags: 'SYN', srcIp: '203.0.113.1', srcPort: 50505, dstIp: '93.184.216.34', dstPort: 443 }],
      ['Tráfico que solo atraviesa el equipo', { protocol: 'TCP', flags: 'SYN', srcIp: '192.168.1.50', srcPort: 50506, dstIp: '172.16.0.10', dstPort: 80 }],
    ],
  };

  function renderPresets() {
    $('selectPacketPreset').innerHTML = '<option value="">Paquetes de ejemplo…</option>' +
      PRESETS[st.engine].map(([t], i) => `<option value="${i}">${esc(t)}</option>`).join('');
  }

  function fillPacketForm(p) {
    $('pktProtocol').value = p.protocol;
    if (p.flags) $('pktFlags').value = p.flags;
    if (p.icmpType !== undefined) $('pktIcmpType').value = String(p.icmpType);
    $('pktSrcIp').value = p.srcIp;
    $('pktDstIp').value = p.dstIp;
    $('pktSrcPort').value = p.srcPort || '';
    $('pktDstPort').value = p.dstPort || '';
    $('pktInIface').value = p.inIface || 'AUTO';
    $('pktState').value = 'AUTO';
    syncPacketForm();
  }

  function syncPacketForm() {
    const proto = $('pktProtocol').value;
    const icmp = proto === 'ICMP';
    $('flagsWrap').classList.toggle('hidden', proto !== 'TCP');
    $('icmpWrap').classList.toggle('hidden', !icmp);
    $$('.port-field').forEach((f) => { f.disabled = icmp; if (icmp) f.value = ''; });
  }

  function readPacketForm() {
    const proto = $('pktProtocol').value;
    const p = {
      protocol: proto, srcIp: $('pktSrcIp').value.trim(), dstIp: $('pktDstIp').value.trim(),
      inIface: $('pktInIface').value, stateOverride: $('pktState').value,
    };
    if (proto !== 'ICMP') { p.srcPort = $('pktSrcPort').value.trim(); p.dstPort = $('pktDstPort').value.trim(); }
    if (proto === 'TCP') p.flags = $('pktFlags').value;
    if (proto === 'ICMP') { p.icmpType = Number($('pktIcmpType').value); p.icmpId = 0x1c2b; }
    return p;
  }

  function clearHighlights() {
    $$('#rulesTableBody tr').forEach((r) => r.classList.remove('rule-evaluating', 'rule-matched-accept', 'rule-matched-drop', 'rule-matched-reject', 'rule-skipped'));
  }

  function highlightResult(res) {
    for (const s of res.steps) {
      const row = $(`rule-row-${s.ruleId}`);
      if (!row) continue;
      if (res.matchedRule && s.ruleId === res.matchedRule.id) row.classList.add(`rule-matched-${res.matchedRule.action === 'ACCEPT' ? 'accept' : res.matchedRule.action === 'DROP' ? 'drop' : 'reject'}`);
      else row.classList.add('rule-skipped');
    }
  }

  function trace(instant) {
    if (ui.tracing) return;
    const input = readPacketForm();
    const res = C.processPacket(st, input);
    const errBox = $('packetErrors');
    if (res.errors) {
      errBox.innerHTML = res.errors.map((x) => `• ${esc(x)}`).join('<br>');
      errBox.classList.remove('hidden');
      return;
    }
    errBox.classList.add('hidden');
    ui.lastResult = res;
    save();
    clearHighlights();
    const finish = () => {
      ui.tracing = false;
      $('btnTrace').disabled = false;
      $('traceStatus').textContent = '✓ Traza completada';
      renderRules();
      highlightResult(res);
      showVerdict(res);
      addLog(res);
      renderConntrack();
      renderNat();
      renderTopology(res);
      renderDissector(res);
      beep(res.notApplicable ? 'scan' : res.action.toLowerCase());
    };
    if (instant || res.notApplicable) { finish(); return; }
    ui.tracing = true;
    $('btnTrace').disabled = true;
    $('traceStatus').textContent = `Evaluando ${st.engine === 'linux' ? 'la cadena ' + res.chain : 'las reglas'}…`;
    const order = res.steps.filter((s) => !s.skipped || (res.matchedRule && s.ruleId === res.matchedRule.id));
    const others = res.steps.filter((s) => !order.includes(s));
    others.forEach((s) => { const row = $(`rule-row-${s.ruleId}`); if (row) row.classList.add('rule-skipped'); });
    let i = 0;
    const timer = setInterval(() => {
      if (i >= order.length) { clearInterval(timer); finish(); return; }
      const s = order[i++];
      const row = $(`rule-row-${s.ruleId}`);
      if (row) {
        row.classList.add('rule-evaluating');
        setTimeout(() => {
          row.classList.remove('rule-evaluating');
          if (!(res.matchedRule && s.ruleId === res.matchedRule.id)) row.classList.add('rule-skipped');
        }, 200);
      }
    }, 260);
  }

  function resetVerdict() {
    $('verdictBox').className = 'verdict verdict-idle';
    $('verdictTitle').textContent = 'ESPERANDO PAQUETE';
    $('verdictSubtitle').textContent = 'Elige un paquete de ejemplo o rellena el formulario y pulsa «Trazar paquete».';
    $('verdictDetails').innerHTML = '<span class="text-slate-400">Aquí verás la interfaz de entrada, la cadena, el estado conntrack, el NAT aplicado y por qué cada regla coincide o no.</span>';
    $('topologyPacketInfo').textContent = 'Listo para inyectar tráfico';
    clearTopology();
  }

  function showVerdict(res) {
    const box = $('verdictBox');
    const linux = res.engine === 'linux';
    let cls, title, sub;
    if (res.notApplicable) {
      cls = 'verdict-na'; title = 'NO LO EVALÚA';
      sub = 'Tráfico enrutado: Windows Defender Firewall solo filtra lo que entra o sale del propio equipo.';
    } else if (res.action === 'ACCEPT') {
      cls = 'verdict-accept'; title = linux ? 'ACEPTADO (ACCEPT)' : 'PERMITIDO';
      sub = res.decidedBy === 'stateful' ? 'Respuesta de una conexión ya permitida' : res.matchedRule ? `Regla #${res.matchedRule.id} · ${res.matchedRule.name}` : `Política ${res.chain} (${res.policy})`;
    } else if (res.action === 'DROP') {
      cls = 'verdict-drop'; title = linux ? 'DESCARTADO (DROP)' : 'BLOQUEADO';
      sub = res.matchedRule ? `Regla #${res.matchedRule.id} · ${res.matchedRule.name}` : (linux ? `Política de ${res.chain}: DROP` : 'Acción predeterminada: bloquear');
    } else {
      cls = 'verdict-reject'; title = 'RECHAZADO (REJECT)';
      sub = `Regla #${res.matchedRule.id} · responde con ${res.response === 'tcp-reset' ? 'TCP RST' : 'ICMP port-unreachable'}`;
    }
    box.className = `verdict ${cls}`;
    $('verdictTitle').textContent = title;
    $('verdictSubtitle').textContent = sub;
    $('verdictSubtitle').className = 'text-xs text-slate-300 mt-1';

    const p = res.pkt;
    const ep = (ip, port) => `${ip}${p.protocol === 'ICMP' ? '' : ':' + port}`;
    const lines = [];
    const route = res.chain === 'INPUT' ? `${devOf(res.inIface)} → <b>INPUT</b> → proceso local`
      : res.chain === 'OUTPUT' ? `proceso local → <b>OUTPUT</b> → ${devOf(res.outIface)}`
        : `${devOf(res.inIface)} → <b>FORWARD</b> → ${devOf(res.outIface)}`;
    lines.push(`<div><span class="text-slate-500">Paquete:</span> ${esc(p.protocol)} ${esc(ep(p.srcIp, p.srcPort))} → ${esc(ep(p.dstIp, p.dstPort))}${p.flags ? ' [' + esc(p.flags) + ']' : ''}${p.protocol === 'ICMP' ? ' tipo ' + p.icmpType : ''}</div>`);
    lines.push(`<div><span class="text-slate-500">Ruta:</span> ${route}</div>`);
    lines.push(`<div><span class="text-slate-500">conntrack:</span> <span class="text-amber-300 font-bold">${esc(res.ctstate)}</span> — ${esc(res.ctWhy)}</div>`);
    if (res.preNat) lines.push(`<div class="text-amber-300">PREROUTING ${esc(res.preNat.type)}: ${esc(res.preNat.from)} → ${esc(res.preNat.to)}</div>`);
    if (res.postNat) lines.push(`<div class="text-amber-300">POSTROUTING ${esc(res.postNat.type)}: ${esc(res.postNat.from)} → ${esc(res.postNat.to)}${res.postNat.portChanged ? ' (puerto cambiado: ya estaba en uso → PAT)' : ''}</div>`);
    lines.push(`<p class="text-cyan-200 font-semibold pt-1">${esc(res.explanation)}</p>`);
    if (res.response !== 'none') lines.push(`<div class="text-amber-200">El firewall contesta al origen con ${res.response === 'tcp-reset' ? 'un TCP RST (parece un puerto cerrado)' : 'un ICMP port-unreachable'}.</div>`);
    const rules = C.rulesOf(st);
    const evaluated = res.steps.filter((s) => !s.skipped || (res.matchedRule && s.ruleId === res.matchedRule.id));
    if (evaluated.length) {
      lines.push('<div class="pt-1 border-t border-slate-800 text-[10px] text-slate-400 space-y-0.5">' + evaluated.map((s) => {
        const r = rules.find((x) => x.id === s.ruleId);
        const win = res.matchedRule && s.ruleId === res.matchedRule.id;
        return `<div>${win ? '<span class="ok">✔</span>' : (s.matched ? '<span class="text-amber-300">✔</span>' : '<span class="ko">✘</span>')} #${s.ruleId} ${esc(r ? r.name : '')}: ${esc(s.why)}${win ? ` → <b>${ACTION_LABEL[st.engine][res.action]}</b>` : ''}</div>`;
      }).join('') + '</div>');
    }
    for (const n of res.notes) lines.push(`<div class="note note-${n.level}">${esc(n.text)}</div>`);
    $('verdictDetails').innerHTML = lines.join('');
  }

  function devOf(z) { return z ? `${C.IFACES[z].dev} (${z})` : '—'; }

  function prepareReturn() {
    const res = ui.lastResult;
    if (!res) { toast('Primero traza un paquete: la respuesta se construye a partir de él.'); return; }
    const p = res.pkt;
    let kind = 'ack';
    if (p.protocol === 'TCP' && C.parseTcpFlags(p.flags).has('SYN') && !C.parseTcpFlags(p.flags).has('ACK')) kind = 'syn-ack';
    if (p.protocol === 'UDP') kind = 'udp';
    if (p.protocol === 'ICMP') kind = 'echo';
    const r = C.responseFor(st, res, kind);
    fillPacketForm(Object.assign({}, r, { flags: r.flags && p.protocol === 'TCP' ? r.flags : undefined }));
    const nat = res.postNat ? ` Va a ${r.dstIp}${r.dstPort ? ':' + r.dstPort : ''}: la IP traducida; conntrack la devolverá a ${p.srcIp}.` : '';
    toast(res.action === 'ACCEPT' ? `Respuesta preparada.${nat} Trázala.` : 'Ojo: el paquete original no pasó, así que esta «respuesta» no existiría en la realidad (conntrack la verá como INVALID o NEW).');
  }

  // ==========================================================================
  // TOPOLOGÍA Y DISECCIÓN
  // ==========================================================================

  function clearTopology() {
    $$('.topo-node').forEach((n) => n.classList.remove('is-src', 'is-dst', 'v-accept', 'v-drop', 'v-reject'));
    $$('.hook').forEach((h) => h.classList.remove('is-on', 'is-nat', 'v-accept', 'v-drop', 'v-reject'));
  }

  function renderTopology(res) {
    clearTopology();
    const v = res.notApplicable ? '' : `v-${res.action === 'ACCEPT' ? 'accept' : res.action === 'DROP' ? 'drop' : 'reject'}`;
    const nodeFor = (ip) => (C.isFirewallIp(ip) ? 'nodeFW' : `node${C.zoneOf(ip)}`);
    const src = res.chain === 'OUTPUT' ? 'nodeFW' : `node${res.inIface}`;
    $(src).classList.add('is-src');
    const dst = nodeFor(res.after.dstIp);
    if (dst !== src) $(dst).classList.add('is-dst');
    if (v) $('nodeFW').classList.add(v);
    if (res.engine === 'linux') {
      for (const h of res.hooks) { const el = $(`hook${h}`); if (el) el.classList.add('is-on'); }
      const ch = $(`hook${res.chain}`);
      if (ch && v) { ch.classList.remove('is-on'); ch.classList.add(v); }
      if (res.preNat) $('hookPREROUTING').classList.add('is-nat');
      if (res.postNat) $('hookPOSTROUTING').classList.add('is-nat');
    }
    const p = res.pkt;
    $('topologyPacketInfo').textContent = `${p.srcIp} → ${res.after.dstIp}${p.protocol === 'ICMP' ? '' : ':' + res.after.dstPort} · ${res.engine === 'linux' ? res.chain : (res.chain === 'INPUT' ? 'entrada' : res.chain === 'OUTPUT' ? 'salida' : 'enrutado')} · ${res.notApplicable ? 'no evaluado' : res.action}`;
  }

  function hex(n, w) { return '0x' + n.toString(16).padStart(w, '0'); }

  function renderDissector(res) {
    const f = res.frame, p = res.pkt;
    const rows = [];
    const sec = (title, cls, items) => rows.push(`<div class="border-b border-slate-800/80 pb-1"><span class="${cls} font-bold uppercase">${title}</span><div class="grid grid-cols-1 sm:grid-cols-2 gap-x-3 gap-y-0.5 text-slate-300 mt-0.5">${items.map((i) => `<div>${esc(i)}</div>`).join('')}</div></div>`);
    sec(`Ethernet II (${res.chain === 'OUTPUT' ? 'sale por' : 'llega a'} ${f.dev})`, 'text-cyan-400', [`Destino: ${f.dstMac}`, `Origen: ${f.srcMac}`, 'Tipo: IPv4 (0x0800)']);
    sec('IPv4', 'text-emerald-400', [`Versión 4 · cabecera 20 bytes`, `Longitud total: ${f.ipLen}`, `Identificación: ${hex(f.ipId, 4)} · Flags: DF`, `TTL: ${f.ttl}${res.chain === 'FORWARD' ? ' (al reenviarlo bajará a ' + (f.ttl - 1) + ')' : ''}`, `Protocolo: ${f.protoNum} (${p.protocol})`, `Checksum: ${hex(f.ipSum, 4)} (correcto)`, `Origen: ${p.srcIp}`, `Destino: ${p.dstIp}`]);
    if (f.tcp) sec('TCP', 'text-amber-400', [`Puertos: ${p.srcPort} → ${p.dstPort}`, `Flags: ${f.tcp.flags}`, `Seq: ${f.tcp.seq}`, `Ack: ${f.tcp.ack}`, `Cabecera: ${f.tcp.hl} bytes${f.tcp.hl > 20 ? ' (MSS 1460, SACK, timestamps, window scale 7)' : ''}`, `Ventana: ${f.tcp.win}`, `Checksum: ${hex(f.l4sum, 4)} (correcto)`]);
    if (f.udp) sec('UDP', 'text-amber-400', [`Puertos: ${p.srcPort} → ${p.dstPort}`, `Longitud: ${f.udp.len}`, `Checksum: ${hex(f.l4sum, 4)} (correcto)`, f.udp.dns ? 'Datos: consulta DNS A unfantasmaenelsistema.com' : 'Datos: vacío']);
    if (f.icmp) sec('ICMP', 'text-amber-400', [`Tipo ${f.icmp.type} · código ${f.icmp.code}${f.icmp.type === 8 ? ' (echo request)' : f.icmp.type === 0 ? ' (echo reply)' : ''}`, `Checksum: ${hex(f.l4sum, 4)} (correcto)`, f.icmp.id !== null ? `Id: ${f.icmp.id} · Seq: ${f.icmp.seq}` : '', f.icmp.id !== null ? 'Datos: 56 bytes (como ping de Linux)' : '']);
    rows.push(`<div><span class="text-slate-400 font-bold uppercase">Bytes (${f.bytes.length})</span><pre class="mt-1 text-[10px] text-cyan-300/90 leading-tight bg-[#05080f] p-2 rounded border border-slate-800/80 overflow-x-auto">${esc(C.hexdump(f.bytes))}</pre></div>`);
    $('dissectorBody').innerHTML = rows.join('');
  }

  // ==========================================================================
  // CONSOLA: REGISTROS, CONNTRACK Y NAT
  // ==========================================================================

  function addLog(res) {
    if (res.notApplicable) return;
    const text = res.engine === 'linux' ? C.iptablesLogLine(res) : C.pfirewallLogLine(res);
    ui.logs.unshift({ text, action: res.action });
    if (ui.logs.length > 120) ui.logs.pop();
    renderLogs();
  }

  function renderLogs() {
    const panel = $('panelLogs');
    if (!ui.logs.length) {
      panel.innerHTML = '<div class="text-slate-500 italic">Sin registros todavía. Cada paquete trazado aparece aquí en el formato real: el de una regla LOG de iptables (journalctl -k) o el de pfirewall.log en Windows.</div>';
      return;
    }
    const color = { ACCEPT: 'text-emerald-300', DROP: 'text-rose-300', REJECT: 'text-amber-300' };
    panel.innerHTML = ui.logs.map((l) => `<div class="${color[l.action]} break-all">${esc(l.text)}</div>`).join('');
  }

  function tupleText(t, proto) {
    return proto === 'ICMP' ? `${t.src} → ${t.dst} id=${t.sport}` : `${t.src}:${t.sport} → ${t.dst}:${t.dport}`;
  }

  function renderConntrack() {
    $('ctBadge').textContent = st.conntrack.length;
    const body = $('ctBody');
    if (!st.conntrack.length) {
      body.innerHTML = '<tr><td colspan="6" class="p-3 text-center text-slate-500 italic">Tabla vacía. Cuando el firewall acepta el primer paquete de una conexión, conntrack la apunta aquí y reconoce su respuesta como ESTABLISHED.</td></tr>';
      return;
    }
    body.innerHTML = st.conntrack.map((c) => `<tr>
      <td class="p-1.5 text-slate-500">${c.id}</td>
      <td class="p-1.5 text-cyan-300 font-bold">${esc(c.proto)}</td>
      <td class="p-1.5"><span class="px-1.5 py-0.5 rounded text-[10px] font-bold ${c.seenReply ? 'bg-emerald-950 text-emerald-300' : 'bg-amber-950 text-amber-300'}">${c.seenReply ? 'ASSURED' : 'UNREPLIED'}</span></td>
      <td class="p-1.5 text-slate-300">${esc(tupleText(c.orig, c.proto))}</td>
      <td class="p-1.5 text-slate-400">${esc(tupleText(c.reply, c.proto))}${c.snat ? ' <span class="text-amber-300">[SNAT]</span>' : ''}${c.dnat ? ' <span class="text-amber-300">[DNAT]</span>' : ''}</td>
      <td class="p-1.5 text-amber-300">${c.timeout}s</td>
    </tr>`).join('');
  }

  function renderNat() {
    $('chkMasq').checked = st.nat.masquerade;
    const active = st.conntrack.filter((c) => c.snat || c.dnat);
    $('natBadge').textContent = active.length;
    const linux = st.engine === 'linux';
    $('panelNat').classList.toggle('opacity-50', !linux);
    $('dnatBody').innerHTML = st.nat.dnat.length ? st.nat.dnat.map((d) => `<tr data-id="${d.id}">
      <td class="p-1"><input type="checkbox" ${d.enabled ? 'checked' : ''} data-dnat-toggle class="accent-amber-500" aria-label="Activar redirección ${d.port}"></td>
      <td class="p-1 text-cyan-300">${esc(d.proto)}</td>
      <td class="p-1">203.0.113.1:${esc(d.port)}</td>
      <td class="p-1 text-emerald-300">${esc(d.toIp)}:${esc(d.toPort)}</td>
      <td class="p-1 text-right"><button class="px-2 py-0.5 rounded bg-slate-800 hover:bg-rose-950 text-slate-400 hover:text-rose-300 text-[10px]" data-dnat-del>Quitar</button></td>
    </tr>`).join('') : '<tr><td colspan="5" class="p-2 text-slate-500 italic">Sin redirecciones: desde Internet solo se llega al propio firewall.</td></tr>';
    $('natActive').innerHTML = active.length ? active.map((c) => {
      if (c.snat) return `<div><span class="text-amber-300">MASQUERADE</span> ${esc(c.orig.src)}${c.proto === 'ICMP' ? '' : ':' + esc(c.orig.sport)} ➔ <span class="text-emerald-300">${esc(c.reply.dst)}${c.proto === 'ICMP' ? '' : ':' + esc(c.reply.dport)}</span> · destino ${esc(c.orig.dst)}${c.proto === 'ICMP' ? '' : ':' + esc(c.orig.dport)} <span class="text-slate-500">(#${c.id})</span></div>`;
      return `<div><span class="text-amber-300">DNAT</span> ${esc(c.orig.src)}:${esc(c.orig.sport)} ➔ ${esc(c.orig.dst)}:${esc(c.orig.dport)} ➔ <span class="text-emerald-300">${esc(c.reply.src)}:${esc(c.reply.sport)}</span> <span class="text-slate-500">(#${c.id})</span></div>`;
    }).join('') : `<div class="text-slate-500 italic">${linux ? 'Ninguna. Traza «LAN → web de Internet» o «Internet → 203.0.113.1:443».' : 'El NAT no se aplica en modo Windows.'}</div>`;
  }

  function setConsoleTab(tab) {
    ui.con = tab;
    $$('.con-tab').forEach((b) => { const on = b.dataset.con === tab; b.classList.toggle('is-active', on); b.setAttribute('aria-selected', String(on)); });
    $('panelLogs').classList.toggle('hidden', tab !== 'logs');
    $('panelConntrack').classList.toggle('hidden', tab !== 'conntrack');
    $('panelNat').classList.toggle('hidden', tab !== 'nat');
    $('btnClearConsole').textContent = tab === 'logs' ? 'Vaciar' : tab === 'conntrack' ? 'conntrack -F' : 'Vaciar traducciones';
    $('consoleFooter').textContent = tab === 'logs'
      ? (st.engine === 'linux' ? 'Formato del kernel (regla LOG con --log-prefix). TTL en FORWARD ya decrementado.' : 'Formato de %systemroot%\\system32\\LogFiles\\Firewall\\pfirewall.log')
      : tab === 'conntrack' ? 'Equivale a «conntrack -L». UNREPLIED: aún sin respuesta; ASSURED: vista en los dos sentidos.'
        : 'Las traducciones viven en conntrack: al vaciarlo, desaparecen.';
  }

  function onDnatSubmit(e) {
    e.preventDefault();
    const d = { proto: $('dnatProto').value, port: Number($('dnatPort').value), toIp: $('dnatToIp').value.trim(), toPort: Number($('dnatToPort').value || $('dnatPort').value), enabled: true };
    const errs = C.validateDnat(d);
    if (st.nat.dnat.some((x) => x.proto === d.proto && x.port === d.port)) errs.push(`ya hay una redirección para ${d.proto}/${d.port}`);
    const box = $('dnatErrors');
    if (errs.length) { box.textContent = 'Revisa: ' + errs.join(', '); box.classList.remove('hidden'); return; }
    box.classList.add('hidden');
    d.id = st.nat.dnat.reduce((m, x) => Math.max(m, x.id), 0) + 1;
    st.nat.dnat.push(d);
    $('dnatForm').reset();
    save(); renderNat(); renderCli();
    toast(`DNAT añadido: 203.0.113.1:${d.port} → ${d.toIp}:${d.toPort}. Recuerda permitirlo en FORWARD.`);
  }

  function onDnatClick(e) {
    const row = e.target.closest('tr[data-id]');
    if (!row) return;
    const id = Number(row.dataset.id);
    if (e.target.matches('[data-dnat-toggle]')) {
      const d = st.nat.dnat.find((x) => x.id === id);
      d.enabled = e.target.checked;
    } else if (e.target.matches('[data-dnat-del]')) {
      st.nat.dnat = st.nat.dnat.filter((x) => x.id !== id);
    } else return;
    save(); renderNat(); renderCli();
  }

  function noise() {
    const list = PRESETS[st.engine];
    const [, p] = list[Math.floor(Math.random() * list.length)];
    const input = Object.assign({}, p);
    if (input.srcPort) input.srcPort = 30000 + Math.floor(Math.random() * 30000);
    if (input.protocol === 'ICMP') input.icmpId = Math.floor(Math.random() * 65535);
    const res = C.processPacket(st, input);
    if (res.errors) return;
    addLog(res);
    renderConntrack(); renderNat(); renderRules();
    save();
    toast('Paquete de fondo procesado y registrado');
  }

  // ==========================================================================
  // CLI
  // ==========================================================================

  function renderCli() {
    $$('.cli-tab').forEach((b) => { const on = b.dataset.cli === ui.cli; b.classList.toggle('is-active', on); b.setAttribute('aria-selected', String(on)); });
    const gen = { iptables: C.genIptables, nftables: C.genNftables, powershell: C.genPowerShell, netsh: C.genNetsh }[ui.cli];
    $('cliOutput').textContent = gen(st);
    const linuxCli = ui.cli === 'iptables' || ui.cli === 'nftables';
    $('cliDescription').textContent = linuxCli
      ? `Reglas de la pestaña Linux${st.engine === 'windows' ? ' (ahora estás en Windows: cambia de motor para editarlas)' : ''}, con políticas, NAT y loopback. Probado en Kali con iptables-nft 1.8 y nft 1.1.`
      : `Reglas de la pestaña Windows${st.engine === 'linux' ? ' (ahora estás en Linux: cambia de motor para editarlas)' : ''}. Local/remoto se deducen de la dirección de cada regla.`;
  }

  function copyCli() {
    const text = $('cliOutput').textContent;
    const done = () => toast('Copiado al portapapeles');
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done, () => toast('No se pudo copiar: selecciona el texto a mano'));
    else toast('Tu navegador no permite copiar aquí: selecciona el texto a mano');
  }

  // ==========================================================================
  // RETOS
  // ==========================================================================

  function renderScenarios() {
    $('scenarioList').innerHTML = C.SCENARIOS.map((s) => `<div class="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-2" data-sc="${s.id}">
      <div class="flex items-center justify-between gap-2 flex-wrap">
        <div class="flex items-center gap-2"><span class="px-1.5 py-0.5 rounded bg-amber-500/10 border border-amber-500/40 text-amber-300 font-mono text-[10px] font-bold">RETO ${s.id}</span><h4 class="font-bold text-white">${esc(s.title)}</h4></div>
        <span class="text-[10px] text-slate-400">${esc(s.level)}</span>
      </div>
      <p class="text-slate-300 leading-relaxed">${esc(s.goal)}</p>
      <div class="flex gap-2 flex-wrap">
        <button class="px-3 py-1 rounded bg-cyan-700 hover:bg-cyan-600 text-white font-semibold" data-sc-load>Cargar reto</button>
        <button class="px-3 py-1 rounded bg-emerald-700 hover:bg-emerald-600 text-white font-semibold" data-sc-check>Comprobar</button>
        <button class="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300" data-sc-hint>Pista</button>
      </div>
      <p class="hidden text-[11px] text-amber-200" data-sc-hinttext>💡 ${esc(s.hint)}</p>
      <div class="hidden space-y-1" data-sc-result></div>
    </div>`).join('');
  }

  function onScenarioClick(e) {
    const card = e.target.closest('[data-sc]');
    if (!card) return;
    const sc = C.SCENARIOS.find((s) => s.id === Number(card.dataset.sc));
    if (e.target.matches('[data-sc-load]')) {
      sc.load(st);
      ui.lastResult = null;
      save(); renderAll(); resetVerdict();
      closeModal($('modalScenarios'));
      if (sc.id === 2) fillPacketForm(PRESETS.linux[3][1]);
      toast(`Reto ${sc.id} cargado. Corrige las reglas y vuelve a «Retos → Comprobar».`);
    } else if (e.target.matches('[data-sc-hint]')) {
      card.querySelector('[data-sc-hinttext]').classList.toggle('hidden');
    } else if (e.target.matches('[data-sc-check]')) {
      const res = sc.verify(st);
      const all = res.every((t) => t.ok);
      const box = card.querySelector('[data-sc-result]');
      box.innerHTML = `<div class="font-bold ${all ? 'ok' : 'ko'}">${all ? '✔ ¡Reto superado!' : '✘ Todavía no: revisa lo que falla'}</div>` +
        res.map((t) => `<div class="text-[11px]"><span class="${t.ok ? 'ok' : 'ko'}">${t.ok ? '✔' : '✘'}</span> ${esc(t.name)} <span class="text-slate-400">— ${esc(t.detail)}</span></div>`).join('');
      box.classList.remove('hidden');
      beep(all ? 'accept' : 'drop');
    }
  }

  // ==========================================================================
  // CIDR, EXPORTAR, NMAP Y AUDITORÍA
  // ==========================================================================

  function onCidrSubmit(e) {
    e.preventDefault();
    const net = C.parseIpSpec($('cidrNet').value.trim());
    const ip = C.ipToInt($('cidrIp').value.trim());
    const out = $('cidrResult');
    if (net.error || net.any) { out.innerHTML = `<span class="ko">${esc(net.error || 'Escribe una red concreta, p. ej. 10.0.0.0/8')}</span>`; return; }
    if (ip === null) { out.innerHTML = '<span class="ko">La IP a comprobar no es válida</span>'; return; }
    const mask = net.bits === 0 ? 0 : (0xffffffff << (32 - net.bits)) >>> 0;
    const and = (ip & mask) >>> 0;
    const bin = (n) => (n >>> 0).toString(2).padStart(32, '0').match(/.{8}/g).join('.');
    const ok = and === net.first;
    out.innerHTML = `<div class="font-bold ${ok ? 'ok' : 'ko'} mb-1">${ok ? '✔ La IP pertenece a la red' : '✘ La IP está fuera de la red'}</div>
      <div class="text-slate-400">IP       <span class="text-cyan-300">${bin(ip)}</span> ${esc(C.intToIp(ip))}</div>
      <div class="text-slate-400">Máscara  <span class="text-amber-300">${bin(mask)}</span> ${esc(C.intToIp(mask))} (/${net.bits})</div>
      <div class="text-slate-400">IP AND m <span class="text-emerald-300">${bin(and)}</span> ${esc(C.intToIp(and))}</div>
      <div class="text-slate-400">Red      <span class="text-emerald-300">${bin(net.first)}</span> ${esc(net.net)}</div>
      <div class="text-slate-400 mt-1">Rango: ${esc(C.intToIp(net.first))} – ${esc(C.intToIp(net.last))} (${(net.last - net.first + 1).toLocaleString('es-ES')} direcciones)${net.aligned ? '' : ' · ojo: la red escrita no estaba alineada y el firewall la recorta a ' + esc(net.net + '/' + net.bits)}</div>`;
  }

  function onExport(kind) {
    const map = {
      sh: ['cyberfirewall-iptables.sh', C.genIptables(st)],
      nft: ['cyberfirewall.nft', C.genNftables(st)],
      ps1: ['cyberfirewall-windows.ps1', '﻿' + C.genPowerShell(st)],
      cmd: ['cyberfirewall-netsh.cmd', C.genNetsh(st).replace(/\n/g, '\r\n')],
      json: ['cyberfirewall-config.json', JSON.stringify(C.exportConfig(st), null, 2)],
    };
    const [name, content] = map[kind];
    download(name, content, kind === 'json' ? 'application/json' : 'text/plain;charset=utf-8');
    toast(`Descargado ${name}`);
  }

  function onImport(e) {
    const file = e.target.files[0];
    if (!file) return;
    const box = $('importResult');
    const show = (ok, html) => { box.className = `p-2 rounded border text-[11px] ${ok ? 'border-emerald-700 bg-emerald-950/40 text-emerald-200' : 'border-rose-700 bg-rose-950/40 text-rose-200'}`; box.innerHTML = html; };
    if (file.size > 512 * 1024) { show(false, 'El archivo es demasiado grande (máximo 512 KB).'); return; }
    const reader = new FileReader();
    reader.onload = () => {
      let data;
      try { data = JSON.parse(reader.result); } catch (err) { show(false, 'No es un JSON válido.'); return; }
      const r = C.importConfig(st, data);
      if (!r.ok) { show(false, '<b>No se ha importado nada:</b><br>' + r.errors.slice(0, 12).map((x) => '• ' + esc(x)).join('<br>')); return; }
      ui.lastResult = null;
      save(); renderAll(); resetVerdict();
      show(true, '✔ Configuración restaurada.' + r.warnings.map((w) => '<br>' + esc(w)).join(''));
    };
    reader.readAsText(file);
    e.target.value = '';
  }

  function renderNmapTargets() {
    const t = st.engine === 'linux'
      ? [['203.0.113.1', '203.0.113.1 · IP pública del firewall'], ['192.168.1.1', '192.168.1.1 · firewall (lado LAN)'], ['172.16.0.10', '172.16.0.10 · srv-web (DMZ)'], ['192.168.1.50', '192.168.1.50 · pc-50 (LAN)']]
      : [['203.0.113.1', '203.0.113.1 · servidor (interfaz pública)'], ['192.168.1.1', '192.168.1.1 · servidor (interfaz LAN)'], ['172.16.0.1', '172.16.0.1 · servidor (interfaz DMZ)']];
    const cur = $('nmapTarget').value;
    $('nmapTarget').innerHTML = t.map(([v, l]) => `<option value="${v}">${esc(l)}</option>`).join('');
    if (t.some(([v]) => v === cur)) $('nmapTarget').value = cur;
  }

  function onNmap(e) {
    e.preventDefault();
    const scan = C.nmapScan(st, { target: $('nmapTarget').value, type: $('nmapType').value, zone: $('nmapZone').value });
    if (scan.errors) { $('nmapOutput').textContent = scan.errors.join('\n'); return; }
    beep('scan');
    $('nmapOutput').textContent = C.nmapReport(scan);
    const color = (s) => (s === 'open' ? 'text-emerald-300' : s === 'closed' ? 'text-amber-300' : s === 'unfiltered' ? 'text-cyan-300' : 'text-rose-300');
    const ex = $('nmapExplain');
    ex.innerHTML = scan.notes.map((n) => `<div class="note note-info">${esc(n)}</div>`).join('') +
      '<div class="text-[11px] text-slate-400 uppercase font-mono">Por qué cada resultado</div>' +
      scan.rows.map((r) => `<div class="text-[11px]"><span class="font-mono ${color(r.state)}">${r.port}/${r.proto} ${esc(r.state)}</span> <span class="text-slate-300">— ${esc(r.why)}</span></div>`).join('');
    ex.classList.remove('hidden');
  }

  function renderAudit() {
    const a = C.audit(st);
    // Clases completas (Tailwind solo genera las que aparecen literalmente en el código)
    const TONE = {
      good: { score: 'text-emerald-400', grade: 'bg-emerald-950 text-emerald-300 border-emerald-800', box: 'border-emerald-800/60', title: 'text-emerald-400' },
      mid: { score: 'text-amber-400', grade: 'bg-amber-950 text-amber-300 border-amber-800', box: 'border-amber-800/60', title: 'text-amber-400' },
      bad: { score: 'text-rose-400', grade: 'bg-rose-950 text-rose-300 border-rose-800', box: 'border-rose-800/60', title: 'text-rose-400' },
    };
    const g = TONE[a.grade === 'A' ? 'good' : a.grade === 'B' ? 'mid' : 'bad'];
    $('auditScore').textContent = `${a.score}/100`;
    $('auditScore').className = `text-3xl font-bold ${g.score}`;
    $('auditGrade').textContent = `Nota ${a.grade}`;
    $('auditGrade').className = `px-2 py-0.5 rounded text-xs font-bold border ${g.grade}`;
    $('auditChecks').innerHTML = a.checks.map((c) => {
      const k = c.status === 'PASS' ? [TONE.good, '✔'] : c.status === 'WARN' ? [TONE.mid, '⚠'] : [TONE.bad, '✘'];
      return `<div class="p-2.5 rounded-lg bg-slate-900 border ${k[0].box} flex items-start justify-between gap-3">
        <div><div class="text-xs ${k[0].title} font-bold">${k[1]} ${esc(c.title)}</div><p class="text-[11px] text-slate-400 leading-snug">${esc(c.desc)}</p></div>
        <span class="text-[10px] font-mono text-slate-500 shrink-0">${c.weight} pts</span>
      </div>`;
    }).join('');
  }

  // ==========================================================================
  // DESCARGAR EN UN ÚNICO .HTML
  // ==========================================================================

  async function downloadSingleFile() {
    if (window.CFW_SINGLE_FILE) { toast('Ya estás usando la versión de archivo único: guárdala con Ctrl+S.'); return; }
    try {
      const get = (u) => fetch(u, { cache: 'no-store' }).then((r) => { if (!r.ok) throw new Error(u); return r; });
      const [html, css, eng, app, logo] = await Promise.all([
        get('index.html').then((r) => r.text()), get('css/app.css').then((r) => r.text()),
        get('js/engine.js').then((r) => r.text()), get('js/app.js').then((r) => r.text()),
        get('assets/logo.png').then((r) => r.blob()),
      ]);
      const dataUri = await new Promise((ok, ko) => { const fr = new FileReader(); fr.onload = () => ok(fr.result); fr.onerror = ko; fr.readAsDataURL(logo); });
      const js = (s) => s.replace(/<\/script/gi, '<\\/script');
      let out = html
        .replace(/<meta http-equiv="Content-Security-Policy"[^>]*>/, '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; script-src \'unsafe-inline\'; style-src \'unsafe-inline\'; img-src data:; base-uri \'none\'; form-action \'none\'" />')
        .replace('<link rel="stylesheet" href="css/app.css" />', () => `<style>\n${css.replace(/<\/style/gi, '<\\/style')}\n</style>`)
        .replace('<script src="js/engine.js"></script>', () => `<script>window.CFW_SINGLE_FILE = true;</script>\n<script>\n${js(eng)}\n</script>`)
        .replace('<script src="js/app.js"></script>', () => `<script>\n${js(app)}\n</script>`)
        .split('assets/logo.png').join(dataUri);
      download('CyberFirewall-Lab.html', out, 'text/html;charset=utf-8');
      toast('Descargado CyberFirewall-Lab.html: funciona sin conexión y sin instalar nada.');
    } catch (err) {
      toast('No se pudo empaquetar desde aquí (¿abierto como archivo local?). Descárgalo desde la web publicada.');
    }
  }

  // ==========================================================================
  // ARRANQUE
  // ==========================================================================

  function renderAll() {
    renderEngine();
    renderRules();
    renderCli();
    renderConntrack();
    renderNat();
    renderLogs();
    setConsoleTab(ui.con);
    if (!$('modalNmap').classList.contains('hidden')) renderNmapTargets();
  }

  function bind() {
    $$('.engine-btn').forEach((b) => b.addEventListener('click', () => setEngine(b.dataset.engine)));
    $$('[data-policy]').forEach((s) => s.addEventListener('change', () => { st.policies.linux[s.dataset.policy] = s.value; colorPolicy(s); save(); renderCli(); toast(`Política de ${s.dataset.policy}: ${s.value}`); }));
    $$('[data-wpolicy]').forEach((s) => s.addEventListener('change', () => { st.policies.windows[s.dataset.wpolicy] = s.value; colorPolicy(s); save(); renderCli(); }));
    $('selectWindowsProfile').addEventListener('change', (e) => { st.windowsProfile = e.target.value; save(); toast(`Perfil activo: ${e.target.selectedOptions[0].textContent}`); });
    $$('[data-open]').forEach((b) => b.addEventListener('click', () => openModal(b.dataset.open)));
    $$('.modal').forEach((m) => {
      m.addEventListener('click', (e) => { if (e.target === m || e.target.closest('[data-close]')) closeModal(m); });
    });
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') { const open = $$('.modal').find((m) => !m.classList.contains('hidden')); if (open) closeModal(open); }
    });
    $('btnZeroCounters').addEventListener('click', () => { C.rulesOf(st).forEach((r) => { r.packets = 0; r.bytes = 0; }); renderRules(); toast('Contadores a cero (iptables -Z)'); });
    $('btnAudio').addEventListener('click', () => { ui.audio = !ui.audio; $('audioIcon').textContent = ui.audio ? '🔊' : '🔇'; savePrefs(); toast(ui.audio ? 'Sonido activado' : 'Sonido silenciado'); });
    $('audioIcon').textContent = ui.audio ? '🔊' : '🔇';
    $('btnReset').addEventListener('click', () => {
      if (!window.confirm('¿Restaurar las reglas, políticas y NAT de ejemplo de los dos motores? Perderás tus cambios.')) return;
      const fresh = C.createState();
      fresh.engine = st.engine;
      Object.assign(st, fresh);
      ui.lastResult = null; ui.logs = [];
      save(); renderAll(); resetVerdict();
      toast('Reglas de ejemplo restauradas');
    });
    $('btnDownloadHtml').addEventListener('click', downloadSingleFile);
    $('btnDemoFirstMatch').addEventListener('click', () => { openModal('modalScenarios'); });
    $('btnToggleTopology').addEventListener('click', (e) => { const b = $('topologyBody'); b.classList.toggle('hidden'); e.target.textContent = b.classList.contains('hidden') ? 'Mostrar' : 'Ocultar'; });

    $('filterChain').addEventListener('change', (e) => { ui.filter = e.target.value; renderRules(); });
    $('btnAddRule').addEventListener('click', () => openRuleModal(null));
    $('rulesTableBody').addEventListener('click', onRuleTableClick);
    $('ruleForm').addEventListener('submit', onRuleSubmit);
    $('ruleChain').addEventListener('change', syncRuleForm);
    $('ruleProtocol').addEventListener('change', syncRuleForm);
    $('ruleTemplates').addEventListener('click', (e) => {
      const b = e.target.closest('[data-tpl]');
      if (!b) return;
      fillRuleForm(C.makeRule(TEMPLATES[st.engine][Number(b.dataset.tpl)][1]));
    });

    $('selectPacketPreset').addEventListener('change', (e) => {
      if (e.target.value === '') return;
      fillPacketForm(PRESETS[st.engine][Number(e.target.value)][1]);
      toast(`Cargado: ${e.target.selectedOptions[0].textContent}`);
    });
    $('pktProtocol').addEventListener('change', () => {
      syncPacketForm();
      if ($('pktProtocol').value !== 'ICMP' && !$('pktSrcPort').value) { $('pktSrcPort').value = '51200'; $('pktDstPort').value = '80'; }
    });
    $('packetForm').addEventListener('submit', (e) => { e.preventDefault(); trace(false); });
    $('btnInstant').addEventListener('click', () => trace(true));
    $('btnReturn').addEventListener('click', prepareReturn);

    $$('.cli-tab').forEach((b) => b.addEventListener('click', () => { ui.cli = b.dataset.cli; savePrefs(); renderCli(); }));
    $('btnCopyCli').addEventListener('click', copyCli);
    $$('.con-tab').forEach((b) => b.addEventListener('click', () => setConsoleTab(b.dataset.con)));
    $('btnClearConsole').addEventListener('click', () => {
      if (ui.con === 'logs') { ui.logs = []; renderLogs(); toast('Registros vaciados'); return; }
      st.conntrack = []; renderConntrack(); renderNat(); toast('conntrack -F: tabla de conexiones vaciada');
    });
    $('btnNoise').addEventListener('click', noise);
    $('chkMasq').addEventListener('change', (e) => { st.nat.masquerade = e.target.checked; save(); renderCli(); toast(`MASQUERADE ${e.target.checked ? 'activado' : 'desactivado'}`); });
    $('dnatForm').addEventListener('submit', onDnatSubmit);
    $('dnatBody').addEventListener('change', onDnatClick);
    $('dnatBody').addEventListener('click', (e) => { if (e.target.matches('[data-dnat-del]')) onDnatClick(e); });

    $('scenarioList').addEventListener('click', onScenarioClick);
    $('cidrForm').addEventListener('submit', onCidrSubmit);
    $$('[data-export]').forEach((b) => b.addEventListener('click', () => onExport(b.dataset.export)));
    $('importInput').addEventListener('change', onImport);
    $('nmapForm').addEventListener('submit', onNmap);
    $('btnAuditRerun').addEventListener('click', renderAudit);
  }

  bind();
  renderAll();
  syncPacketForm();
  $('cidrForm').requestSubmit ? $('cidrForm').requestSubmit() : null;
})();

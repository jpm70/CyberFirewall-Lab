/*!
 * CyberFirewall Lab — motor de simulación (sin DOM)
 * Copyright (c) 2026 Un Fantasma en el Sistema — Licencia MIT
 *
 * Modela un firewall Linux de tres patas (WAN eth0 / LAN eth1 / DMZ eth2) con
 * las cadenas reales de netfilter (INPUT, FORWARD, OUTPUT), seguimiento de
 * conexiones (conntrack), DNAT/MASQUERADE, y un modo Windows Defender Firewall
 * (firewall de host con precedencia de bloqueo). Se usa igual en el navegador
 * (window.CFW) que en Node (require) para las pruebas.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.CFW = api;
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // ==========================================================================
  // TOPOLOGÍA
  // ==========================================================================

  const IFACES = {
    WAN: { dev: 'eth0', fwIp: '203.0.113.1', net: null, mac: '52:54:00:0a:00:01', label: 'WAN (Internet)' },
    LAN: { dev: 'eth1', fwIp: '192.168.1.1', net: '192.168.1.0/24', mac: '52:54:00:0b:00:01', label: 'LAN (red interna)' },
    DMZ: { dev: 'eth2', fwIp: '172.16.0.1', net: '172.16.0.0/24', mac: '52:54:00:0c:00:01', label: 'DMZ (servidores)' },
  };
  const ZONES = ['WAN', 'LAN', 'DMZ'];
  const WAN_IP = IFACES.WAN.fwIp;

  // Servicios que escuchan en cada equipo simulado (lo que Nmap puede encontrar).
  const HOSTS = {
    '172.16.0.10': { name: 'srv-web (DMZ)', tcp: [22, 80, 443], udp: [53], ttl: 64 },
    '192.168.1.50': { name: 'pc-50 (LAN, Windows)', tcp: [135, 445, 3389], udp: [137], ttl: 128 },
    '93.184.216.34': { name: 'web externa', tcp: [80, 443], udp: [], ttl: 54 },
    '8.8.8.8': { name: 'DNS público', tcp: [53, 443], udp: [53], ttl: 118 },
  };
  const FIREWALL_HOST = {
    linux: { name: 'firewall (Linux)', tcp: [22], udp: [53], ttl: 64 },
    windows: { name: 'servidor Windows', tcp: [135, 443, 445, 3389], udp: [137], ttl: 128 },
  };

  const SERVICE_NAMES = {
    21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'domain', 67: 'dhcps', 80: 'http', 123: 'ntp',
    135: 'msrpc', 137: 'netbios-ns', 139: 'netbios-ssn', 161: 'snmp', 443: 'https', 445: 'microsoft-ds',
    3389: 'ms-wbt-server', 8080: 'http-proxy',
  };

  // ==========================================================================
  // DIRECCIONES IPv4, CIDR Y PUERTOS
  // ==========================================================================

  function ipToInt(str) {
    if (typeof str !== 'string') return null;
    const parts = str.trim().split('.');
    if (parts.length !== 4) return null;
    let n = 0;
    for (const p of parts) {
      if (!/^\d{1,3}$/.test(p)) return null;
      const o = Number(p);
      if (o > 255) return null;
      n = n * 256 + o;
    }
    return n;
  }

  function intToIp(n) {
    return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
  }

  function maskOf(bits) {
    return bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  }

  function isAnySpec(spec) {
    if (spec === undefined || spec === null) return true;
    const s = String(spec).trim().toUpperCase();
    return s === '' || s === 'ANY' || s === '*' || s === '0.0.0.0/0';
  }

  /** Devuelve { any } | { net, bits, first, last } | { error }. */
  function parseIpSpec(spec) {
    if (isAnySpec(spec)) return { any: true, first: 0, last: 0xffffffff };
    const s = String(spec).trim();
    const [addr, bitsStr, extra] = s.split('/');
    if (extra !== undefined) return { error: `«${s}» no es una IP ni un CIDR válido` };
    const ip = ipToInt(addr);
    if (ip === null) return { error: `«${s}» no es una IP ni un CIDR válido` };
    let bits = 32;
    if (bitsStr !== undefined) {
      if (!/^\d{1,2}$/.test(bitsStr) || Number(bitsStr) > 32) return { error: `Prefijo /${bitsStr} no válido (0-32)` };
      bits = Number(bitsStr);
    }
    const mask = maskOf(bits);
    const first = (ip & mask) >>> 0;
    const last = (first | (~mask >>> 0)) >>> 0;
    return { net: intToIp(first), bits, first, last, aligned: first === ip };
  }

  function ipInSpec(ip, spec) {
    const p = parseIpSpec(spec);
    if (p.error) return false;
    if (p.any) return true;
    const n = ipToInt(ip);
    return n !== null && n >= p.first && n <= p.last;
  }

  /** Devuelve { any } | { ranges: [[a,b],...] } | { error }. Admite 80 · 80,443 · 1024-65535 · 80,8000-8080. */
  function parsePortSpec(spec) {
    if (spec === undefined || spec === null) return { any: true };
    const s = String(spec).trim().toUpperCase();
    if (s === '' || s === 'ANY' || s === '*') return { any: true };
    const ranges = [];
    for (const raw of s.split(',')) {
      const item = raw.trim();
      const m = /^(\d{1,5})(?:\s*[-:]\s*(\d{1,5}))?$/.exec(item);
      if (!m) return { error: `«${item || s}» no es un puerto, lista o rango válido` };
      const a = Number(m[1]);
      const b = m[2] !== undefined ? Number(m[2]) : a;
      if (a < 1 || b > 65535 || a > b) return { error: `Rango de puertos «${item}» fuera de 1-65535 o invertido` };
      ranges.push([a, b]);
    }
    if (ranges.length > 15) return { error: 'Máximo 15 puertos o rangos por regla (límite de iptables multiport)' };
    return { ranges };
  }

  function portInSpec(port, spec) {
    const p = parsePortSpec(spec);
    if (p.error) return false;
    if (p.any) return true;
    return p.ranges.some(([a, b]) => port >= a && port <= b);
  }

  function portSpecIsMulti(spec) {
    const p = parsePortSpec(spec);
    return !p.any && !p.error && (p.ranges.length > 1);
  }

  function zoneOf(ip) {
    if (ipInSpec(ip, IFACES.LAN.net)) return 'LAN';
    if (ipInSpec(ip, IFACES.DMZ.net)) return 'DMZ';
    return 'WAN';
  }

  function firewallZoneOf(ip) {
    for (const z of ZONES) if (IFACES[z].fwIp === ip) return z;
    return null;
  }

  function isFirewallIp(ip) {
    return firewallZoneOf(ip) !== null;
  }

  function isPrivateIp(ip) {
    return ipInSpec(ip, '10.0.0.0/8') || ipInSpec(ip, '172.16.0.0/12') || ipInSpec(ip, '192.168.0.0/16');
  }

  // ==========================================================================
  // REGLAS
  // ==========================================================================

  const CHAINS = ['INPUT', 'FORWARD', 'OUTPUT'];
  const ACTIONS = ['ACCEPT', 'DROP', 'REJECT'];
  const PROTOCOLS = ['ANY', 'TCP', 'UDP', 'ICMP'];
  const CT_STATES = ['NEW', 'ESTABLISHED', 'RELATED', 'INVALID'];
  const PROFILES = ['Any', 'Domain', 'Private', 'Public'];
  const IFACE_OPTS = ['ANY', 'WAN', 'LAN', 'DMZ'];

  function parseStateSpec(spec) {
    if (spec === undefined || spec === null) return { any: true };
    const s = String(spec).trim().toUpperCase();
    if (s === '' || s === 'ANY') return { any: true };
    const list = s.split(',').map((x) => x.trim()).filter(Boolean);
    for (const st of list) if (!CT_STATES.includes(st)) return { error: `Estado conntrack «${st}» desconocido` };
    return { states: [...new Set(list)] };
  }

  function makeRule(fields) {
    return Object.assign({
      id: 0, name: '', chain: 'INPUT', inIface: 'ANY', outIface: 'ANY', protocol: 'ANY',
      srcIp: 'ANY', srcPort: 'ANY', dstIp: 'ANY', dstPort: 'ANY', state: 'ANY', action: 'ACCEPT',
      profile: 'Any', enabled: true, packets: 0, bytes: 0,
    }, fields);
  }

  /** Lista de errores (en castellano) de una regla para el motor indicado. Vacía = válida. */
  function validateRule(r, engine) {
    const e = [];
    if (!r || typeof r !== 'object') return ['La regla no es un objeto'];
    if (typeof r.name !== 'string' || !r.name.trim()) e.push('Falta el nombre de la regla');
    else if (r.name.length > 120) e.push('El nombre no puede superar 120 caracteres');
    if (!CHAINS.includes(r.chain)) e.push(`Cadena/dirección «${r.chain}» no válida`);
    if (engine === 'windows' && r.chain === 'FORWARD') e.push('Windows Defender Firewall no tiene cadena FORWARD: usa Entrada o Salida');
    if (!ACTIONS.includes(r.action)) e.push(`Acción «${r.action}» no válida`);
    if (!PROTOCOLS.includes(r.protocol)) e.push(`Protocolo «${r.protocol}» no válido`);
    if (!IFACE_OPTS.includes(r.inIface)) e.push(`Interfaz de entrada «${r.inIface}» no válida`);
    if (!IFACE_OPTS.includes(r.outIface)) e.push(`Interfaz de salida «${r.outIface}» no válida`);
    if (engine !== 'windows') {
      if (r.chain === 'OUTPUT' && r.inIface !== 'ANY') e.push('En OUTPUT no existe interfaz de entrada (-i): el paquete lo genera el propio firewall');
      if (r.chain === 'INPUT' && r.outIface !== 'ANY') e.push('En INPUT no existe interfaz de salida (-o): el paquete va al propio firewall');
    }
    if (!PROFILES.includes(r.profile)) e.push(`Perfil «${r.profile}» no válido`);
    for (const [label, v] of [['IP origen', r.srcIp], ['IP destino', r.dstIp]]) {
      const p = parseIpSpec(v);
      if (p.error) e.push(`${label}: ${p.error}`);
    }
    for (const [label, v] of [['Puerto origen', r.srcPort], ['Puerto destino', r.dstPort]]) {
      const p = parsePortSpec(v);
      if (p.error) e.push(`${label}: ${p.error}`);
      else if (!p.any && r.protocol !== 'TCP' && r.protocol !== 'UDP') e.push(`${label}: los puertos solo existen en TCP y UDP (elige el protocolo)`);
    }
    const st = parseStateSpec(r.state);
    if (st.error) e.push(st.error);
    return e;
  }

  /** Convierte una regla importada (incluido el formato de la v1) al formato actual. */
  function normalizeRule(raw, engine) {
    if (!raw || typeof raw !== 'object') return { errors: ['Entrada que no es un objeto'] };
    const legacyDir = { INBOUND: 'INPUT', OUTBOUND: 'OUTPUT', FORWARD: 'FORWARD' };
    const str = (v, d) => (v === undefined || v === null ? d : String(v).trim());
    const up = (v, d) => str(v, d).toUpperCase();
    let chain = up(raw.chain, '') || legacyDir[up(raw.direction, '')] || up(raw.direction, 'INPUT');
    let inIface = up(raw.inIface, '');
    let outIface = up(raw.outIface, '');
    if (!inIface && !outIface && raw.zone !== undefined) {
      const z = up(raw.zone, 'ANY');
      if (chain === 'OUTPUT') { inIface = 'ANY'; outIface = z; } else { inIface = z; outIface = 'ANY'; }
    }
    let profile = str(raw.profile, 'Any');
    if (/^(all|any|todos)$/i.test(profile)) profile = 'Any';
    else profile = profile.charAt(0).toUpperCase() + profile.slice(1).toLowerCase();
    const rule = makeRule({
      id: Number.isInteger(raw.id) && raw.id > 0 ? raw.id : 0,
      name: str(raw.name, '').slice(0, 120),
      chain, inIface: inIface || 'ANY', outIface: outIface || 'ANY',
      protocol: up(raw.protocol, 'ANY'),
      srcIp: str(raw.srcIp, 'ANY') || 'ANY', srcPort: str(raw.srcPort, 'ANY') || 'ANY',
      dstIp: str(raw.dstIp, 'ANY') || 'ANY', dstPort: str(raw.dstPort, 'ANY') || 'ANY',
      state: up(raw.state, 'ANY') || 'ANY',
      action: up(raw.action, 'ACCEPT'),
      profile,
      enabled: raw.enabled !== false,
      packets: 0, bytes: 0,
    });
    if (rule.action === 'ALLOW') rule.action = 'ACCEPT';
    if (rule.action === 'BLOCK') rule.action = 'DROP';
    if (isAnySpec(rule.srcIp)) rule.srcIp = 'ANY';
    if (isAnySpec(rule.dstIp)) rule.dstIp = 'ANY';
    const errors = validateRule(rule, engine);
    return { rule, errors };
  }

  // --- relaciones entre reglas (sombreado / redundancia) ---------------------

  function ipSpecCovers(a, b) {
    const pa = parseIpSpec(a), pb = parseIpSpec(b);
    if (pa.error || pb.error) return false;
    return pa.first <= pb.first && pa.last >= pb.last;
  }

  function portSpecCovers(a, b) {
    const pa = parsePortSpec(a), pb = parsePortSpec(b);
    if (pa.error || pb.error) return false;
    if (pa.any) return true;
    if (pb.any) return false;
    return pb.ranges.every(([x, y]) => {
      // cada rango de b debe quedar cubierto por la unión de rangos de a
      let cur = x;
      const sorted = pa.ranges.slice().sort((m, n) => m[0] - n[0]);
      for (const [s, t] of sorted) {
        if (s <= cur && t >= cur) cur = t + 1;
        if (cur > y) return true;
      }
      return cur > y;
    });
  }

  function stateSpecCovers(a, b) {
    const pa = parseStateSpec(a), pb = parseStateSpec(b);
    if (pa.error || pb.error) return false;
    if (pa.any) return true;
    if (pb.any) return pa.states.length === CT_STATES.length;
    return pb.states.every((s) => pa.states.includes(s));
  }

  function ruleCovers(a, b, engine) {
    if (a.chain !== b.chain) return false;
    if (engine === 'windows' && a.profile !== 'Any' && a.profile !== b.profile) return false;
    if (engine !== 'windows') {
      if (a.inIface !== 'ANY' && a.inIface !== b.inIface) return false;
      if (a.outIface !== 'ANY' && a.outIface !== b.outIface) return false;
      if (!stateSpecCovers(a.state, b.state)) return false;
    }
    if (a.protocol !== 'ANY' && a.protocol !== b.protocol) return false;
    return ipSpecCovers(a.srcIp, b.srcIp) && ipSpecCovers(a.dstIp, b.dstIp) &&
      portSpecCovers(a.srcPort, b.srcPort) && portSpecCovers(a.dstPort, b.dstPort);
  }

  /**
   * Linux: una regla queda «sombreada» si otra anterior de la misma cadena la cubre entera
   * con otra acción (nunca se aplicará) y «redundante» si la cubre con la misma acción.
   * Windows: una regla de permiso queda «anulada» si una de bloqueo la cubre entera.
   */
  function analyzeRules(rules, engine) {
    const out = {};
    const active = rules.filter((r) => r.enabled);
    if (engine === 'windows') {
      for (const r of active) {
        if (r.action !== 'ACCEPT') continue;
        const blocker = active.find((b) => b !== r && b.action !== 'ACCEPT' && ruleCovers(b, r, engine));
        if (blocker) out[r.id] = { type: 'overridden', by: blocker.id };
      }
      return out;
    }
    for (let j = 0; j < active.length; j++) {
      for (let i = 0; i < j; i++) {
        if (ruleCovers(active[i], active[j], engine)) {
          out[active[j].id] = { type: active[i].action === active[j].action ? 'redundant' : 'shadowed', by: active[i].id };
          break;
        }
      }
    }
    return out;
  }

  // ==========================================================================
  // ESTADO DEL LABORATORIO
  // ==========================================================================

  function defaultLinuxRules() {
    let id = 0;
    const r = (f) => makeRule(Object.assign({ id: ++id }, f));
    return [
      r({ name: 'Vuelta de conexiones ya aceptadas', chain: 'INPUT', state: 'ESTABLISHED,RELATED', action: 'ACCEPT' }),
      r({ name: 'Vuelta de conexiones ya aceptadas', chain: 'FORWARD', state: 'ESTABLISHED,RELATED', action: 'ACCEPT' }),
      r({ name: 'Descartar paquetes INVALID', chain: 'FORWARD', state: 'INVALID', action: 'DROP' }),
      r({ name: 'SSH de administración solo desde la LAN', chain: 'INPUT', inIface: 'LAN', protocol: 'TCP', srcIp: '192.168.1.0/24', dstPort: '22', state: 'NEW', action: 'ACCEPT' }),
      r({ name: 'Ping al firewall desde la LAN', chain: 'INPUT', inIface: 'LAN', protocol: 'ICMP', state: 'NEW', action: 'ACCEPT' }),
      r({ name: 'DNS del firewall para la LAN', chain: 'INPUT', inIface: 'LAN', protocol: 'UDP', dstPort: '53', state: 'NEW', action: 'ACCEPT' }),
      r({ name: 'SSH desde Internet: descartar y contar', chain: 'INPUT', inIface: 'WAN', protocol: 'TCP', dstPort: '22', state: 'NEW', action: 'DROP' }),
      r({ name: 'La LAN sale a Internet', chain: 'FORWARD', inIface: 'LAN', outIface: 'WAN', srcIp: '192.168.1.0/24', state: 'NEW', action: 'ACCEPT' }),
      r({ name: 'La LAN usa la web de la DMZ', chain: 'FORWARD', inIface: 'LAN', outIface: 'DMZ', protocol: 'TCP', dstIp: '172.16.0.10', dstPort: '80,443', state: 'NEW', action: 'ACCEPT' }),
      r({ name: 'Internet → web de la DMZ (tras el DNAT)', chain: 'FORWARD', inIface: 'WAN', outIface: 'DMZ', protocol: 'TCP', dstIp: '172.16.0.10', dstPort: '80,443', state: 'NEW', action: 'ACCEPT' }),
      r({ name: 'La DMZ no abre conexiones a la LAN', chain: 'FORWARD', inIface: 'DMZ', outIface: 'LAN', state: 'NEW', action: 'REJECT' }),
    ];
  }

  function defaultWindowsRules() {
    let id = 0;
    const r = (f) => makeRule(Object.assign({ id: ++id }, f));
    return [
      r({ name: 'Servidor web HTTPS', chain: 'INPUT', protocol: 'TCP', dstPort: '443', action: 'ACCEPT' }),
      r({ name: 'Escritorio remoto (RDP) solo desde la LAN', chain: 'INPUT', protocol: 'TCP', srcIp: '192.168.1.0/24', dstPort: '3389', action: 'ACCEPT', profile: 'Private' }),
      r({ name: 'Bloquear SMB desde cualquier sitio', chain: 'INPUT', protocol: 'TCP', dstPort: '445', action: 'DROP' }),
      r({ name: 'Ping desde la LAN', chain: 'INPUT', protocol: 'ICMP', srcIp: '192.168.1.0/24', action: 'ACCEPT' }),
      r({ name: 'Bloquear Telnet saliente', chain: 'OUTPUT', protocol: 'TCP', dstPort: '23', action: 'DROP' }),
    ];
  }

  function defaultDnat() {
    return [
      { id: 1, proto: 'TCP', port: 80, toIp: '172.16.0.10', toPort: 80, enabled: true },
      { id: 2, proto: 'TCP', port: 443, toIp: '172.16.0.10', toPort: 443, enabled: true },
    ];
  }

  function createState() {
    return {
      engine: 'linux',
      windowsProfile: 'Public',
      policies: {
        linux: { INPUT: 'DROP', FORWARD: 'DROP', OUTPUT: 'ACCEPT' },
        windows: { INPUT: 'DROP', OUTPUT: 'ACCEPT' },
      },
      rules: { linux: defaultLinuxRules(), windows: defaultWindowsRules() },
      nat: { masquerade: true, masqNets: ['192.168.1.0/24', '172.16.0.0/24'], dnat: defaultDnat() },
      conntrack: [],
      ctSeq: 1,
    };
  }

  function cloneState(st) {
    return JSON.parse(JSON.stringify(st));
  }

  function rulesOf(st) {
    return st.rules[st.engine];
  }

  function nextRuleId(rules) {
    return rules.reduce((m, r) => Math.max(m, r.id), 0) + 1;
  }

  // ==========================================================================
  // PAQUETES
  // ==========================================================================

  const TCP_FLAG_BITS = { FIN: 0x01, SYN: 0x02, RST: 0x04, PSH: 0x08, ACK: 0x10, URG: 0x20 };

  function parseTcpFlags(flags) {
    const set = new Set(String(flags || 'SYN').toUpperCase().split(/[^A-Z]+/).filter((f) => TCP_FLAG_BITS[f]));
    if (!set.size) set.add('SYN');
    return set;
  }

  function flagsToString(set) {
    return ['SYN', 'RST', 'FIN', 'PSH', 'ACK', 'URG'].filter((f) => set.has(f)).join(',');
  }

  /** Normaliza y valida un paquete de entrada. Devuelve { pkt } o { errors }. */
  function normalizePacket(input) {
    const errors = [];
    const protocol = String(input.protocol || 'TCP').toUpperCase();
    if (!['TCP', 'UDP', 'ICMP'].includes(protocol)) errors.push(`Protocolo «${input.protocol}» no válido`);
    const srcIp = String(input.srcIp || '').trim();
    const dstIp = String(input.dstIp || '').trim();
    if (ipToInt(srcIp) === null) errors.push(`IP de origen «${srcIp}» no válida`);
    if (ipToInt(dstIp) === null) errors.push(`IP de destino «${dstIp}» no válida`);
    let srcPort = 0, dstPort = 0;
    if (protocol === 'TCP' || protocol === 'UDP') {
      srcPort = Number(input.srcPort);
      dstPort = Number(input.dstPort);
      if (!Number.isInteger(srcPort) || srcPort < 1 || srcPort > 65535) errors.push('Puerto de origen fuera de 1-65535');
      if (!Number.isInteger(dstPort) || dstPort < 1 || dstPort > 65535) errors.push('Puerto de destino fuera de 1-65535');
    }
    if (srcIp && srcIp === dstIp) errors.push('Origen y destino no pueden ser la misma IP');
    if (isFirewallIp(srcIp) && isFirewallIp(dstIp)) errors.push('Origen y destino son el propio firewall (eso va por la interfaz lo, que no se simula)');
    const inIface = String(input.inIface || 'AUTO').toUpperCase();
    if (!['AUTO', ...ZONES].includes(inIface)) errors.push(`Interfaz de entrada «${input.inIface}» no válida`);
    const stateOverride = String(input.stateOverride || 'AUTO').toUpperCase();
    if (!['AUTO', ...CT_STATES].includes(stateOverride)) errors.push(`Estado «${input.stateOverride}» no válido`);
    if (errors.length) return { errors };
    const pkt = { protocol, srcIp, dstIp, srcPort, dstPort, inIface, stateOverride };
    if (protocol === 'TCP') pkt.flags = flagsToString(parseTcpFlags(input.flags));
    if (protocol === 'ICMP') {
      pkt.icmpType = input.icmpType !== undefined ? Number(input.icmpType) : 8;
      pkt.icmpCode = input.icmpCode !== undefined ? Number(input.icmpCode) : 0;
      pkt.icmpId = input.icmpId !== undefined ? Number(input.icmpId) : 0x1c2b;
      if (input.inner) pkt.inner = input.inner;
    }
    if (input.payloadLen !== undefined) pkt.payloadLen = input.payloadLen;
    return { pkt };
  }

  // ==========================================================================
  // CONNTRACK
  // ==========================================================================

  function tupleOf(pkt) {
    if (pkt.protocol === 'ICMP') return { proto: 'ICMP', src: pkt.srcIp, sport: pkt.icmpId, dst: pkt.dstIp, dport: pkt.icmpId };
    return { proto: pkt.protocol, src: pkt.srcIp, sport: pkt.srcPort, dst: pkt.dstIp, dport: pkt.dstPort };
  }

  function sameTuple(t, u) {
    return t.src === u.src && t.sport === u.sport && t.dst === u.dst && t.dport === u.dport;
  }

  function findConn(st, proto, tuple) {
    for (const c of st.conntrack) {
      if (c.proto !== proto) continue;
      if (sameTuple(c.orig, tuple)) return { conn: c, dir: 'ORIGINAL' };
      if (sameTuple(c.reply, tuple)) return { conn: c, dir: 'REPLY' };
    }
    return null;
  }

  /**
   * Clasifica el paquete como lo haría nf_conntrack (con nf_conntrack_tcp_loose=1, el valor por defecto).
   * Devuelve { state, conn, dir, why }.
   */
  function classify(st, pkt) {
    if (pkt.protocol === 'ICMP' && [3, 4, 5, 11, 12].includes(pkt.icmpType)) {
      // Error ICMP: se asocia a la conexión del paquete que lo provocó (va embebido).
      const inner = pkt.inner;
      if (inner) {
        // El paquete embebido puede verse antes del NAT (coincide con una tupla) o después (coincide con la inversa).
        const f = findConn(st, inner.proto, { src: inner.src, sport: inner.sport, dst: inner.dst, dport: inner.dport });
        const g = f ? null : findConn(st, inner.proto, { src: inner.dst, sport: inner.dport, dst: inner.src, dport: inner.sport });
        const why = (c) => `Error ICMP tipo ${pkt.icmpType} asociado a la conexión #${c.id}`;
        if (f) return { state: 'RELATED', conn: f.conn, dir: f.dir === 'ORIGINAL' ? 'REPLY' : 'ORIGINAL', why: why(f.conn) };
        if (g) return { state: 'RELATED', conn: g.conn, dir: g.dir, why: why(g.conn) };
      }
      return { state: 'INVALID', why: 'Error ICMP que no corresponde a ninguna conexión conocida' };
    }
    const t = tupleOf(pkt);
    if (pkt.protocol === 'ICMP' && pkt.icmpType === 0) {
      // Echo reply: su tupla «original» es la del echo request (mismo id, IP invertidas).
      const f = findConn(st, 'ICMP', t);
      if (f) return { state: 'ESTABLISHED', conn: f.conn, dir: f.dir, why: `Respuesta al ping de la conexión #${f.conn.id}` };
      return { state: 'INVALID', why: 'Echo reply sin un echo request previo: conntrack no puede asociarlo' };
    }
    const f = findConn(st, pkt.protocol, t);
    if (f) {
      if (f.dir === 'REPLY') return { state: 'ESTABLISHED', conn: f.conn, dir: 'REPLY', why: `Respuesta de la conexión #${f.conn.id} (vista en los dos sentidos)` };
      return {
        state: f.conn.seenReply ? 'ESTABLISHED' : 'NEW', conn: f.conn, dir: 'ORIGINAL',
        why: f.conn.seenReply ? `Sigue la conexión #${f.conn.id}` : `La conexión #${f.conn.id} todavía no ha recibido respuesta: conntrack la sigue viendo como NEW`,
      };
    }
    if (pkt.protocol === 'TCP') {
      const fl = parseTcpFlags(pkt.flags);
      if (fl.has('RST')) return { state: 'INVALID', why: 'Un RST sin conexión previa no puede abrir nada: INVALID' };
      if (fl.has('SYN') && fl.has('ACK')) return { state: 'INVALID', why: 'SYN+ACK sin un SYN previo: conntrack lo marca INVALID' };
      if (fl.has('SYN')) return { state: 'NEW', why: 'SYN sin conexión previa: abre una conexión nueva' };
      if (fl.has('FIN')) return { state: 'INVALID', why: 'FIN sin conexión previa: INVALID' };
      return { state: 'NEW', why: 'ACK sin conexión previa: con nf_conntrack_tcp_loose=1 (valor por defecto) Linux «recoge» la conexión a medias y la marca NEW. Por eso se recomienda exigir SYN en las reglas NEW' };
    }
    return { state: 'NEW', why: 'Primer paquete de este flujo: NEW' };
  }

  // ==========================================================================
  // PIPELINE NETFILTER
  // ==========================================================================

  function matchRuleLinux(r, v) {
    if (r.chain !== v.chain) return { ok: false, why: `pertenece a la cadena ${r.chain}` };
    if (r.inIface !== 'ANY' && r.inIface !== v.inIface) return { ok: false, why: `entrada por ${IFACES[r.inIface].dev} y el paquete entra por ${v.inIface ? IFACES[v.inIface].dev : '(local)'}` };
    if (r.outIface !== 'ANY' && r.outIface !== v.outIface) return { ok: false, why: `salida por ${IFACES[r.outIface].dev} y el paquete sale por ${v.outIface ? IFACES[v.outIface].dev : '(local)'}` };
    return matchCommon(r, v, true);
  }

  function matchCommon(r, v, useState) {
    if (r.protocol !== 'ANY' && r.protocol !== v.protocol) return { ok: false, why: `protocolo ${r.protocol} ≠ ${v.protocol}` };
    if (!ipInSpec(v.srcIp, r.srcIp)) return { ok: false, why: `origen ${v.srcIp} fuera de ${r.srcIp}` };
    if (!ipInSpec(v.dstIp, r.dstIp)) return { ok: false, why: `destino ${v.dstIp} fuera de ${r.dstIp}` };
    const hasPorts = !parsePortSpec(r.srcPort).any || !parsePortSpec(r.dstPort).any;
    if (hasPorts) {
      if (v.protocol === 'ICMP') return { ok: false, why: 'la regla filtra puertos e ICMP no tiene puertos' };
      if (!portInSpec(v.srcPort, r.srcPort)) return { ok: false, why: `puerto origen ${v.srcPort} fuera de ${r.srcPort}` };
      if (!portInSpec(v.dstPort, r.dstPort)) return { ok: false, why: `puerto destino ${v.dstPort} fuera de ${r.dstPort}` };
    }
    if (useState) {
      const s = parseStateSpec(r.state);
      if (!s.any && !s.states.includes(v.ctstate)) return { ok: false, why: `estado ${v.ctstate} no está en ${r.state}` };
    }
    return { ok: true, why: 'coinciden todos los campos' };
  }

  function matchRuleWindows(r, v, profile) {
    if (r.chain !== v.chain) return { ok: false, why: `es de ${r.chain === 'INPUT' ? 'entrada' : 'salida'}` };
    if (r.profile !== 'Any' && r.profile !== profile) return { ok: false, why: `solo se aplica al perfil ${r.profile} (activo: ${profile})` };
    return matchCommon(r, v, false);
  }

  function isServiceOpen(host, proto, port) {
    if (!host) return false;
    const list = proto === 'TCP' ? host.tcp : proto === 'UDP' ? host.udp : [];
    return list.includes(port);
  }

  function hostAt(st, ip) {
    if (isFirewallIp(ip)) return FIREWALL_HOST[st.engine];
    if (HOSTS[ip]) return HOSTS[ip];
    if (zoneOf(ip) === 'WAN') return { name: 'equipo de Internet', tcp: [], udp: [], ttl: 52 };
    return null; // nadie tiene esa IP en la LAN/DMZ simuladas
  }

  function allocateNatPort(st, wantPort, proto, remote, rport) {
    const used = (p) => st.conntrack.some((c) => c.proto === proto && c.reply.dst === WAN_IP && c.reply.dport === p && c.reply.src === remote && c.reply.sport === rport);
    if (!used(wantPort)) return { port: wantPort, changed: false };
    for (let p = 61000; p < 65535; p++) if (!used(p)) return { port: p, changed: true };
    return { port: wantPort, changed: false };
  }

  /**
   * Procesa un paquete a través del firewall.
   * opts.dryRun: no modifica conntrack ni contadores.
   */
  function processPacket(st, input, opts) {
    opts = opts || {};
    const norm = normalizePacket(input);
    if (norm.errors) return { errors: norm.errors };
    const pkt = norm.pkt;
    const notes = [];
    const engine = st.engine;
    const local = isFirewallIp(pkt.srcIp);

    // 1) Interfaz de entrada
    let inIface = null;
    if (!local) {
      const auto = zoneOf(pkt.srcIp);
      inIface = pkt.inIface === 'AUTO' ? auto : pkt.inIface;
      if (inIface !== auto) notes.push({ level: 'warn', text: `La IP de origen ${pkt.srcIp} pertenece a ${IFACES[auto].dev} (${auto}) pero el paquete entra por ${IFACES[inIface].dev}: es una IP falsificada (spoofing). Con rp_filter=1 el kernel lo descartaría antes de llegar a las reglas.` });
    }

    // 2) Conntrack
    let ct = classify(st, pkt);
    if (pkt.stateOverride !== 'AUTO' && pkt.stateOverride !== ct.state) {
      notes.push({ level: 'warn', text: `Estado forzado a ${pkt.stateOverride} (conntrack habría dicho ${ct.state}). En un firewall real el estado no se elige: lo calcula el kernel.` });
      ct = { state: pkt.stateOverride, conn: ct.conn, dir: ct.dir, why: 'forzado a mano' };
    }

    // 3) PREROUTING: DNAT nuevo o deshacer el SNAT de una respuesta
    let dstIp = pkt.dstIp, dstPort = pkt.dstPort;
    let preNat = null;
    if (!local && engine === 'linux') {
      if (ct.conn && ct.dir === 'REPLY' && ct.conn.snat) {
        dstIp = ct.conn.orig.src; dstPort = ct.conn.orig.sport;
        preNat = { type: 'de-SNAT', from: `${pkt.dstIp}${portSuffix(pkt, pkt.dstPort)}`, to: `${dstIp}${portSuffix(pkt, dstPort)}` };
      } else if (ct.conn && ct.dir === 'ORIGINAL' && ct.conn.dnat) {
        dstIp = ct.conn.reply.src; dstPort = ct.conn.reply.sport;
        preNat = { type: 'DNAT', from: `${pkt.dstIp}${portSuffix(pkt, pkt.dstPort)}`, to: `${dstIp}${portSuffix(pkt, dstPort)}`, ruleId: ct.conn.dnatRule };
      } else if (!ct.conn && ct.state === 'NEW' && inIface === 'WAN' && pkt.dstIp === WAN_IP && pkt.protocol !== 'ICMP') {
        const d = st.nat.dnat.find((x) => x.enabled && x.proto === pkt.protocol && x.port === pkt.dstPort);
        if (d) {
          dstIp = d.toIp; dstPort = d.toPort;
          preNat = { type: 'DNAT', from: `${pkt.dstIp}:${pkt.dstPort}`, to: `${dstIp}:${dstPort}`, ruleId: d.id, isNew: true };
        }
      }
    }

    // 4) Decisión de enrutamiento
    let chain, outIface = null;
    if (local) {
      chain = 'OUTPUT';
      outIface = zoneOf(dstIp);
    } else if (isFirewallIp(dstIp)) {
      chain = 'INPUT';
      if (firewallZoneOf(dstIp) !== inIface) notes.push({ level: 'info', text: `El paquete entra por ${IFACES[inIface].dev} pero va a la IP de ${IFACES[firewallZoneOf(dstIp)].dev}: Linux lo acepta igual (modelo de host débil) y lo entrega por INPUT.` });
    } else {
      chain = 'FORWARD';
      outIface = zoneOf(dstIp);
      if (outIface === inIface) notes.push({ level: 'warn', text: `Entra y sale por la misma interfaz (${IFACES[inIface].dev}): el firewall solo haría de puente. Revisa las IP.` });
    }
    if (!local && inIface === 'WAN' && !preNat && isPrivateIp(dstIp) && !ct.conn) {
      notes.push({ level: 'info', text: `Desde Internet no se enruta hacia IP privadas como ${dstIp}: el atacante real apuntaría a la IP pública ${WAN_IP}. El simulador lo procesa igual para que veas qué haría el firewall (p. ej., un atacante en el mismo segmento del proveedor).` });
    }

    const view = {
      chain, inIface: chain === 'OUTPUT' ? null : inIface, outIface: chain === 'INPUT' ? null : outIface,
      protocol: pkt.protocol, srcIp: pkt.srcIp, srcPort: pkt.srcPort, dstIp, dstPort, ctstate: ct.state,
    };

    // 5) Filtrado
    const rules = rulesOf(st);
    const steps = [];
    let matched = null, action, decidedBy, notApplicable = false;
    if (engine === 'linux') {
      for (const r of rules) {
        if (!r.enabled) { steps.push({ ruleId: r.id, matched: false, skipped: true, why: 'regla desactivada' }); continue; }
        if (matched) { steps.push({ ruleId: r.id, matched: false, skipped: true, why: 'no se evalúa: ya ganó una regla anterior' }); continue; }
        const m = matchRuleLinux(r, view);
        steps.push({ ruleId: r.id, matched: m.ok, skipped: r.chain !== chain, why: m.why });
        if (m.ok) matched = r;
      }
      action = matched ? matched.action : st.policies.linux[chain];
      decidedBy = matched ? 'rule' : 'policy';
    } else {
      if (chain === 'FORWARD') {
        notApplicable = true;
        action = 'ACCEPT';
        decidedBy = 'n/a';
        for (const r of rules) steps.push({ ruleId: r.id, matched: false, skipped: true, why: 'Windows Defender Firewall no filtra tráfico enrutado' });
      } else if (ct.state === 'ESTABLISHED' || ct.state === 'RELATED') {
        action = 'ACCEPT';
        decidedBy = 'stateful';
        for (const r of rules) steps.push({ ruleId: r.id, matched: false, skipped: true, why: 'no se evalúa: tráfico de una conexión ya permitida' });
      } else {
        const hits = [];
        for (const r of rules) {
          if (!r.enabled) { steps.push({ ruleId: r.id, matched: false, skipped: true, why: 'regla desactivada' }); continue; }
          const m = matchRuleWindows(r, view, st.windowsProfile);
          steps.push({ ruleId: r.id, matched: m.ok, skipped: r.chain !== chain, why: m.why });
          if (m.ok) hits.push(r);
        }
        const block = hits.find((r) => r.action !== 'ACCEPT');
        const allow = hits.find((r) => r.action === 'ACCEPT');
        if (block) { matched = block; action = 'DROP'; decidedBy = 'block'; }
        else if (allow) { matched = allow; action = 'ACCEPT'; decidedBy = 'allow'; }
        else { action = st.policies.windows[chain]; decidedBy = 'policy'; }
        for (const s of steps) s.winner = matched && s.ruleId === matched.id;
        if (block && allow) notes.push({ level: 'info', text: `También coincidía la regla de permiso #${allow.id} («${allow.name}»), pero en Windows el bloqueo explícito siempre gana, esté donde esté en la lista.` });
        if (block && block.action === 'REJECT') notes.push({ level: 'info', text: 'Windows no tiene REJECT: las reglas de bloqueo descartan en silencio.' });
      }
    }

    // Respuesta del firewall al rechazar
    let response = 'none';
    if (action === 'REJECT') response = (pkt.protocol === 'TCP' && matched && matched.protocol === 'TCP') ? 'tcp-reset' : 'icmp-port-unreachable';
    if (action === 'REJECT' && pkt.protocol === 'TCP' && response !== 'tcp-reset') {
      notes.push({ level: 'info', text: 'REJECT sin «-p tcp» responde con ICMP port-unreachable, no con RST. Nmap -sS verá el puerto como filtered, no closed. Para un RST hace falta una regla TCP con --reject-with tcp-reset.' });
    }

    // 6) POSTROUTING: SNAT/MASQUERADE o deshacer el DNAT en las respuestas
    let postNat = null;
    let srcAfter = pkt.srcIp, sportAfter = pkt.srcPort;
    const accepted = action === 'ACCEPT';
    if (accepted && engine === 'linux') {
      if (ct.conn && ct.dir === 'REPLY' && ct.conn.dnat) {
        srcAfter = ct.conn.orig.dst; sportAfter = ct.conn.orig.dport;
        postNat = { type: 'de-DNAT', from: `${pkt.srcIp}${portSuffix(pkt, pkt.srcPort)}`, to: `${srcAfter}${portSuffix(pkt, sportAfter)}` };
      } else if (ct.conn && ct.dir === 'ORIGINAL' && ct.conn.snat) {
        srcAfter = ct.conn.reply.dst; sportAfter = ct.conn.reply.dport;
        postNat = { type: 'SNAT', from: `${pkt.srcIp}${portSuffix(pkt, pkt.srcPort)}`, to: `${srcAfter}${portSuffix(pkt, sportAfter)}` };
      } else if (!ct.conn && ct.state === 'NEW' && chain === 'FORWARD' && outIface === 'WAN' && st.nat.masquerade &&
        st.nat.masqNets.some((n) => ipInSpec(pkt.srcIp, n))) {
        const wantPort = pkt.protocol === 'ICMP' ? pkt.icmpId : pkt.srcPort;
        const alloc = allocateNatPort(st, wantPort, pkt.protocol, dstIp, pkt.protocol === 'ICMP' ? pkt.icmpId : dstPort);
        srcAfter = WAN_IP; sportAfter = alloc.port;
        postNat = { type: 'MASQUERADE', from: `${pkt.srcIp}${portSuffix(pkt, pkt.srcPort)}`, to: `${WAN_IP}${portSuffix(pkt, alloc.port)}`, portChanged: alloc.changed, isNew: true };
      }
    }

    // 7) Actualizar conntrack y contadores
    const frame = buildPacket(st, pkt, inIface, local);
    let conn = ct.conn || null;
    if (!opts.dryRun) {
      if (matched) { matched.packets += 1; matched.bytes += frame.ipLen; }
      if (accepted) {
        if (conn) {
          if (ct.dir === 'REPLY' && !conn.seenReply) { conn.seenReply = true; conn.status = 'ASSURED'; }
          conn.timeout = timeoutFor(conn.proto, true);
        } else if (ct.state === 'NEW' && !notApplicable) {
          const isIcmp = pkt.protocol === 'ICMP';
          const origT = isIcmp ? { src: pkt.srcIp, sport: pkt.icmpId, dst: pkt.dstIp, dport: pkt.icmpId } : { src: pkt.srcIp, sport: pkt.srcPort, dst: pkt.dstIp, dport: pkt.dstPort };
          const masq = !!(postNat && postNat.type === 'MASQUERADE');
          const replySrc = dstIp;
          const replyDst = masq ? srcAfter : pkt.srcIp;
          const replyDport = masq ? sportAfter : (isIcmp ? pkt.icmpId : pkt.srcPort);
          // En ICMP la «tupla» usa el identificador del echo en los dos lados (traducido si hay NAT).
          const replySport = isIcmp ? replyDport : dstPort;
          conn = {
            id: st.ctSeq++, proto: pkt.protocol,
            orig: origT,
            reply: { src: replySrc, sport: replySport, dst: replyDst, dport: replyDport },
            seenReply: false, status: 'UNREPLIED',
            snat: !!(postNat && postNat.type === 'MASQUERADE'),
            dnat: !!(preNat && preNat.type === 'DNAT'),
            dnatRule: preNat && preNat.ruleId,
            timeout: timeoutFor(pkt.protocol, false),
          };
          st.conntrack.unshift(conn);
          if (st.conntrack.length > 60) st.conntrack.pop();
        }
      }
    }

    const hooks = chain === 'OUTPUT' ? ['OUTPUT'] : ['PREROUTING', 'ROUTING', chain];
    if (accepted && chain !== 'INPUT') hooks.push('POSTROUTING');

    return {
      pkt, engine, chain, inIface: view.inIface, outIface: view.outIface,
      ctstate: ct.state, ctWhy: ct.why, ctDir: ct.dir || null, connId: conn ? conn.id : null,
      preNat, postNat, after: { srcIp: srcAfter, srcPort: sportAfter, dstIp, dstPort },
      steps, matchedRule: matched, action, decidedBy, notApplicable, response,
      policy: engine === 'linux' ? st.policies.linux[chain] : st.policies.windows[chain],
      hooks, notes, frame, explanation: explain(st, { chain, matched, action, decidedBy, notApplicable, ct, inIface: view.inIface, outIface: view.outIface }),
    };
  }

  function portSuffix(pkt, port) {
    return pkt.protocol === 'ICMP' ? '' : `:${port}`;
  }

  function timeoutFor(proto, replied) {
    if (proto === 'TCP') return replied ? 432000 : 120;
    if (proto === 'UDP') return replied ? 120 : 30;
    return 30;
  }

  function explain(st, x) {
    const path = x.chain === 'INPUT' ? `entra por ${IFACES[x.inIface].dev} y va al propio firewall`
      : x.chain === 'OUTPUT' ? `lo genera el propio firewall y sale por ${IFACES[x.outIface].dev}`
        : `entra por ${IFACES[x.inIface].dev} y se enruta hacia ${IFACES[x.outIface].dev}`;
    if (x.notApplicable) return `El paquete ${path}. Windows Defender Firewall es un firewall de host: solo filtra lo que entra o sale del propio equipo, así que este tráfico enrutado no lo evalúa. Apunta el paquete a una IP del equipo (${ZONES.map((z) => IFACES[z].fwIp).join(', ')}).`;
    if (st.engine === 'linux') {
      const head = `Cadena ${x.chain}: el paquete ${path}. Estado conntrack: ${x.ct.state}.`;
      if (x.decidedBy === 'rule') return `${head} Primera coincidencia en la regla #${x.matched.id} («${x.matched.name}») → ${x.action}. Las reglas de debajo ya no se miran.`;
      return `${head} Ninguna regla de ${x.chain} coincide → se aplica la política por defecto de la cadena: ${x.action}.`;
    }
    const dir = x.chain === 'INPUT' ? 'Entrada' : 'Salida';
    const head = `${dir}: el paquete ${path}. Perfil activo: ${st.windowsProfile}.`;
    if (x.decidedBy === 'stateful') return `${head} Pertenece a una conexión ya permitida: Windows deja pasar la respuesta sin mirar las reglas (filtrado con estado).`;
    if (x.decidedBy === 'block') return `${head} Coincide la regla de bloqueo #${x.matched.id} («${x.matched.name}») → bloqueado. En Windows el bloqueo explícito gana a cualquier permiso, sin importar el orden.`;
    if (x.decidedBy === 'allow') return `${head} Coincide la regla de permiso #${x.matched.id} («${x.matched.name}») y ninguna de bloqueo → permitido.`;
    return `${head} Ninguna regla coincide → acción predeterminada de ${dir.toLowerCase()}: ${x.action === 'ACCEPT' ? 'permitir' : 'bloquear'}.`;
  }

  // ==========================================================================
  // CONSTRUCCIÓN DEL PAQUETE REAL (bytes, checksums, volcado)
  // ==========================================================================

  function hash32(str) {
    let h = 0x811c9dc5;
    for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; }
    return h >>> 0;
  }

  function checksum(bytes) {
    let sum = 0;
    for (let i = 0; i < bytes.length; i += 2) sum += (bytes[i] << 8) + (i + 1 < bytes.length ? bytes[i + 1] : 0);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >>> 16);
    return (~sum) & 0xffff;
  }

  function put16(a, o, v) { a[o] = (v >>> 8) & 255; a[o + 1] = v & 255; }
  function put32(a, o, v) { a[o] = (v >>> 24) & 255; a[o + 1] = (v >>> 16) & 255; a[o + 2] = (v >>> 8) & 255; a[o + 3] = v & 255; }
  function ipBytes(ip) { const n = ipToInt(ip); return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]; }
  function macBytes(mac) { return mac.split(':').map((h) => parseInt(h, 16)); }

  function hostMac(ip) {
    const h = hash32('mac' + ip);
    return ['02', ((h >>> 24) & 255), ((h >>> 16) & 255), ((h >>> 8) & 255), (h & 255), 0x10].map((x, i) => (i === 0 ? x : x.toString(16).padStart(2, '0'))).join(':');
  }

  function dnsQuery(id, name) {
    const out = [];
    out.push((id >>> 8) & 255, id & 255, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0);
    for (const label of name.split('.')) { out.push(label.length); for (const ch of label) out.push(ch.charCodeAt(0)); }
    out.push(0, 0, 1, 0, 1);
    return out;
  }

  /** Construye la trama Ethernet + IPv4 + L4 tal como llega (o sale) del firewall, con checksums reales. */
  function buildPacket(st, pkt, inIface, local) {
    const ttl = local ? 64 : (HOSTS[pkt.srcIp] ? HOSTS[pkt.srcIp].ttl : (zoneOf(pkt.srcIp) === 'WAN' ? 52 : 64));
    const flow = `${pkt.protocol}${pkt.srcIp}${pkt.srcPort}${pkt.dstIp}${pkt.dstPort}${pkt.flags || ''}${pkt.icmpType}`;
    const ipId = hash32('id' + flow) & 0xffff;
    let l4 = [];
    let tcpInfo = null, udpInfo = null, icmpInfo = null;
    if (pkt.protocol === 'TCP') {
      const fl = parseTcpFlags(pkt.flags);
      const syn = fl.has('SYN');
      const opts = syn ? [2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 3, 7] : [];
      if (syn) put32(opts, 8, hash32('ts' + flow));
      const hl = 20 + opts.length;
      const seg = new Array(hl).fill(0);
      put16(seg, 0, pkt.srcPort); put16(seg, 2, pkt.dstPort);
      const seq = hash32('seq' + flow), ack = fl.has('ACK') ? hash32('ack' + flow) : 0;
      put32(seg, 4, seq); put32(seg, 8, ack);
      seg[12] = (hl / 4) << 4;
      let fb = 0; for (const f of fl) fb |= TCP_FLAG_BITS[f];
      seg[13] = fb;
      const win = syn ? 64240 : 502;
      put16(seg, 14, win);
      for (let i = 0; i < opts.length; i++) seg[20 + i] = opts[i];
      l4 = seg;
      tcpInfo = { seq, ack, hl, flags: flagsToString(fl), win };
    } else if (pkt.protocol === 'UDP') {
      const payload = pkt.dstPort === 53 ? dnsQuery(hash32('dns' + flow) & 0xffff, 'unfantasmaenelsistema.com') : [];
      const len = 8 + payload.length;
      const seg = new Array(len).fill(0);
      put16(seg, 0, pkt.srcPort); put16(seg, 2, pkt.dstPort); put16(seg, 4, len);
      for (let i = 0; i < payload.length; i++) seg[8 + i] = payload[i];
      l4 = seg;
      udpInfo = { len, dns: pkt.dstPort === 53 };
    } else {
      const isEcho = pkt.icmpType === 8 || pkt.icmpType === 0;
      const payload = [];
      if (isEcho) {
        for (let i = 0; i < 16; i++) payload.push((hash32('t' + flow) >>> ((i % 4) * 8)) & 255);
        for (let i = 0x10; i < 0x38; i++) payload.push(i);
      } else {
        for (let i = 0; i < 28; i++) payload.push(0);
      }
      const seg = new Array(8 + payload.length).fill(0);
      seg[0] = pkt.icmpType; seg[1] = pkt.icmpCode;
      if (isEcho) { put16(seg, 4, pkt.icmpId); put16(seg, 6, 1); }
      for (let i = 0; i < payload.length; i++) seg[8 + i] = payload[i];
      put16(seg, 2, checksum(seg));
      l4 = seg;
      icmpInfo = { type: pkt.icmpType, code: pkt.icmpCode, id: isEcho ? pkt.icmpId : null, seq: isEcho ? 1 : null };
    }
    const protoNum = pkt.protocol === 'TCP' ? 6 : pkt.protocol === 'UDP' ? 17 : 1;
    const ipLen = 20 + l4.length;
    const ip = new Array(20).fill(0);
    ip[0] = 0x45; put16(ip, 2, ipLen); put16(ip, 4, ipId); put16(ip, 6, 0x4000); ip[8] = ttl; ip[9] = protoNum;
    const s = ipBytes(pkt.srcIp), d = ipBytes(pkt.dstIp);
    for (let i = 0; i < 4; i++) { ip[12 + i] = s[i]; ip[16 + i] = d[i]; }
    const ipSum = checksum(ip);
    put16(ip, 10, ipSum);
    if (pkt.protocol !== 'ICMP') {
      const pseudo = [...s, ...d, 0, protoNum, (l4.length >>> 8) & 255, l4.length & 255, ...l4];
      let c = checksum(pseudo);
      if (pkt.protocol === 'UDP' && c === 0) c = 0xffff;
      put16(l4, pkt.protocol === 'TCP' ? 16 : 6, c);
    }
    const ifc = local ? IFACES[zoneOf(pkt.dstIp)] : IFACES[inIface];
    const srcMac = local ? ifc.mac : hostMac(pkt.srcIp);
    const dstMac = local ? hostMac(pkt.dstIp) : ifc.mac;
    const eth = [...macBytes(dstMac), ...macBytes(srcMac), 0x08, 0x00];
    const bytes = [...eth, ...ip, ...l4];
    const l4sum = pkt.protocol === 'ICMP' ? (l4[2] << 8) | l4[3] : pkt.protocol === 'TCP' ? (l4[16] << 8) | l4[17] : (l4[6] << 8) | l4[7];
    return {
      bytes, srcMac, dstMac, ipLen, ttl, ipId, ipSum, protoNum, l4sum,
      tcp: tcpInfo, udp: udpInfo, icmp: icmpInfo, dev: ifc.dev,
    };
  }

  function hexdump(bytes) {
    const lines = [];
    for (let o = 0; o < bytes.length; o += 16) {
      const row = bytes.slice(o, o + 16);
      const hex = row.map((b) => b.toString(16).padStart(2, '0'));
      const left = hex.slice(0, 8).join(' '), right = hex.slice(8).join(' ');
      const ascii = row.map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.')).join('');
      lines.push(`${o.toString(16).padStart(4, '0')}  ${(left + (right ? '  ' + right : '')).padEnd(48)}  ${ascii}`);
    }
    return lines.join('\n');
  }

  // ==========================================================================
  // REGISTROS (formato iptables LOG y pfirewall.log)
  // ==========================================================================

  function pad2(n) { return String(n).padStart(2, '0'); }

  function iptablesLogLine(res, date) {
    const d = date || new Date();
    const f = res.frame, p = res.pkt;
    const tag = res.matchedRule ? `CFW r${res.matchedRule.id} ${res.action}` : `CFW ${res.chain} policy ${res.action}`;
    const ttl = res.chain === 'FORWARD' ? f.ttl - 1 : f.ttl;
    const inDev = res.inIface ? IFACES[res.inIface].dev : '';
    const outDev = res.outIface ? IFACES[res.outIface].dev : '';
    const mac = res.inIface ? ` MAC=${f.dstMac}:${f.srcMac}:08:00` : '';
    let l4 = '';
    if (p.protocol === 'TCP') {
      const fl = parseTcpFlags(p.flags);
      l4 = `PROTO=TCP SPT=${p.srcPort} DPT=${p.dstPort} WINDOW=${f.tcp.win} RES=0x00 ${['URG', 'ACK', 'PSH', 'RST', 'SYN', 'FIN'].filter((x) => fl.has(x)).join(' ')} URGP=0`;
    } else if (p.protocol === 'UDP') {
      l4 = `PROTO=UDP SPT=${p.srcPort} DPT=${p.dstPort} LEN=${f.udp.len}`;
    } else {
      l4 = `PROTO=ICMP TYPE=${p.icmpType} CODE=${p.icmpCode}${f.icmp.id !== null ? ` ID=${f.icmp.id} SEQ=${f.icmp.seq}` : ''}`;
    }
    const ts = `${d.toDateString().slice(4, 10)} ${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
    return `${ts} fw kernel: [${tag}] IN=${inDev} OUT=${outDev}${mac} SRC=${p.srcIp} DST=${p.dstIp} LEN=${f.ipLen} TOS=0x00 PREC=0x00 TTL=${ttl} ID=${f.ipId} DF ${l4}`;
  }

  function pfirewallLogLine(res, date) {
    const d = date || new Date();
    const p = res.pkt, f = res.frame;
    const ts = `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
    const action = res.action === 'ACCEPT' ? 'ALLOW' : 'DROP';
    const ports = p.protocol === 'ICMP' ? '- -' : `${p.srcPort} ${p.dstPort}`;
    let tcp = '- - - -';
    if (p.protocol === 'TCP') {
      const fl = parseTcpFlags(p.flags);
      const letters = [['SYN', 'S'], ['ACK', 'A'], ['FIN', 'F'], ['RST', 'R'], ['PSH', 'P'], ['URG', 'U']].filter(([k]) => fl.has(k)).map(([, v]) => v).join('');
      tcp = `${letters} ${f.tcp.seq} ${f.tcp.ack} ${f.tcp.win}`;
    }
    const icmp = p.protocol === 'ICMP' ? `${p.icmpType} ${p.icmpCode}` : '- -';
    const path = res.chain === 'OUTPUT' ? 'SEND' : 'RECEIVE';
    return `${ts} ${action} ${p.protocol} ${p.srcIp} ${p.dstIp} ${ports} ${f.ipLen} ${tcp} ${icmp} - ${path}`;
  }

  // ==========================================================================
  // RESPUESTAS Y CONEXIONES COMPLETAS (para Nmap, retos y auditoría)
  // ==========================================================================

  /** Paquete que devolvería el equipo de destino (o el firewall al rechazar). */
  function responseFor(st, res, kind) {
    const p = res.pkt;
    const to = res.postNat ? { ip: res.after.srcIp, port: res.after.srcPort } : { ip: p.srcIp, port: p.srcPort };
    const from = { ip: res.after.dstIp, port: res.after.dstPort };
    if (kind === 'icmp-unreach') {
      // Error ICMP generado por el destino: viaja con la cabecera del paquete original embebida.
      const inner = res.connId ? connTupleForInner(st, res) : { proto: p.protocol, src: p.srcIp, sport: p.srcPort, dst: p.dstIp, dport: p.dstPort };
      return { protocol: 'ICMP', icmpType: 3, icmpCode: 3, srcIp: from.ip, dstIp: to.ip, inner };
    }
    if (p.protocol === 'ICMP') return { protocol: 'ICMP', icmpType: 0, icmpCode: 0, icmpId: res.postNat ? res.after.srcPort : p.icmpId, srcIp: from.ip, dstIp: to.ip };
    const flags = kind === 'syn-ack' ? 'SYN,ACK' : kind === 'rst' ? 'RST,ACK' : 'ACK';
    return { protocol: p.protocol, flags, srcIp: from.ip, srcPort: from.port, dstIp: to.ip, dstPort: to.port };
  }

  function connTupleForInner(st, res) {
    const c = st.conntrack.find((x) => x.id === res.connId);
    if (!c) return { proto: res.pkt.protocol, src: res.pkt.srcIp, sport: res.pkt.srcPort, dst: res.pkt.dstIp, dport: res.pkt.dstPort };
    // El error lo genera el destino real con el paquete ya traducido: tupla de respuesta invertida
    return { proto: c.proto, src: c.reply.dst, sport: c.reply.dport, dst: c.reply.src, dport: c.reply.sport };
  }

  /**
   * Simula un intento completo (ida y, si procede, vuelta) sobre una copia del estado.
   * Devuelve { fwd, back, host, outcome } con outcome:
   *   'connected' | 'refused-host' | 'refused-fw' | 'blocked' | 'reply-blocked' | 'no-host' | 'icmp-fw'
   */
  function tryConnection(st, input) {
    const s = cloneState(st);
    s.conntrack = s.conntrack || [];
    const fwd = processPacket(s, Object.assign({ stateOverride: 'AUTO', inIface: 'AUTO' }, input));
    if (fwd.errors) return { errors: fwd.errors };
    const proto = fwd.pkt.protocol;
    if (fwd.action === 'DROP') return { fwd, outcome: 'blocked' };
    if (fwd.action === 'REJECT') return { fwd, outcome: fwd.response === 'tcp-reset' ? 'refused-fw' : 'icmp-fw' };
    const host = hostAt(s, fwd.after.dstIp);
    if (!host) return { fwd, outcome: 'no-host' };
    let kind;
    if (proto === 'TCP') {
      const fl = parseTcpFlags(fwd.pkt.flags);
      if (fl.has('SYN') && !fl.has('ACK')) kind = isServiceOpen(host, 'TCP', fwd.after.dstPort) ? 'syn-ack' : 'rst';
      else kind = 'rst';
    } else if (proto === 'UDP') {
      kind = isServiceOpen(host, 'UDP', fwd.after.dstPort) ? 'udp' : 'icmp-unreach';
    } else {
      kind = fwd.pkt.icmpType === 8 ? 'echo' : null;
      if (!kind) return { fwd, host, outcome: 'connected' };
    }
    const rp = responseFor(s, fwd, kind);
    if (kind === 'udp') { rp.flags = undefined; }
    const back = processPacket(s, rp);
    const backOk = !back.errors && back.action === 'ACCEPT';
    let outcome;
    if (!backOk) outcome = 'reply-blocked';
    else if (kind === 'syn-ack' || kind === 'udp' || kind === 'echo') outcome = 'connected';
    else outcome = 'refused-host';
    return { fwd, back, host, kind, outcome };
  }

  // ==========================================================================
  // NMAP SIMULADO
  // ==========================================================================

  const NMAP_TCP_PORTS = [21, 22, 23, 53, 80, 135, 443, 445, 3389, 8080];
  const NMAP_UDP_PORTS = [53, 67, 123, 137, 161];
  const SCANNER_IP = { WAN: '198.51.100.99', LAN: '192.168.1.66', DMZ: '172.16.0.66' };

  function nmapScan(st, opts) {
    const target = opts.target, type = opts.type || '-sS', zone = opts.zone || 'WAN';
    const src = SCANNER_IP[zone];
    const isUdp = type === '-sU';
    const ports = opts.ports || (isUdp ? NMAP_UDP_PORTS : NMAP_TCP_PORTS);
    const rows = [];
    let sport = 41234;
    for (const port of ports) {
      sport += 7;
      const input = isUdp
        ? { protocol: 'UDP', srcIp: src, srcPort: sport, dstIp: target, dstPort: port }
        : { protocol: 'TCP', srcIp: src, srcPort: sport, dstIp: target, dstPort: port, flags: type === '-sA' ? 'ACK' : 'SYN' };
      const t = tryConnection(st, input);
      if (t.errors) return { errors: t.errors };
      rows.push(Object.assign({ port, proto: isUdp ? 'udp' : 'tcp', service: SERVICE_NAMES[port] || 'unknown' }, nmapVerdict(st, t, type)));
    }
    const notes = [];
    if (st.engine === 'windows' && !isFirewallIp(target)) notes.push('En modo Windows el firewall protege al propio equipo: escanea una de sus IP para ver el efecto de las reglas.');
    if (zone === 'WAN' && isPrivateIp(target)) notes.push(`Desde Internet no se llega a IP privadas (${target}); un atacante real escanearía ${WAN_IP}.`);
    return { target, type, zone, src, rows, notes, command: `nmap -Pn ${type} --reason -p ${ports.join(',')} ${target}` };
  }

  function nmapVerdict(st, t, type) {
    const fwTtl = 64;
    const hostTtl = (t.host ? t.host.ttl : 64) - (t.fwd.chain === 'FORWARD' ? 1 : 0);
    const isUdp = type === '-sU';
    const isAck = type === '-sA';
    const why = (s) => s;
    switch (t.outcome) {
      case 'blocked':
        return isUdp ? { state: 'open|filtered', reason: 'no-response', why: why(`${dropWho(t)}: Nmap no recibe nada y no puede distinguir abierto de filtrado`) }
          : { state: 'filtered', reason: 'no-response', why: why(`${dropWho(t)}: sin respuesta, Nmap agota el tiempo`) };
      case 'refused-fw':
        return isAck ? { state: 'unfiltered', reason: `reset ttl ${fwTtl}`, why: 'REJECT con tcp-reset: el RST lo envía el firewall, pero para -sA cualquier RST significa «sin filtrar»' }
          : { state: 'closed', reason: `reset ttl ${fwTtl}`, why: `REJECT --reject-with tcp-reset (regla #${t.fwd.matchedRule.id}): el firewall finge que el puerto está cerrado` };
      case 'icmp-fw':
        return isUdp ? { state: 'closed', reason: `port-unreach ttl ${fwTtl}`, why: `REJECT (regla #${t.fwd.matchedRule.id}) devuelve ICMP port-unreachable: para UDP eso es «cerrado»` }
          : { state: 'filtered', reason: `port-unreach ttl ${fwTtl}`, why: `REJECT (regla #${t.fwd.matchedRule.id}) devuelve ICMP port-unreachable: con TCP Nmap lo interpreta como filtrado. En un escaneo real algunos saldrán como no-response: Linux limita cuántos ICMP envía por segundo (net.ipv4.icmp_ratelimit)` };
      case 'no-host':
        return { state: 'filtered', reason: `host-unreach ttl ${fwTtl}`, why: 'El firewall deja pasar el paquete, pero no hay ningún equipo con esa IP' };
      case 'reply-blocked':
        return isUdp ? { state: 'open|filtered', reason: 'no-response', why: 'El sondeo llega, pero la respuesta se bloquea a la vuelta (falta la regla ESTABLISHED,RELATED)' }
          : { state: 'filtered', reason: 'no-response', why: `El sondeo llega, pero la respuesta se descarta a la vuelta en ${t.back.chain} (falta una regla ESTABLISHED,RELATED)` };
      case 'connected':
        return isUdp ? { state: 'open', reason: `udp-response ttl ${hostTtl}`, why: `${t.host.name} responde por UDP` }
          : { state: 'open', reason: `syn-ack ttl ${hostTtl}`, why: `El firewall acepta y ${t.host.name} tiene el servicio escuchando` };
      case 'refused-host':
        if (isAck) return { state: 'unfiltered', reason: `reset ttl ${hostTtl}`, why: 'El ACK atraviesa el firewall (como NEW por tcp_loose) y el equipo responde RST: Nmap solo sabe que no está filtrado' };
        if (isUdp) return { state: 'closed', reason: `port-unreach ttl ${hostTtl}`, why: `${t.host.name} no escucha en ese puerto UDP y responde ICMP port-unreachable (RELATED)` };
        return { state: 'closed', reason: `reset ttl ${hostTtl}`, why: `El firewall acepta, pero en ${t.host.name} no escucha nada: el equipo responde RST` };
      default:
        return { state: 'filtered', reason: 'no-response', why: '' };
    }
  }

  function dropWho(t) {
    const r = t.fwd.matchedRule;
    if (t.fwd.engine === 'windows') return r ? `Bloqueado por la regla #${r.id}` : 'Bloqueado por la acción predeterminada de entrada';
    return r ? `DROP en la regla #${r.id}` : `política ${t.fwd.policy} de ${t.fwd.chain}`;
  }

  function nmapReport(scan, date) {
    const d = date || new Date();
    const ts = `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
    const w = Math.max(8, ...scan.rows.map((r) => `${r.port}/${r.proto}`.length + 1));
    const sw = Math.max(9, ...scan.rows.map((r) => r.state.length + 1));
    const vw = Math.max(8, ...scan.rows.map((r) => r.service.length + 1));
    const lines = [
      `$ ${scan.type === '-sS' || scan.type === '-sA' || scan.type === '-sU' ? 'sudo ' : ''}${scan.command}`,
      `Starting Nmap 7.94 ( https://nmap.org ) at ${ts}`,
      `Nmap scan report for ${scan.target}`,
      'Host is up, received user-set.',
      '',
      `${'PORT'.padEnd(w)}${'STATE'.padEnd(sw)}${'SERVICE'.padEnd(vw)}REASON`,
      ...scan.rows.map((r) => `${`${r.port}/${r.proto}`.padEnd(w)}${r.state.padEnd(sw)}${r.service.padEnd(vw)}${r.reason}`),
      '',
      `Nmap done: 1 IP address (1 host up) scanned (simulación de CyberFirewall Lab)`,
    ];
    return lines.join('\n');
  }

  // ==========================================================================
  // GENERADORES DE CONFIGURACIÓN REAL
  // ==========================================================================

  function safeComment(name, max) {
    return String(name).replace(/[^\p{L}\p{N} .,:;()\/_+-]/gu, '').replace(/\s+/g, ' ').trim().slice(0, max || 200) || 'regla';
  }

  function iptPorts(spec) {
    return parsePortSpec(spec).ranges.map(([a, b]) => (a === b ? `${a}` : `${a}:${b}`)).join(',');
  }

  function nftPorts(spec) {
    const r = parsePortSpec(spec).ranges.map(([a, b]) => (a === b ? `${a}` : `${a}-${b}`));
    return r.length > 1 ? `{ ${r.join(', ')} }` : r[0];
  }

  function iptablesRule(r) {
    const a = [`iptables -A ${r.chain}`];
    if (r.inIface !== 'ANY') a.push(`-i ${IFACES[r.inIface].dev}`);
    if (r.outIface !== 'ANY') a.push(`-o ${IFACES[r.outIface].dev}`);
    if (r.protocol !== 'ANY') a.push(`-p ${r.protocol.toLowerCase()}`);
    if (r.srcIp !== 'ANY') a.push(`-s ${r.srcIp}`);
    if (r.dstIp !== 'ANY') a.push(`-d ${r.dstIp}`);
    for (const [spec, one, multi] of [[r.srcPort, '--sport', '--sports'], [r.dstPort, '--dport', '--dports']]) {
      if (parsePortSpec(spec).any) continue;
      if (portSpecIsMulti(spec)) a.push(`-m multiport ${multi} ${iptPorts(spec)}`);
      else a.push(`${one} ${iptPorts(spec)}`);
    }
    if (r.state !== 'ANY') a.push(`-m conntrack --ctstate ${parseStateSpec(r.state).states.join(',')}`);
    a.push(`-m comment --comment "${safeComment(r.name)}"`);
    a.push(`-j ${r.action}`);
    if (r.action === 'REJECT') a.push(r.protocol === 'TCP' ? '--reject-with tcp-reset' : '--reject-with icmp-port-unreachable');
    return a.join(' ');
  }

  function genIptables(st) {
    const P = st.policies.linux;
    const L = [
      '#!/bin/sh',
      '# CyberFirewall Lab — reglas iptables generadas desde el simulador',
      `# Interfaces: eth0=WAN (${WAN_IP}), eth1=LAN (${IFACES.LAN.net}), eth2=DMZ (${IFACES.DMZ.net})`,
      '# Revísalas y adáptalas a tus interfaces antes de aplicarlas. Ejecutar como root.',
      'set -e',
      '',
      '# 1. Vaciar reglas y contadores',
      'iptables -F', 'iptables -X', 'iptables -Z', 'iptables -t nat -F', 'iptables -t nat -X',
      '',
      '# 2. Políticas por defecto (lo que pasa si ninguna regla coincide)',
      `iptables -P INPUT ${P.INPUT}`, `iptables -P FORWARD ${P.FORWARD}`, `iptables -P OUTPUT ${P.OUTPUT}`,
      '',
      '# 3. Loopback (el simulador no lo modela, pero sin esto muchos servicios locales fallan)',
      'iptables -A INPUT -i lo -j ACCEPT',
      '',
      '# 4. Reglas de filtrado (dentro de cada cadena, la primera que coincide gana)',
    ];
    for (const r of st.rules.linux) L.push(r.enabled ? iptablesRule(r) : `# [desactivada] ${iptablesRule(r)}`);
    const nat = natLines(st, 'iptables');
    if (nat.length) L.push('', '# 5. NAT', ...nat);
    L.push('', '# 6. Activar el enrutamiento entre interfaces', 'sysctl -w net.ipv4.ip_forward=1');
    return L.join('\n');
  }

  function natLines(st, kind) {
    const out = [];
    for (const d of st.nat.dnat) {
      if (!d.enabled) continue;
      if (kind === 'iptables') out.push(`iptables -t nat -A PREROUTING -i eth0 -d ${WAN_IP} -p ${d.proto.toLowerCase()} --dport ${d.port} -j DNAT --to-destination ${d.toIp}:${d.toPort}`);
      else out.push(`        iifname "eth0" ip daddr ${WAN_IP} ${d.proto.toLowerCase()} dport ${d.port} dnat to ${d.toIp}:${d.toPort}`);
    }
    if (st.nat.masquerade) {
      for (const n of st.nat.masqNets) {
        if (kind === 'iptables') out.push(`iptables -t nat -A POSTROUTING -o eth0 -s ${n} -j MASQUERADE`);
        else out.push(`        oifname "eth0" ip saddr ${n} masquerade`);
      }
    }
    return out;
  }

  function nftRule(r) {
    const t = [];
    if (r.inIface !== 'ANY') t.push(`iifname "${IFACES[r.inIface].dev}"`);
    if (r.outIface !== 'ANY') t.push(`oifname "${IFACES[r.outIface].dev}"`);
    if (r.srcIp !== 'ANY') t.push(`ip saddr ${r.srcIp}`);
    if (r.dstIp !== 'ANY') t.push(`ip daddr ${r.dstIp}`);
    const p = r.protocol.toLowerCase();
    const sp = !parsePortSpec(r.srcPort).any, dp = !parsePortSpec(r.dstPort).any;
    if (r.protocol !== 'ANY') {
      if (!sp && !dp) t.push(`meta l4proto ${p}`);
      if (sp) t.push(`${p} sport ${nftPorts(r.srcPort)}`);
      if (dp) t.push(`${p} dport ${nftPorts(r.dstPort)}`);
    }
    if (r.state !== 'ANY') {
      const s = parseStateSpec(r.state).states.map((x) => x.toLowerCase());
      t.push(`ct state ${s.length > 1 ? `{ ${s.join(', ')} }` : s[0]}`);
    }
    t.push('counter');
    if (r.action === 'REJECT') t.push(r.protocol === 'TCP' ? 'reject with tcp reset' : 'reject');
    else t.push(r.action.toLowerCase());
    t.push(`comment "${safeComment(r.name, 120)}"`);
    return t.join(' ');
  }

  function genNftables(st) {
    const P = st.policies.linux;
    const L = [
      '#!/usr/sbin/nft -f',
      '# CyberFirewall Lab — reglas nftables generadas desde el simulador',
      '# Comprobar sin aplicar: nft -c -f reglas.nft',
      'flush ruleset',
      '',
      'table inet filter {',
    ];
    for (const ch of CHAINS) {
      L.push(`    chain ${ch.toLowerCase()} {`);
      L.push(`        type filter hook ${ch.toLowerCase()} priority filter; policy ${P[ch].toLowerCase()};`);
      if (ch === 'INPUT') L.push('        iif "lo" accept');
      for (const r of st.rules.linux.filter((x) => x.chain === ch)) L.push(`        ${r.enabled ? '' : '# [desactivada] '}${nftRule(r)}`);
      L.push('    }');
    }
    L.push('}');
    const nat = natLines(st, 'nft');
    if (nat.length) {
      L.push('', 'table ip nat {');
      L.push('    chain prerouting {', '        type nat hook prerouting priority dstnat; policy accept;');
      L.push(...nat.filter((x) => x.includes('dnat')), '    }');
      L.push('    chain postrouting {', '        type nat hook postrouting priority srcnat; policy accept;');
      L.push(...nat.filter((x) => x.includes('masquerade')), '    }', '}');
    }
    return L.join('\n');
  }

  function psQuote(s) { return `'${String(s).replace(/'/g, "''")}'`; }

  function winAddrPorts(r) {
    // En Windows las reglas hablan de equipo local y remoto, no de origen y destino.
    const inbound = r.chain === 'INPUT';
    return {
      local: inbound ? r.dstIp : r.srcIp, remote: inbound ? r.srcIp : r.dstIp,
      lport: inbound ? r.dstPort : r.srcPort, rport: inbound ? r.srcPort : r.dstPort,
    };
  }

  function winPorts(spec) {
    return parsePortSpec(spec).ranges.map(([a, b]) => (a === b ? `${a}` : `${a}-${b}`)).join(',');
  }

  function genPowerShell(st) {
    const P = st.policies.windows;
    const L = [
      '# CyberFirewall Lab — reglas de Windows Defender Firewall',
      '# Ejecutar en PowerShell como Administrador. Prueba antes añadiendo -WhatIf a cada línea.',
      `Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction ${P.INPUT === 'ACCEPT' ? 'Allow' : 'Block'} -DefaultOutboundAction ${P.OUTPUT === 'ACCEPT' ? 'Allow' : 'Block'}`,
      '',
    ];
    for (const r of st.rules.windows) {
      if (r.chain === 'FORWARD') { L.push(`# Omitida (#${r.id}): Windows Defender Firewall no tiene cadena FORWARD`); continue; }
      const a = winAddrPorts(r);
      const args = [
        'New-NetFirewallRule', `-DisplayName ${psQuote(`CFW ${r.id} - ${safeComment(r.name, 100)}`)}`, `-Group ${psQuote('CyberFirewall Lab')}`,
        `-Direction ${r.chain === 'INPUT' ? 'Inbound' : 'Outbound'}`, `-Action ${r.action === 'ACCEPT' ? 'Allow' : 'Block'}`,
        `-Profile ${r.profile}`, `-Enabled ${r.enabled ? 'True' : 'False'}`,
      ];
      if (r.protocol !== 'ANY') args.push(`-Protocol ${r.protocol === 'ICMP' ? 'ICMPv4' : r.protocol}`);
      if (a.local !== 'ANY') args.push(`-LocalAddress ${a.local}`);
      if (a.remote !== 'ANY') args.push(`-RemoteAddress ${a.remote}`);
      if (!parsePortSpec(a.lport).any) args.push(`-LocalPort ${winPorts(a.lport)}`);
      if (!parsePortSpec(a.rport).any) args.push(`-RemotePort ${winPorts(a.rport)}`);
      L.push(args.join(' '));
    }
    return L.join('\n');
  }

  function genNetsh(st) {
    const P = st.policies.windows;
    const L = [
      'REM CyberFirewall Lab — reglas para netsh advfirewall (CMD como Administrador)',
      `netsh advfirewall set allprofiles firewallpolicy ${P.INPUT === 'ACCEPT' ? 'allowinbound' : 'blockinbound'},${P.OUTPUT === 'ACCEPT' ? 'allowoutbound' : 'blockoutbound'}`,
      '',
    ];
    for (const r of st.rules.windows) {
      if (r.chain === 'FORWARD') { L.push(`REM Omitida (#${r.id}): no existe FORWARD en Windows Defender Firewall`); continue; }
      const a = winAddrPorts(r);
      const args = [
        'netsh advfirewall firewall add rule', `name="CFW ${r.id} - ${safeComment(r.name, 100)}"`,
        `dir=${r.chain === 'INPUT' ? 'in' : 'out'}`, `action=${r.action === 'ACCEPT' ? 'allow' : 'block'}`,
        `enable=${r.enabled ? 'yes' : 'no'}`, `profile=${r.profile.toLowerCase()}`,
        `protocol=${r.protocol === 'ANY' ? 'any' : r.protocol === 'ICMP' ? 'icmpv4' : r.protocol.toLowerCase()}`,
      ];
      if (a.local !== 'ANY') args.push(`localip=${a.local}`);
      if (a.remote !== 'ANY') args.push(`remoteip=${a.remote}`);
      if (!parsePortSpec(a.lport).any) args.push(`localport=${winPorts(a.lport)}`);
      if (!parsePortSpec(a.rport).any) args.push(`remoteport=${winPorts(a.rport)}`);
      L.push(args.join(' '));
    }
    return L.join('\n');
  }

  // ==========================================================================
  // AUDITORÍA DE BUENAS PRÁCTICAS
  // ==========================================================================

  function probe(st, input) {
    const s = cloneState(st);
    s.conntrack = [];
    return tryConnection(s, input);
  }

  const reached = (t) => t.outcome === 'connected' || t.outcome === 'refused-host' || t.outcome === 'reply-blocked' || t.outcome === 'no-host';

  function audit(st) {
    const checks = [];
    const add = (id, weight, ok, title, desc, level) => checks.push({ id, weight, status: ok ? 'PASS' : (level || 'FAIL'), title, desc });
    if (st.engine === 'linux') {
      const P = st.policies.linux;
      add('pol-input', 15, P.INPUT === 'DROP', 'Política de INPUT en DROP', P.INPUT === 'DROP' ? 'Lo que no esté permitido hacia el firewall se descarta.' : 'Con ACCEPT, cualquier servicio del firewall que no tenga regla queda expuesto.');
      add('pol-forward', 15, P.FORWARD === 'DROP', 'Política de FORWARD en DROP', P.FORWARD === 'DROP' ? 'El tráfico entre redes solo pasa si una regla lo permite.' : 'Con ACCEPT el firewall enruta todo entre WAN, LAN y DMZ salvo lo que bloquees a mano.');
      const browse = probe(st, { protocol: 'TCP', srcIp: '192.168.1.50', srcPort: 51200, dstIp: '93.184.216.34', dstPort: 443, flags: 'SYN' });
      add('lan-out', 15, browse.outcome === 'connected', 'La LAN navega y recibe las respuestas',
        browse.outcome === 'connected' ? 'Ida aceptada y vuelta aceptada por conntrack (ESTABLISHED).'
          : browse.outcome === 'reply-blocked' ? 'La petición sale pero la respuesta se descarta: falta la regla ESTABLISHED,RELATED en FORWARD (o está por debajo de un DROP).'
            : 'La LAN no puede abrir conexiones a Internet.');
      const wanLan = [445, 3389, 135].map((p) => probe(st, { protocol: 'TCP', srcIp: '198.51.100.99', srcPort: 40000 + p, dstIp: '192.168.1.50', dstPort: p, flags: 'SYN' }));
      const okWanLan = wanLan.every((t) => !reached(t));
      add('wan-lan', 15, okWanLan, 'Internet no puede abrir conexiones hacia la LAN', okWanLan ? 'SMB, RDP y RPC del equipo de la LAN no son alcanzables desde la WAN.' : 'Desde la WAN se llega a servicios de la LAN (probado con 135, 445 y 3389).');
      const ssh = probe(st, { protocol: 'TCP', srcIp: '198.51.100.99', srcPort: 40022, dstIp: WAN_IP, dstPort: 22, flags: 'SYN' });
      add('wan-ssh', 10, !reached(ssh) || (ssh.fwd.preNat), 'SSH del firewall cerrado a Internet', !reached(ssh) ? 'La administración del firewall solo es posible desde dentro.' : 'El SSH del propio firewall responde desde Internet: limítalo a la LAN o a una VPN.');
      const dmzLan = [22, 445, 3389].map((p) => probe(st, { protocol: 'TCP', srcIp: '172.16.0.10', srcPort: 38000 + p, dstIp: '192.168.1.50', dstPort: p, flags: 'SYN' }));
      const okDmz = dmzLan.every((t) => !reached(t));
      add('dmz-lan', 15, okDmz, 'La DMZ no puede abrir conexiones hacia la LAN', okDmz ? 'Si un servidor de la DMZ cae, el atacante no salta desde ahí a la red interna.' : 'Un servidor comprometido de la DMZ llegaría a equipos de la LAN.');
      const dmzSsh = probe(st, { protocol: 'TCP', srcIp: '198.51.100.99', srcPort: 40122, dstIp: '172.16.0.10', dstPort: 22, flags: 'SYN' });
      add('dmz-ssh', 10, !reached(dmzSsh), 'SSH de los servidores de la DMZ no expuesto', !reached(dmzSsh) ? 'Desde Internet solo se ve lo que publicas (web).' : 'El SSH del servidor web de la DMZ es alcanzable desde Internet.');
      const invalid = st.rules.linux.some((r) => r.enabled && r.action !== 'ACCEPT' && parseStateSpec(r.state).states && parseStateSpec(r.state).states.includes('INVALID'));
      add('invalid', 5, invalid, 'Se descartan los paquetes INVALID', invalid ? 'Hay una regla que tira los paquetes que conntrack no sabe asociar.' : 'Recomendado: «-m conntrack --ctstate INVALID -j DROP» al principio de FORWARD e INPUT.', 'WARN');
    } else {
      const P = st.policies.windows;
      add('w-in', 25, P.INPUT === 'DROP', 'Entrada bloqueada por defecto', P.INPUT === 'DROP' ? 'Solo entra lo que tiene una regla de permiso.' : 'Con «Permitir» por defecto, cualquier servicio queda expuesto.');
      const host = WAN_IP;
      const risky = [135, 445, 3389].map((p) => ({ p, t: probe(st, { protocol: 'TCP', srcIp: '198.51.100.99', srcPort: 40000 + p, dstIp: host, dstPort: p, flags: 'SYN' }) }));
      const open = risky.filter((x) => x.t.outcome === 'connected').map((x) => x.p);
      add('w-mgmt', 25, open.length === 0, 'RPC, SMB y RDP no accesibles desde Internet', open.length ? `Responden desde Internet: ${open.join(', ')}. Restringe la IP remota o usa el perfil adecuado.` : 'Los servicios de gestión no responden a una IP pública.');
    }
    const rel = analyzeRules(rulesOf(st), st.engine);
    const bad = Object.keys(rel).length;
    const wide = rulesOf(st).filter((r) => r.enabled && r.action === 'ACCEPT' && r.srcIp === 'ANY' && r.dstIp === 'ANY' && r.protocol === 'ANY' && (st.engine === 'windows' || r.state === 'ANY' || parseStateSpec(r.state).states.includes('NEW')) && (st.engine === 'windows' || r.inIface === 'WAN' || r.inIface === 'ANY') && r.chain !== 'OUTPUT');
    add('wide', 15, wide.length === 0, 'Sin reglas de «permitir todo» desde cualquier origen', wide.length ? `Las reglas ${wide.map((r) => '#' + r.id).join(', ')} aceptan cualquier protocolo desde cualquier IP.` : 'Ninguna regla abre la puerta de par en par.');
    add('dead', 5, bad === 0, st.engine === 'windows' ? 'Sin permisos anulados por bloqueos' : 'Sin reglas sombreadas ni redundantes',
      bad === 0 ? 'Todas las reglas pueden llegar a aplicarse.' : `${bad} regla(s) nunca deciden nada (marcadas en la tabla). Bórralas o reordénalas.`, 'WARN');
    const total = checks.reduce((s, c) => s + c.weight, 0);
    const got = checks.reduce((s, c) => s + (c.status === 'PASS' ? c.weight : 0), 0);
    const score = Math.round((got / total) * 100);
    const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 50 ? 'C' : 'F';
    return { score, grade, checks };
  }

  // ==========================================================================
  // RETOS
  // ==========================================================================

  function conn(st, f) {
    return probe(st, Object.assign({ protocol: 'TCP', flags: 'SYN' }, f));
  }

  const SCENARIOS = [
    {
      id: 1, title: 'Aislar la DMZ', level: 'Intermedio',
      goal: 'La LAN debe usar la web de la DMZ (172.16.0.10:80/443) y recibir las respuestas, pero un servidor de la DMZ comprometido no puede abrir conexiones hacia la LAN. El administrador anterior «arregló» las respuestas con una regla demasiado amplia.',
      hint: 'Las respuestas no necesitan una regla por zona: basta con aceptar ESTABLISHED,RELATED en FORWARD. Sustituye la regla amplia.',
      load(st) {
        st.engine = 'linux';
        st.policies.linux = { INPUT: 'DROP', FORWARD: 'DROP', OUTPUT: 'ACCEPT' };
        st.conntrack = [];
        st.rules.linux = [
          makeRule({ id: 1, name: 'La LAN usa la web de la DMZ', chain: 'FORWARD', inIface: 'LAN', outIface: 'DMZ', protocol: 'TCP', dstIp: '172.16.0.10', dstPort: '80,443', state: 'NEW', action: 'ACCEPT' }),
          makeRule({ id: 2, name: 'Que funcionen las respuestas de la DMZ', chain: 'FORWARD', inIface: 'DMZ', action: 'ACCEPT' }),
        ];
      },
      verify(st) {
        const a = conn(st, { srcIp: '192.168.1.50', srcPort: 51200, dstIp: '172.16.0.10', dstPort: 443 });
        const b = conn(st, { srcIp: '172.16.0.10', srcPort: 38192, dstIp: '192.168.1.50', dstPort: 445 });
        const c = conn(st, { srcIp: '172.16.0.10', srcPort: 38193, dstIp: '192.168.1.50', dstPort: 3389 });
        return [
          { name: 'LAN → web DMZ (443) con respuesta', ok: a.outcome === 'connected', detail: outcomeText(a) },
          { name: 'DMZ → LAN SMB (445) bloqueado', ok: !reached(b), detail: outcomeText(b) },
          { name: 'DMZ → LAN RDP (3389) bloqueado', ok: !reached(c), detail: outcomeText(c) },
        ];
      },
    },
    {
      id: 2, title: 'La trampa del orden (first match)', level: 'Básico',
      goal: 'La web de la DMZ está publicada con DNAT (203.0.113.1:80 → 172.16.0.10:80), pero una regla general de bloqueo está por encima y nadie de Internet llega. Arréglalo solo reordenando: sin borrar ni desactivar reglas.',
      hint: 'En Linux gana la primera regla que coincide. Sube la regla del puerto 80 por encima del bloqueo general.',
      load(st) {
        st.engine = 'linux';
        st.policies.linux = { INPUT: 'DROP', FORWARD: 'DROP', OUTPUT: 'ACCEPT' };
        st.conntrack = [];
        st.nat.dnat = defaultDnat();
        st.rules.linux = [
          makeRule({ id: 1, name: 'Respuestas de conexiones aceptadas', chain: 'FORWARD', state: 'ESTABLISHED,RELATED', action: 'ACCEPT' }),
          makeRule({ id: 2, name: 'Bloqueo general de TCP desde Internet', chain: 'FORWARD', inIface: 'WAN', protocol: 'TCP', action: 'DROP' }),
          makeRule({ id: 3, name: 'Web publicada en la DMZ (puerto 80)', chain: 'FORWARD', inIface: 'WAN', outIface: 'DMZ', protocol: 'TCP', dstIp: '172.16.0.10', dstPort: '80', state: 'NEW', action: 'ACCEPT' }),
        ];
      },
      verify(st) {
        const intact = [1, 2, 3].every((id) => { const r = st.rules.linux.find((x) => x.id === id); return r && r.enabled; });
        const a = conn(st, { srcIp: '198.51.100.20', srcPort: 50500, dstIp: WAN_IP, dstPort: 80 });
        const b = conn(st, { srcIp: '198.51.100.20', srcPort: 50501, dstIp: '172.16.0.10', dstPort: 22 });
        return [
          { name: 'Las tres reglas siguen activas', ok: intact, detail: intact ? 'Nada borrado ni desactivado' : 'Se ha borrado o desactivado alguna regla' },
          { name: 'Internet → 203.0.113.1:80 llega a la web', ok: a.outcome === 'connected', detail: outcomeText(a) },
          { name: 'Internet → SSH de la DMZ sigue bloqueado', ok: !reached(b), detail: outcomeText(b) },
        ];
      },
    },
    {
      id: 3, title: 'Windows: el bloqueo siempre gana', level: 'Intermedio',
      goal: 'En el servidor Windows, RDP (3389) debe estar cerrado a todo el mundo excepto al equipo de administración 198.51.100.10. Hay una regla de permiso para esa IP… pero el administrador sigue sin poder entrar.',
      hint: 'En Windows un bloqueo explícito anula cualquier permiso, esté donde esté. No necesitas bloquear: la acción predeterminada de entrada ya bloquea lo que no está permitido.',
      load(st) {
        st.engine = 'windows';
        st.policies.windows = { INPUT: 'DROP', OUTPUT: 'ACCEPT' };
        st.windowsProfile = 'Public';
        st.conntrack = [];
        st.rules.windows = [
          makeRule({ id: 1, name: 'RDP para el equipo de administración', chain: 'INPUT', protocol: 'TCP', srcIp: '198.51.100.10', dstPort: '3389', action: 'ACCEPT' }),
          makeRule({ id: 2, name: 'Bloquear RDP a todo el mundo', chain: 'INPUT', protocol: 'TCP', dstPort: '3389', action: 'DROP' }),
        ];
      },
      verify(st) {
        const a = conn(st, { srcIp: '198.51.100.10', srcPort: 50000, dstIp: WAN_IP, dstPort: 3389 });
        const b = conn(st, { srcIp: '198.51.100.99', srcPort: 50001, dstIp: WAN_IP, dstPort: 3389 });
        const pol = st.policies.windows.INPUT === 'DROP';
        return [
          { name: 'Acción predeterminada de entrada: bloquear', ok: pol, detail: pol ? 'Correcto' : 'Con «permitir» por defecto todo lo demás quedaría abierto' },
          { name: 'Administración 198.51.100.10 → RDP permitido', ok: a.outcome === 'connected', detail: outcomeText(a) },
          { name: 'Atacante 198.51.100.99 → RDP bloqueado', ok: !reached(b), detail: outcomeText(b) },
        ];
      },
    },
    {
      id: 4, title: 'DNAT: filtra la dirección traducida', level: 'Intermedio',
      goal: 'Publica HTTPS: 203.0.113.1:443 se redirige con DNAT a 172.16.0.10:443. La regla de FORWARD está escrita contra la IP pública y no funciona. Corrígela sin abrir nada más.',
      hint: 'El DNAT ocurre en PREROUTING, antes de FORWARD: cuando el paquete llega a las reglas de filtrado ya lleva el destino 172.16.0.10.',
      load(st) {
        st.engine = 'linux';
        st.policies.linux = { INPUT: 'DROP', FORWARD: 'DROP', OUTPUT: 'ACCEPT' };
        st.conntrack = [];
        st.nat.dnat = [{ id: 1, proto: 'TCP', port: 443, toIp: '172.16.0.10', toPort: 443, enabled: true }];
        st.rules.linux = [
          makeRule({ id: 1, name: 'Respuestas de conexiones aceptadas', chain: 'FORWARD', state: 'ESTABLISHED,RELATED', action: 'ACCEPT' }),
          makeRule({ id: 2, name: 'HTTPS publicado', chain: 'FORWARD', inIface: 'WAN', protocol: 'TCP', dstIp: '203.0.113.1', dstPort: '443', state: 'NEW', action: 'ACCEPT' }),
        ];
      },
      verify(st) {
        const a = conn(st, { srcIp: '198.51.100.20', srcPort: 50600, dstIp: WAN_IP, dstPort: 443 });
        const b = conn(st, { srcIp: '198.51.100.20', srcPort: 50601, dstIp: '172.16.0.10', dstPort: 22 });
        const c = conn(st, { srcIp: '198.51.100.20', srcPort: 50602, dstIp: '192.168.1.50', dstPort: 445 });
        return [
          { name: 'Internet → 203.0.113.1:443 llega a la web', ok: a.outcome === 'connected', detail: outcomeText(a) },
          { name: 'Internet → SSH de la DMZ bloqueado', ok: !reached(b), detail: outcomeText(b) },
          { name: 'Internet → LAN bloqueado', ok: !reached(c), detail: outcomeText(c) },
        ];
      },
    },
  ];

  function outcomeText(t) {
    if (!t || t.errors) return 'error';
    const r = t.fwd.matchedRule;
    const by = r ? `regla #${r.id}` : t.fwd.decidedBy === 'stateful' ? 'filtrado con estado' : `política ${t.fwd.policy}`;
    switch (t.outcome) {
      case 'connected': return `Conecta (ida: ${by}; vuelta aceptada)`;
      case 'refused-host': return `Llega al equipo (ida: ${by}), pero el puerto está cerrado`;
      case 'reply-blocked': return `La ida pasa (${by}) pero la respuesta se descarta en ${t.back.chain}`;
      case 'blocked': return `Descartado en ${t.fwd.chain} (${by})`;
      case 'refused-fw': case 'icmp-fw': return `Rechazado en ${t.fwd.chain} (${by})`;
      case 'no-host': return 'Pasa el firewall, pero no hay equipo con esa IP';
      default: return t.outcome;
    }
  }

  // ==========================================================================
  // IMPORTACIÓN / EXPORTACIÓN
  // ==========================================================================

  function exportConfig(st) {
    const strip = (r) => { const o = Object.assign({}, r); delete o.packets; delete o.bytes; return o; };
    return {
      app: 'CyberFirewall Lab', version: 2,
      engine: st.engine, windowsProfile: st.windowsProfile, policies: st.policies,
      rules: { linux: st.rules.linux.map(strip), windows: st.rules.windows.map(strip) },
      nat: st.nat,
    };
  }

  /** Aplica una configuración importada sobre el estado. Devuelve { ok, errors, warnings }. */
  function importConfig(st, data) {
    const errors = [], warnings = [];
    if (!data || typeof data !== 'object') return { ok: false, errors: ['El archivo no contiene un objeto JSON'] };
    const next = cloneState(st);
    const engineIn = data.engine || data.engineMode;
    if (engineIn !== undefined) {
      if (engineIn !== 'linux' && engineIn !== 'windows') errors.push(`Motor «${engineIn}» desconocido`);
      else next.engine = engineIn;
    }
    const loadList = (list, engine) => {
      if (!Array.isArray(list)) { errors.push(`Las reglas de ${engine} no son una lista`); return null; }
      if (list.length > 200) { errors.push('Demasiadas reglas (máximo 200)'); return null; }
      const out = [];
      const ids = new Set();
      list.forEach((raw, i) => {
        const { rule, errors: e } = normalizeRule(raw, engine);
        if (e.length) { errors.push(`Regla ${i + 1}: ${e.join('; ')}`); return; }
        if (!rule.id || ids.has(rule.id)) rule.id = Math.max(0, ...ids) + 1;
        ids.add(rule.id);
        out.push(rule);
      });
      return out;
    };
    if (Array.isArray(data.rules)) {
      // Formato v1: una sola lista para el motor indicado
      const l = loadList(data.rules, next.engine);
      if (l) next.rules[next.engine] = l;
      warnings.push('Archivo de la versión anterior: se han convertido INBOUND/OUTBOUND a INPUT/OUTPUT y «zona» a interfaz.');
    } else if (data.rules && typeof data.rules === 'object') {
      for (const eng of ['linux', 'windows']) {
        if (data.rules[eng] !== undefined) { const l = loadList(data.rules[eng], eng); if (l) next.rules[eng] = l; }
      }
    } else errors.push('No hay reglas en el archivo');
    const pol = data.policies;
    if (pol && typeof pol === 'object') {
      const okp = (v) => v === 'ACCEPT' || v === 'DROP';
      if (pol.linux) for (const ch of CHAINS) if (pol.linux[ch] !== undefined) { if (okp(pol.linux[ch])) next.policies.linux[ch] = pol.linux[ch]; else errors.push(`Política ${ch} no válida`); }
      if (pol.windows) for (const ch of ['INPUT', 'OUTPUT']) if (pol.windows[ch] !== undefined) { if (okp(pol.windows[ch])) next.policies.windows[ch] = pol.windows[ch]; else errors.push(`Acción predeterminada ${ch} no válida`); }
    } else if (data.defaultPolicy === 'ACCEPT' || data.defaultPolicy === 'DROP') {
      next.policies.linux.INPUT = data.defaultPolicy; next.policies.linux.FORWARD = data.defaultPolicy; next.policies.windows.INPUT = data.defaultPolicy;
    }
    if (data.windowsProfile !== undefined) {
      if (['Domain', 'Private', 'Public'].includes(data.windowsProfile)) next.windowsProfile = data.windowsProfile;
      else errors.push('Perfil de Windows no válido');
    }
    if (data.nat && typeof data.nat === 'object') {
      if (typeof data.nat.masquerade === 'boolean') next.nat.masquerade = data.nat.masquerade;
      if (Array.isArray(data.nat.dnat)) {
        const list = [];
        data.nat.dnat.forEach((d, i) => {
          const e = validateDnat(d);
          if (e.length) errors.push(`DNAT ${i + 1}: ${e.join('; ')}`);
          else list.push({ id: i + 1, proto: d.proto, port: Number(d.port), toIp: d.toIp, toPort: Number(d.toPort), enabled: d.enabled !== false });
        });
        next.nat.dnat = list;
      }
    }
    if (errors.length) return { ok: false, errors, warnings };
    next.conntrack = [];
    Object.assign(st, next);
    return { ok: true, errors, warnings };
  }

  function validateDnat(d) {
    const e = [];
    if (!d || typeof d !== 'object') return ['no es un objeto'];
    if (d.proto !== 'TCP' && d.proto !== 'UDP') e.push('protocolo TCP o UDP');
    const p = Number(d.port), tp = Number(d.toPort);
    if (!Number.isInteger(p) || p < 1 || p > 65535) e.push('puerto público 1-65535');
    if (!Number.isInteger(tp) || tp < 1 || tp > 65535) e.push('puerto interno 1-65535');
    if (ipToInt(String(d.toIp)) === null) e.push('IP interna no válida');
    else if (zoneOf(d.toIp) === 'WAN') e.push('la IP interna debe estar en la LAN o la DMZ');
    else if (isFirewallIp(d.toIp)) e.push('la IP interna no puede ser el propio firewall');
    return e;
  }

  return {
    IFACES, ZONES, WAN_IP, HOSTS, FIREWALL_HOST, SERVICE_NAMES, CHAINS, CT_STATES, SCANNER_IP,
    NMAP_TCP_PORTS, NMAP_UDP_PORTS, SCENARIOS,
    ipToInt, intToIp, parseIpSpec, ipInSpec, parsePortSpec, portInSpec, parseStateSpec, zoneOf, isFirewallIp, isPrivateIp,
    makeRule, validateRule, normalizeRule, analyzeRules, ruleCovers,
    createState, cloneState, rulesOf, nextRuleId, defaultLinuxRules, defaultWindowsRules, defaultDnat,
    normalizePacket, classify, processPacket, tryConnection, responseFor, buildPacket, checksum, hexdump,
    iptablesLogLine, pfirewallLogLine, nmapScan, nmapReport,
    genIptables, genNftables, genPowerShell, genNetsh, safeComment,
    audit, outcomeText, exportConfig, importConfig, validateDnat, parseTcpFlags,
  };
});

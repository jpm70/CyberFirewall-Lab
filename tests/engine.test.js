'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const C = require('../js/engine.js');

const fresh = () => C.createState();
const syn = (src, sport, dst, dport, extra) => Object.assign({ protocol: 'TCP', srcIp: src, srcPort: sport, dstIp: dst, dstPort: dport, flags: 'SYN' }, extra);

test('IP, CIDR y rangos privados', () => {
  assert.equal(C.ipToInt('192.168.1.1'), 3232235777);
  assert.equal(C.ipToInt('256.1.1.1'), null);
  assert.equal(C.ipToInt('1.2.3'), null);
  assert.equal(C.ipToInt('01x.1.1.1'), null);
  assert.ok(C.ipInSpec('192.168.1.45', '192.168.1.0/24'));
  assert.ok(!C.ipInSpec('192.168.2.45', '192.168.1.0/24'));
  assert.ok(C.ipInSpec('10.9.9.9', 'ANY'));
  assert.ok(C.ipInSpec('10.9.9.9', '0.0.0.0/0'));
  assert.equal(C.parseIpSpec('10.0.0.0/33').error !== undefined, true);
  // la v1 consideraba privada cualquier 172.2x.x.x (startsWith('172.2'))
  assert.ok(!C.isPrivateIp('172.2.0.1'));
  assert.ok(!C.isPrivateIp('172.200.0.1'));
  assert.ok(C.isPrivateIp('172.20.0.1'));
  assert.ok(!C.isPrivateIp('172.32.0.1'));
});

test('Puertos: listas, rangos combinados y errores', () => {
  assert.ok(C.portInSpec(8050, '80,8000-8080'));
  assert.ok(!C.portInSpec(81, '80,8000-8080'));
  assert.ok(C.parsePortSpec('70000').error);
  assert.ok(C.parsePortSpec('90-80').error);
  assert.ok(C.parsePortSpec('80;443').error);
  assert.ok(C.parsePortSpec('ANY').any);
});

test('Validación de reglas', () => {
  const ok = C.makeRule({ name: 'x', chain: 'FORWARD', protocol: 'TCP', dstPort: '80' });
  assert.deepEqual(C.validateRule(ok, 'linux'), []);
  assert.ok(C.validateRule(C.makeRule({ name: 'x', protocol: 'ANY', dstPort: '80' }), 'linux').some((e) => /solo existen en TCP y UDP/.test(e)));
  assert.ok(C.validateRule(C.makeRule({ name: 'x', chain: 'OUTPUT', inIface: 'LAN' }), 'linux').length);
  assert.ok(C.validateRule(C.makeRule({ name: 'x', chain: 'FORWARD' }), 'windows').length);
  assert.ok(C.validateRule(C.makeRule({ name: 'x', srcIp: '300.1.1.1' }), 'linux').length);
});

test('Conntrack: clasificación como nf_conntrack (tcp_loose=1)', () => {
  const st = fresh();
  const cls = (p) => C.classify(st, C.normalizePacket(p).pkt).state;
  assert.equal(cls(syn('198.51.100.9', 40000, C.WAN_IP, 22)), 'NEW');
  assert.equal(cls(syn('198.51.100.9', 40000, C.WAN_IP, 22, { flags: 'ACK' })), 'NEW');
  assert.equal(cls(syn('198.51.100.9', 40000, C.WAN_IP, 22, { flags: 'SYN,ACK' })), 'INVALID');
  assert.equal(cls(syn('198.51.100.9', 40000, C.WAN_IP, 22, { flags: 'FIN,ACK' })), 'INVALID');
  assert.equal(cls(syn('198.51.100.9', 40000, C.WAN_IP, 22, { flags: 'RST' })), 'INVALID');
  assert.equal(cls({ protocol: 'ICMP', srcIp: '8.8.8.8', dstIp: C.WAN_IP, icmpType: 0 }), 'INVALID');
  assert.equal(cls({ protocol: 'UDP', srcIp: '192.168.1.50', srcPort: 5000, dstIp: '8.8.8.8', dstPort: 53 }), 'NEW');
});

test('Cadenas: la ruta se deduce de las IP (INPUT / FORWARD / OUTPUT)', () => {
  const st = fresh();
  const r1 = C.processPacket(st, syn('192.168.1.50', 51200, '172.16.0.10', 80), { dryRun: true });
  assert.equal(r1.chain, 'FORWARD'); assert.equal(r1.inIface, 'LAN'); assert.equal(r1.outIface, 'DMZ');
  const r2 = C.processPacket(st, syn('198.51.100.9', 40000, C.WAN_IP, 22), { dryRun: true });
  assert.equal(r2.chain, 'INPUT'); assert.equal(r2.action, 'DROP'); assert.equal(r2.matchedRule.id, 7);
  const r3 = C.processPacket(st, { protocol: 'UDP', srcIp: C.WAN_IP, srcPort: 40000, dstIp: '8.8.8.8', dstPort: 53 }, { dryRun: true });
  assert.equal(r3.chain, 'OUTPUT'); assert.equal(r3.outIface, 'WAN'); assert.equal(r3.action, 'ACCEPT'); assert.equal(r3.decidedBy, 'policy');
  // spoofing: IP de la LAN entrando por la WAN
  const r4 = C.processPacket(st, syn('192.168.1.50', 1234, '172.16.0.10', 80, { inIface: 'WAN' }), { dryRun: true });
  assert.ok(r4.notes.some((n) => /spoofing/.test(n.text)));
});

test('Reglas por defecto: la LAN navega con MASQUERADE y vuelve por conntrack', () => {
  const st = fresh();
  const out = C.processPacket(st, syn('192.168.1.50', 51200, '93.184.216.34', 443));
  assert.equal(out.action, 'ACCEPT'); assert.equal(out.matchedRule.id, 8);
  assert.equal(out.postNat.type, 'MASQUERADE');
  assert.equal(out.after.srcIp, C.WAN_IP);
  assert.equal(out.after.srcPort, 51200, 'MASQUERADE conserva el puerto si no hay colisión');
  const back = C.processPacket(st, { protocol: 'TCP', flags: 'SYN,ACK', srcIp: '93.184.216.34', srcPort: 443, dstIp: C.WAN_IP, dstPort: 51200 });
  assert.equal(back.ctstate, 'ESTABLISHED');
  assert.equal(back.preNat.type, 'de-SNAT');
  assert.equal(back.after.dstIp, '192.168.1.50');
  assert.equal(back.chain, 'FORWARD');
  assert.equal(back.action, 'ACCEPT'); assert.equal(back.matchedRule.id, 2);
  // Segundo equipo con el mismo puerto de origen al mismo destino → PAT cambia el puerto
  const other = C.processPacket(st, syn('192.168.1.51', 51200, '93.184.216.34', 443));
  assert.notEqual(other.after.srcPort, 51200);
  assert.ok(other.postNat.portChanged);
});

test('DNAT: Internet llega a la web de la DMZ y FORWARD ve la IP traducida', () => {
  const st = fresh();
  const t = C.tryConnection(st, syn('198.51.100.20', 50500, C.WAN_IP, 443));
  assert.equal(t.fwd.preNat.type, 'DNAT');
  assert.equal(t.fwd.after.dstIp, '172.16.0.10');
  assert.equal(t.fwd.chain, 'FORWARD');
  assert.equal(t.fwd.matchedRule.id, 10);
  assert.equal(t.outcome, 'connected');
  assert.equal(t.back.postNat.type, 'de-DNAT');
  assert.equal(t.back.after.srcIp, C.WAN_IP);
});

test('Sin regla ESTABLISHED en FORWARD la respuesta se pierde', () => {
  const st = fresh();
  st.rules.linux = st.rules.linux.filter((r) => r.id !== 2);
  const t = C.tryConnection(st, syn('192.168.1.50', 51200, '93.184.216.34', 443));
  assert.equal(t.outcome, 'reply-blocked');
});

test('First match: el orden importa en Linux', () => {
  const st = fresh();
  st.rules.linux = [
    C.makeRule({ id: 1, name: 'drop tcp', chain: 'INPUT', protocol: 'TCP', action: 'DROP' }),
    C.makeRule({ id: 2, name: 'ssh', chain: 'INPUT', protocol: 'TCP', dstPort: '22', action: 'ACCEPT' }),
  ];
  const a = C.processPacket(st, syn('192.168.1.50', 1000, '192.168.1.1', 22), { dryRun: true });
  assert.equal(a.action, 'DROP'); assert.equal(a.matchedRule.id, 1);
  assert.equal(C.analyzeRules(st.rules.linux, 'linux')[2].type, 'shadowed');
  st.rules.linux.reverse();
  const b = C.processPacket(st, syn('192.168.1.50', 1000, '192.168.1.1', 22), { dryRun: true });
  assert.equal(b.action, 'ACCEPT'); assert.equal(b.matchedRule.id, 2);
});

test('Sombreado con CIDR y puertos contenidos, y redundancia', () => {
  const rules = [
    C.makeRule({ id: 1, name: 'a', chain: 'FORWARD', protocol: 'TCP', srcIp: '10.0.0.0/8', dstPort: '1-1024', action: 'DROP' }),
    C.makeRule({ id: 2, name: 'b', chain: 'FORWARD', protocol: 'TCP', srcIp: '10.1.2.0/24', dstPort: '22,80', state: 'NEW', action: 'ACCEPT' }),
    C.makeRule({ id: 3, name: 'c', chain: 'FORWARD', protocol: 'TCP', srcIp: '10.1.2.3', dstPort: '443', action: 'DROP' }),
    C.makeRule({ id: 4, name: 'd', chain: 'FORWARD', protocol: 'TCP', srcIp: '10.1.2.3', dstPort: '2000', action: 'DROP' }),
  ];
  const a = C.analyzeRules(rules, 'linux');
  assert.equal(a[2].type, 'shadowed');
  assert.equal(a[3].type, 'redundant');
  assert.equal(a[4], undefined);
});

test('REJECT: tcp-reset solo en reglas TCP; ICMP port-unreachable en el resto', () => {
  const st = fresh();
  const r = C.processPacket(st, syn('172.16.0.10', 38000, '192.168.1.50', 445), { dryRun: true });
  assert.equal(r.action, 'REJECT'); assert.equal(r.response, 'icmp-port-unreachable');
  st.rules.linux.push(C.makeRule({ id: 99, name: 'rej', chain: 'INPUT', inIface: 'WAN', protocol: 'TCP', dstPort: '8080', action: 'REJECT' }));
  const r2 = C.processPacket(st, syn('198.51.100.9', 1, C.WAN_IP, 8080), { dryRun: true });
  assert.equal(r2.response, 'tcp-reset');
});

test('Windows: el bloqueo gana, perfiles, estado automático y sin FORWARD', () => {
  const st = fresh();
  st.engine = 'windows';
  st.rules.windows = [
    C.makeRule({ id: 1, name: 'allow 443', chain: 'INPUT', protocol: 'TCP', dstPort: '443', action: 'ACCEPT' }),
    C.makeRule({ id: 2, name: 'block ip', chain: 'INPUT', protocol: 'TCP', srcIp: '198.51.100.99', action: 'DROP' }),
    C.makeRule({ id: 3, name: 'rdp private', chain: 'INPUT', protocol: 'TCP', dstPort: '3389', action: 'ACCEPT', profile: 'Private' }),
  ];
  const a = C.processPacket(st, syn('198.51.100.99', 1, C.WAN_IP, 443), { dryRun: true });
  assert.equal(a.action, 'DROP'); assert.equal(a.decidedBy, 'block'); assert.equal(a.matchedRule.id, 2);
  const b = C.processPacket(st, syn('198.51.100.20', 1, C.WAN_IP, 443), { dryRun: true });
  assert.equal(b.action, 'ACCEPT'); assert.equal(b.decidedBy, 'allow');
  st.windowsProfile = 'Public';
  assert.equal(C.processPacket(st, syn('198.51.100.20', 2, C.WAN_IP, 3389), { dryRun: true }).action, 'DROP');
  st.windowsProfile = 'Private';
  assert.equal(C.processPacket(st, syn('198.51.100.20', 2, C.WAN_IP, 3389), { dryRun: true }).action, 'ACCEPT');
  const f = C.processPacket(st, syn('192.168.1.50', 1, '172.16.0.10', 80), { dryRun: true });
  assert.ok(f.notApplicable);
  // la salida está permitida por defecto y la respuesta entra sola
  const t = C.tryConnection(st, syn(C.WAN_IP, 50000, '93.184.216.34', 443));
  assert.equal(t.outcome, 'connected');
  assert.equal(t.back.decidedBy, 'stateful');
  assert.equal(C.analyzeRules(st.rules.windows, 'windows')[1], undefined);
  st.rules.windows.push(C.makeRule({ id: 4, name: 'block all 443', chain: 'INPUT', protocol: 'TCP', dstPort: '443', action: 'DROP' }));
  assert.equal(C.analyzeRules(st.rules.windows, 'windows')[1].type, 'overridden');
});

test('Nmap -sS desde Internet contra la IP pública', () => {
  const st = fresh();
  const s = C.nmapScan(st, { target: C.WAN_IP, type: '-sS', zone: 'WAN' });
  const by = Object.fromEntries(s.rows.map((r) => [r.port, r]));
  assert.equal(by[22].state, 'filtered');
  assert.equal(by[22].reason, 'no-response');
  assert.equal(by[80].state, 'open');
  assert.equal(by[443].state, 'open');
  assert.match(by[443].reason, /^syn-ack ttl 63$/, 'el servidor está detrás del firewall: TTL 64-1');
  assert.equal(by[3389].state, 'filtered');
  assert.match(C.nmapReport(s), /PORT +STATE +SERVICE +REASON/);
});

test('Nmap: REJECT TCP → closed; REJECT genérico → filtered; UDP; ACK scan', () => {
  const st = fresh();
  st.rules.linux.unshift(C.makeRule({ id: 51, name: 'rej resto', chain: 'INPUT', inIface: 'WAN', dstIp: C.WAN_IP, action: 'REJECT', state: 'NEW' }));
  st.rules.linux.unshift(C.makeRule({ id: 50, name: 'rej 8080', chain: 'INPUT', inIface: 'WAN', protocol: 'TCP', dstPort: '8080', action: 'REJECT' }));
  const s = C.nmapScan(st, { target: C.WAN_IP, type: '-sS', zone: 'WAN', ports: [8080, 21] });
  assert.equal(s.rows[0].state, 'closed'); assert.match(s.rows[0].reason, /^reset/);
  assert.equal(s.rows[1].state, 'filtered'); assert.match(s.rows[1].reason, /^port-unreach/);

  const st2 = fresh();
  const u = C.nmapScan(st2, { target: '192.168.1.1', type: '-sU', zone: 'LAN', ports: [53, 123] });
  assert.equal(u.rows[0].state, 'open');
  assert.equal(u.rows[1].state, 'open|filtered');
  // UDP a un puerto cerrado de un equipo que el firewall deja pasar → ICMP port-unreachable RELATED → closed
  st2.rules.linux.push(C.makeRule({ id: 60, name: 'udp dmz', chain: 'FORWARD', inIface: 'LAN', outIface: 'DMZ', protocol: 'UDP', state: 'NEW', action: 'ACCEPT' }));
  const u2 = C.nmapScan(st2, { target: '172.16.0.10', type: '-sU', zone: 'LAN', ports: [53, 161] });
  assert.equal(u2.rows[0].state, 'open');
  assert.equal(u2.rows[1].state, 'closed');

  const a = C.nmapScan(fresh(), { target: C.WAN_IP, type: '-sA', zone: 'WAN', ports: [22, 443] });
  assert.equal(a.rows[0].state, 'filtered');
  assert.equal(a.rows[1].state, 'unfiltered');
});

test('Paquetes con checksums reales', () => {
  const st = fresh();
  const verifyIp = (bytes) => C.checksum(bytes.slice(14, 34)) === 0;
  const l4ok = (bytes) => {
    const ip = bytes.slice(14, 34), l4 = bytes.slice(34);
    const proto = ip[9];
    if (proto === 1) return C.checksum(l4) === 0;
    const pseudo = [...ip.slice(12, 20), 0, proto, (l4.length >> 8) & 255, l4.length & 255, ...l4];
    return C.checksum(pseudo) === 0;
  };
  for (const p of [
    syn('192.168.1.50', 51200, '172.16.0.10', 80),
    syn('192.168.1.50', 51200, '172.16.0.10', 80, { flags: 'PSH,ACK' }),
    { protocol: 'UDP', srcIp: '192.168.1.50', srcPort: 53100, dstIp: '8.8.8.8', dstPort: 53 },
    { protocol: 'UDP', srcIp: '192.168.1.50', srcPort: 53100, dstIp: '8.8.8.8', dstPort: 9999 },
    { protocol: 'ICMP', srcIp: '192.168.1.50', dstIp: '192.168.1.1', icmpType: 8 },
  ]) {
    const r = C.processPacket(st, p, { dryRun: true });
    assert.ok(verifyIp(r.frame.bytes), 'checksum IPv4');
    assert.ok(l4ok(r.frame.bytes), `checksum L4 ${p.protocol}`);
    assert.equal(r.frame.bytes.length, 14 + r.frame.ipLen);
  }
  const s = C.processPacket(st, syn('192.168.1.50', 51200, '172.16.0.10', 80), { dryRun: true });
  assert.equal(s.frame.ipLen, 60, 'SYN de Linux: 20 IP + 40 TCP con opciones');
  assert.equal(C.processPacket(st, { protocol: 'ICMP', srcIp: '192.168.1.50', dstIp: '192.168.1.1' }, { dryRun: true }).frame.ipLen, 84, 'ping de Linux: 84 bytes');
  assert.match(C.hexdump(s.frame.bytes).split('\n')[0], /^0000  52 54 00 0b 00 01 /);
});

test('Registros con formato real', () => {
  const st = fresh();
  const r = C.processPacket(st, syn('198.51.100.9', 40000, C.WAN_IP, 22), { dryRun: true });
  const line = C.iptablesLogLine(r, new Date(2026, 9, 23, 10, 5, 7));
  assert.match(line, /^Oct 23 10:05:07 fw kernel: \[CFW r7 DROP\] IN=eth0 OUT= MAC=52:54:00:0a:00:01:02:[0-9a-f:]+:08:00 SRC=198.51.100.9 DST=203.0.113.1 LEN=60 .* TTL=52 .* PROTO=TCP SPT=40000 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0$/);
  st.engine = 'windows';
  const w = C.processPacket(st, syn('198.51.100.9', 40000, C.WAN_IP, 445), { dryRun: true });
  assert.match(C.pfirewallLogLine(w, new Date(2026, 9, 23, 10, 5, 7)), /^2026-10-23 10:05:07 DROP TCP 198\.51\.100\.9 203\.0\.113\.1 40000 445 60 S \d+ 0 64240 - - - RECEIVE$/);
});

test('Exportadores: iptables, nftables, PowerShell y netsh', () => {
  const st = fresh();
  const ipt = C.genIptables(st);
  assert.match(ipt, /iptables -A FORWARD -i eth1 -o eth2 -p tcp -d 172\.16\.0\.10 -m multiport --dports 80,443 -m conntrack --ctstate NEW -m comment --comment "La LAN usa la web de la DMZ" -j ACCEPT/);
  assert.match(ipt, /-j REJECT --reject-with icmp-port-unreachable/);
  assert.match(ipt, /iptables -t nat -A PREROUTING -i eth0 -d 203\.0\.113\.1 -p tcp --dport 443 -j DNAT --to-destination 172\.16\.0\.10:443/);
  assert.match(ipt, /iptables -t nat -A POSTROUTING -o eth0 -s 192\.168\.1\.0\/24 -j MASQUERADE/);
  assert.doesNotMatch(ipt, /-A OUTPUT .*-i /);
  const nft = C.genNftables(st);
  assert.match(nft, /chain forward \{\n {8}type filter hook forward priority filter; policy drop;/);
  assert.match(nft, /iifname "eth1" oifname "eth2" ip daddr 172\.16\.0\.10 tcp dport \{ 80, 443 \} ct state new counter accept/);
  assert.match(nft, /ct state \{ established, related \} counter accept/);
  const ps = C.genPowerShell(st);
  assert.doesNotMatch(ps, /-Profile All/);
  assert.match(ps, /-Direction Outbound -Action Block -Profile Any -Enabled True -Protocol TCP -RemotePort 23/);
  assert.match(ps, /-Direction Inbound -Action Allow -Profile Any -Enabled True -Protocol ICMPv4 -RemoteAddress 192\.168\.1\.0\/24/);
  const ns = C.genNetsh(st);
  assert.match(ns, /dir=out action=block enable=yes profile=any protocol=tcp remoteport=23/);
  // nombres maliciosos no rompen las comillas del script
  st.rules.linux[0].name = 'x" ; rm -rf / ; echo "$(id)`';
  const line = C.genIptables(st).split('\n').find((l) => l.includes('ESTABLISHED,RELATED'));
  const c = /--comment "([^"]*)" -j ACCEPT/.exec(line)[1];
  assert.doesNotMatch(c, /["$`\\]/);
});

test('Importación: formato v1, saneado y rechazo de basura', () => {
  const st = fresh();
  const v1 = {
    engineMode: 'linux', defaultPolicy: 'DROP',
    rules: [{ id: 1, name: '<img src=x onerror=alert(1)>', direction: 'INBOUND', zone: 'WAN', protocol: 'TCP', srcIp: 'ANY', srcPort: 'ANY', dstIp: 'ANY', dstPort: '22', state: 'NEW', action: 'DROP', enabled: true, profile: 'All' }],
  };
  const r = C.importConfig(st, v1);
  assert.ok(r.ok, r.errors.join());
  assert.equal(st.rules.linux[0].chain, 'INPUT');
  assert.equal(st.rules.linux[0].inIface, 'WAN');
  assert.equal(st.rules.linux[0].profile, 'Any');
  const bad = C.importConfig(st, { rules: [{ name: 'x', direction: 'INBOUND', srcIp: '1.2.3.4/99' }] });
  assert.ok(!bad.ok);
  assert.ok(!C.importConfig(st, { rules: 'nope' }).ok);
  const round = C.importConfig(fresh(), JSON.parse(JSON.stringify(C.exportConfig(fresh()))));
  assert.ok(round.ok, round.errors.join());
});

test('Retos: fallan al cargarlos y se superan con la solución esperada', () => {
  const fixes = {
    1: (st) => { const r = st.rules.linux.find((x) => x.id === 2); Object.assign(r, { inIface: 'ANY', state: 'ESTABLISHED,RELATED' }); },
    2: (st) => { const i = st.rules.linux.findIndex((x) => x.id === 3); const [r] = st.rules.linux.splice(i, 1); st.rules.linux.splice(1, 0, r); },
    3: (st) => { st.rules.windows.find((x) => x.id === 2).enabled = false; },
    4: (st) => { st.rules.linux.find((x) => x.id === 2).dstIp = '172.16.0.10'; },
  };
  for (const sc of C.SCENARIOS) {
    const st = fresh();
    sc.load(st);
    assert.ok(sc.verify(st).some((t) => !t.ok), `reto ${sc.id} no debería estar resuelto de salida`);
    fixes[sc.id](st);
    const res = sc.verify(st);
    assert.ok(res.every((t) => t.ok), `reto ${sc.id}: ${res.filter((t) => !t.ok).map((t) => t.name + ' → ' + t.detail).join(' | ')}`);
  }
  // Reto 2: borrar la regla de bloqueo no vale
  const st = fresh();
  C.SCENARIOS[1].load(st);
  st.rules.linux = st.rules.linux.filter((r) => r.id !== 2);
  assert.ok(C.SCENARIOS[1].verify(st).some((t) => !t.ok));
});

test('Auditoría: la configuración por defecto saca A y una mala suspende', () => {
  const a = C.audit(fresh());
  assert.equal(a.grade, 'A', JSON.stringify(a.checks.filter((c) => c.status !== 'PASS')));
  const st = fresh();
  st.policies.linux.FORWARD = 'ACCEPT';
  st.rules.linux = [C.makeRule({ id: 1, name: 'todo', chain: 'FORWARD', action: 'ACCEPT' })];
  const b = C.audit(st);
  assert.ok(b.score < 50, String(b.score));
  const w = fresh(); w.engine = 'windows';
  assert.equal(C.audit(w).grade, 'A');
});

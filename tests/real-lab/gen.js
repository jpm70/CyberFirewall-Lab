// Genera las reglas iptables y las predicciones del Nmap simulado para el laboratorio real.
// Uso: node tests/real-lab/gen.js   (escribe en tests/real-lab/out/)
'use strict';
const fs = require('fs');
const path = require('path');
const C = require('../../js/engine.js');

const out = path.join(__dirname, 'out');
fs.mkdirSync(out, { recursive: true });
const st = C.createState();
st.rules.linux.push(C.makeRule({ id: 12, name: 'Rechazar 8080 con RST', chain: 'INPUT', inIface: 'WAN', protocol: 'TCP', dstPort: '8080', action: 'REJECT' }));
fs.writeFileSync(path.join(out, 'rules.sh'), C.genIptables(st));
const scans = [
  { target: '203.0.113.1', type: '-sS', zone: 'WAN' }, { target: '203.0.113.1', type: '-sA', zone: 'WAN' },
  { target: '192.168.1.1', type: '-sS', zone: 'LAN' }, { target: '192.168.1.1', type: '-sU', zone: 'LAN' },
  { target: '172.16.0.10', type: '-sS', zone: 'LAN' }, { target: '192.168.1.50', type: '-sS', zone: 'DMZ' },
  { target: '172.16.0.10', type: '-sU', zone: 'LAN' },
];
const sim = scans.map((s) => ({ scan: s, rows: C.nmapScan(st, s).rows.map((x) => ({ port: x.port, proto: x.proto, state: x.state, reason: x.reason.split(' ')[0] })) }));
fs.writeFileSync(path.join(out, 'sim.json'), JSON.stringify(sim, null, 1));
console.log(`Escrito ${out}/rules.sh y sim.json (${scans.length} escaneos)`);

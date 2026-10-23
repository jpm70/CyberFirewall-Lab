"""Compara el Nmap real (out/real.xml) con el simulado (out/sim.json). Uso: python3 tests/real-lab/compare.py"""
import json, os, re, sys
import xml.etree.ElementTree as ET

d = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'out')
sim = json.load(open(os.path.join(d, 'sim.json'), encoding='utf-8'))
runs = re.findall(r'<nmaprun.*?</nmaprun>', open(os.path.join(d, 'real.xml'), encoding='utf-8').read(), re.S)
same_state = same_both = total = 0
for s, r in zip(sim, runs):
    real = {int(p.get('portid')): (p.find('state').get('state'), p.find('state').get('reason')) for p in ET.fromstring(r).iter('port')}
    sc = s['scan']
    print(f"== nmap {sc['type']} desde {sc['zone']} -> {sc['target']}")
    for row in s['rows']:
        rs, rr = real.get(row['port'], ('?', '?'))
        total += 1
        same_state += rs == row['state']
        same_both += rs == row['state'] and rr == row['reason']
        mark = 'OK ' if rs == row['state'] else 'DIF'
        print(f"  {mark} {row['port']:>5}/{row['proto']}  simulado={row['state']:<14}{row['reason']:<14} real={rs:<14}{rr}")
print(f"\nEstado igual: {same_state}/{total} · estado y motivo iguales: {same_both}/{total}")
sys.exit(0 if same_state == total else 1)

import re
import json
from collections import defaultdict
from datetime import datetime, timezone

LOG_FILE = "lab1/access.log"
OUTPUT_FILE = "lab1/reporte_web.json"

LOG_PATTERN = re.compile(
    r'(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) \d+ "([^"]*)" "([^"]*)"'
)
SQLI_PATTERN = re.compile(r'(UNION|SELECT|--|OR\s+1=1|\')', re.IGNORECASE)

entries = []

with open(LOG_FILE, 'r') as f:
    for line in f:
        m = LOG_PATTERN.match(line)
        if not m:
            continue
        ip, ts_str, method, path, status = m.group(1), m.group(2), m.group(3), m.group(4), int(m.group(5))
        try:
            ts = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            continue
        entries.append({"ip": ip, "ts": ts, "method": method, "path": path, "status": status})

# --- Escaneo de directorios: >20 rutas distintas en <60 seg desde la misma IP ---
by_ip = defaultdict(list)
for e in entries:
    by_ip[e["ip"]].append(e)

scanners = {}
for ip, reqs in by_ip.items():
    reqs_sorted = sorted(reqs, key=lambda x: x["ts"])
    for i, base in enumerate(reqs_sorted):
        window_paths = set()
        for req in reqs_sorted[i:]:
            delta = (req["ts"] - base["ts"]).total_seconds()
            if delta > 60:
                break
            window_paths.add(req["path"])
        if len(window_paths) > 20:
            scanners[ip] = len(window_paths)
            break

print("=== Escaneo de directorios detectado ===")
if scanners:
    for ip, count in scanners.items():
        print(f"  IP: {ip}  rutas distintas en <60s: {count}")
else:
    print("  Ninguno detectado")

# --- Errores 4xx y 5xx agrupados por IP ---
errors_by_ip = defaultdict(lambda: defaultdict(int))
for e in entries:
    if e["status"] >= 400:
        errors_by_ip[e["ip"]][e["status"]] += 1

print("\n=== Peticiones 4xx/5xx por IP ===")
for ip, codes in sorted(errors_by_ip.items(), key=lambda x: sum(x[1].values()), reverse=True)[:10]:
    total_err = sum(codes.values())
    print(f"  IP: {ip}  total errores: {total_err}  detalle: {dict(codes)}")

# --- SQL Injection ---
sqli_hits = []
for e in entries:
    if SQLI_PATTERN.search(e["path"]):
        sqli_hits.append({"ip": e["ip"], "path": e["path"], "status": e["status"],
                          "timestamp": e["ts"].strftime("%Y-%m-%d %H:%M:%S")})

print(f"\n=== Posibles SQL Injection detectados: {len(sqli_hits)} ===")
for h in sqli_hits[:10]:
    print(f"  IP: {h['ip']}  path: {h['path']}")

# --- Reporte JSON ---
report = {
    "fecha_analisis": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "total_peticiones": len(entries),
    "escaneo_directorios": [
        {"ip": ip, "rutas_distintas_60s": count} for ip, count in scanners.items()
    ],
    "errores_4xx_5xx_por_ip": [
        {"ip": ip, "codigos": dict(codes), "total": sum(codes.values())}
        for ip, codes in sorted(errors_by_ip.items(), key=lambda x: sum(x[1].values()), reverse=True)
    ],
    "posibles_sqli": sqli_hits
}

with open(OUTPUT_FILE, 'w') as f:
    json.dump(report, f, indent=2, ensure_ascii=False)

print(f"\nReporte exportado a {OUTPUT_FILE}")

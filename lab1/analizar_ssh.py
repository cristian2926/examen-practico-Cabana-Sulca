import re
import json
from collections import defaultdict
from datetime import datetime

LOG_FILE = "lab1/auth.log"
OUTPUT_FILE = "lab1/reporte_ssh.json"

ip_pattern = re.compile(r'Failed password.*from (\d+\.\d+\.\d+\.\d+)')

counts = defaultdict(int)

with open(LOG_FILE, 'r') as f:
    for line in f:
        match = ip_pattern.search(line)
        if match:
            counts[match.group(1)] += 1

total = sum(counts.values())
sorted_ips = sorted(counts.items(), key=lambda x: x[1], reverse=True)
top10 = sorted_ips[:10]

print("Top 10 IPs con mas intentos fallidos SSH:")
print("-" * 50)
for i, (ip, n) in enumerate(top10, 1):
    print(f"{i:2}. {ip:<20} {n} intentos")

print()

ips_data = []
for ip, n in sorted_ips:
    alerta = n > 50
    if alerta:
        print(f"[ALERTA] IP: {ip} -- {n} intentos fallidos -- Posible ataque de fuerza bruta")
    ips_data.append({"ip": ip, "intentos": n, "alerta": alerta})

report = {
    "fecha_analisis": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "total_intentos_fallidos": total,
    "ips_sospechosas": ips_data
}

with open(OUTPUT_FILE, 'w') as f:
    json.dump(report, f, indent=2, ensure_ascii=False)

print(f"\nReporte exportado a {OUTPUT_FILE}")

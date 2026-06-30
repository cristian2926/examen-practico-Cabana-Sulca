import re
import json
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from collections import defaultdict
from datetime import datetime
import os

os.makedirs("lab1/graficas", exist_ok=True)

# ============================================================
# Grafica 1: Top 10 IPs con mas intentos fallidos SSH
# ============================================================
with open("lab1/reporte_ssh.json", 'r') as f:
    ssh_data = json.load(f)

top10 = ssh_data["ips_sospechosas"][:10]
ips = [e["ip"] for e in top10]
intentos = [e["intentos"] for e in top10]

fig, ax = plt.subplots(figsize=(10, 6))
bars = ax.barh(ips[::-1], intentos[::-1], color='crimson', edgecolor='black')
ax.set_xlabel("Numero de intentos fallidos")
ax.set_title("Top 10 IPs con mas intentos fallidos SSH")
ax.bar_label(bars, padding=3)
plt.tight_layout()
plt.savefig("lab1/graficas/top10_ssh.png", dpi=120)
plt.close()
print("Generada: lab1/graficas/top10_ssh.png")

# ============================================================
# Grafica 2: Linea de tiempo — peticiones HTTP por hora
# ============================================================
LOG_PATTERN = re.compile(
    r'\S+ \S+ \S+ \[([^\]]+)\] "\S+ \S+ \S+" \d+ \d+'
)

requests_by_hour = defaultdict(int)

with open("lab1/access.log", 'r') as f:
    for line in f:
        m = LOG_PATTERN.search(line)
        if m:
            try:
                ts = datetime.strptime(m.group(1), "%d/%b/%Y:%H:%M:%S %z")
                requests_by_hour[ts.hour] += 1
            except ValueError:
                pass

hours = list(range(24))
counts = [requests_by_hour.get(h, 0) for h in hours]

fig, ax = plt.subplots(figsize=(12, 5))
ax.plot(hours, counts, marker='o', linewidth=2, color='steelblue')
ax.fill_between(hours, counts, alpha=0.2, color='steelblue')
ax.set_xlabel("Hora del dia")
ax.set_ylabel("Numero de peticiones")
ax.set_title("Peticiones HTTP por hora")
ax.set_xticks(hours)
ax.grid(True, linestyle='--', alpha=0.5)
plt.tight_layout()
plt.savefig("lab1/graficas/timeline_http.png", dpi=120)
plt.close()
print("Generada: lab1/graficas/timeline_http.png")

# ============================================================
# Grafica 3: Heatmap — peticiones por hora y codigo de respuesta
# ============================================================
LOG_FULL = re.compile(
    r'\S+ \S+ \S+ \[([^\]]+)\] "\S+ \S+ \S+" (\d+) \d+'
)

TARGET_CODES = [200, 301, 404, 500]
matrix = {code: defaultdict(int) for code in TARGET_CODES}

with open("lab1/access.log", 'r') as f:
    for line in f:
        m = LOG_FULL.search(line)
        if m:
            try:
                ts = datetime.strptime(m.group(1), "%d/%b/%Y:%H:%M:%S %z")
                code = int(m.group(2))
                if code in TARGET_CODES:
                    matrix[code][ts.hour] += 1
            except ValueError:
                pass

df = pd.DataFrame(
    {code: [matrix[code].get(h, 0) for h in range(24)] for code in TARGET_CODES},
    index=range(24)
).T

fig, ax = plt.subplots(figsize=(14, 5))
sns.heatmap(df, annot=True, fmt='d', cmap='YlOrRd', linewidths=0.5,
            xticklabels=range(24), yticklabels=TARGET_CODES, ax=ax)
ax.set_xlabel("Hora del dia")
ax.set_ylabel("Codigo de respuesta HTTP")
ax.set_title("Peticiones HTTP por hora y codigo de respuesta")
plt.tight_layout()
plt.savefig("lab1/graficas/heatmap_http.png", dpi=120)
plt.close()
print("Generada: lab1/graficas/heatmap_http.png")

print("\nTodas las graficas guardadas en lab1/graficas/")

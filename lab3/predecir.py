import sys
import pandas as pd
import numpy as np
import joblib

if len(sys.argv) < 2:
    print("Uso: python3 lab3/predecir.py <archivo_csv>")
    print("Ejemplo: python3 lab3/predecir.py nuevo_trafico.csv")
    sys.exit(1)

CSV_FILE = sys.argv[1]
MODEL_FILE = "lab3/modelo_anomalias.pkl"
SCALER_FILE = "lab3/scaler.pkl"
FEATURES = ['bytes_sent', 'bytes_recv', 'duration_sec', 'packets',
            'dst_port', 'ratio_bytes', 'bytes_por_segundo']

print(f"[*] Cargando modelo desde {MODEL_FILE}")
modelo = joblib.load(MODEL_FILE)
scaler = joblib.load(SCALER_FILE)

print(f"[*] Leyendo datos desde {CSV_FILE}")
df = pd.read_csv(CSV_FILE, parse_dates=['timestamp'])

# Feature engineering (mismas variables que en entrenamiento)
df['ratio_bytes'] = df['bytes_sent'] / (df['bytes_recv'] + 1)
df['bytes_por_segundo'] = df['bytes_sent'] / (df['duration_sec'] + 0.001)

# Clipeo de outliers al percentil 99 del dataset original (valores aproximados)
for col in ['bytes_sent', 'bytes_recv', 'duration_sec', 'packets']:
    if col in df.columns:
        df[col] = df[col].clip(lower=0)

X = scaler.transform(df[FEATURES])
predicciones = modelo.predict(X)
scores = modelo.decision_function(X)

df['prediccion'] = predicciones
df['anomaly_score'] = scores

anomalias = df[df['prediccion'] == -1].copy()
anomalias = anomalias.sort_values('anomaly_score')

print(f"\n[+] Total de registros analizados : {len(df)}")
print(f"[+] Anomalias detectadas          : {len(anomalias)}")
print(f"[+] Porcentaje anomalo            : {len(anomalias)/len(df)*100:.2f}%")

if len(anomalias) > 0:
    print("\n=== Registros clasificados como ANOMALIA (ordenados por score) ===\n")
    cols_mostrar = ['timestamp', 'src_ip', 'dst_ip', 'dst_port', 'protocol',
                    'bytes_sent', 'bytes_recv', 'duration_sec', 'anomaly_score']
    cols_existentes = [c for c in cols_mostrar if c in anomalias.columns]
    print(anomalias[cols_existentes].to_string(index=False))
else:
    print("[+] No se detectaron anomalias en el archivo proporcionado.")

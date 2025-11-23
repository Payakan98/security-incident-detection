# src/analyze.py
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import os

# Chemins
BASE_DIR = os.path.dirname(os.path.dirname(__file__))
INPUT_CSV = os.path.join(BASE_DIR, "data", "processed", "events.csv")
OUTPUT_CSV = os.path.join(BASE_DIR, "data", "processed", "events_with_anomalies.csv")

# 1️⃣ Charger les événements
df = pd.read_csv(INPUT_CSV)
print(f"[+] Loaded {len(df)} events")

# 2️⃣ Préparer les features pour le modèle
# Transformer les colonnes non numériques avec LabelEncoder
le_src = LabelEncoder()
le_dst = LabelEncoder()
le_proto = LabelEncoder()
le_event = LabelEncoder()

df['src_ip_enc'] = le_src.fit_transform(df['src_ip'])
df['dst_ip_enc'] = le_dst.fit_transform(df['dst_ip'])
df['proto_enc'] = le_proto.fit_transform(df['proto'].astype(str))
df['event_enc'] = le_event.fit_transform(df['event_type'].astype(str))

# Features numériques pour Isolation Forest
features = df[['src_ip_enc', 'dst_ip_enc', 'src_port', 'dst_port', 'proto_enc', 'event_enc', 'payload_size']]

# 3️⃣ Détection d'anomalies
model = IsolationForest(contamination=0.2, random_state=42)
df['anomaly'] = model.fit_predict(features)  # -1 = anomalie, 1 = normal

# 4️⃣ Sauvegarder les résultats
df.to_csv(OUTPUT_CSV, index=False)
print(f"[+] Saved results to {OUTPUT_CSV}")

# 5️⃣ Optionnel : afficher les anomalies
anomalies = df[df['anomaly'] == -1]
print(f"[!] Found {len(anomalies)} anomalies")
print(anomalies[['ts','src_ip','dst_ip','event_type','payload_size']])

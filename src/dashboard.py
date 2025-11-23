# src/dashboard.py
import pandas as pd
import dash
from dash import dcc, html
import plotly.express as px
import os

# Chemins
BASE_DIR = os.path.dirname(os.path.dirname(__file__))
CSV_FILE = os.path.join(BASE_DIR, "data", "processed", "events_with_anomalies.csv")

# 1️⃣ Charger les données
df = pd.read_csv(CSV_FILE)
df['anomaly_label'] = df['anomaly'].apply(lambda x: 'Anomalie' if x == -1 else 'Normal')

# 2️⃣ Créer l'application Dash
app = dash.Dash(__name__)
app.title = "Tableau de bord - Détection d'incidents"

# 3️⃣ Layout du dashboard
app.layout = html.Div([
    html.H1("Détection d'incidents de sécurité avec IA"),
    html.Hr(),

    # Graphiques : incidents par protocole
    html.Div([
        dcc.Graph(
            id='protocol-count',
            figure=px.histogram(df, x='proto', color='anomaly_label',
                                barmode='group', title="Nombre d'événements par protocole",
                                labels={'proto':'Protocole', 'count':'Nombre'})
        )
    ]),

    # Graphique : anomalies par IP source
    html.Div([
        dcc.Graph(
            id='src-ip-anomalies',
            figure=px.histogram(df[df['anomaly']==-1], x='src_ip', 
                                title="Anomalies détectées par IP source",
                                labels={'src_ip':'IP Source', 'count':'Nombre'})
        )
    ]),

    # Tableau des anomalies
    html.Div([
        html.H2("Liste des anomalies détectées"),
        dcc.Graph(
            id='anomaly-table',
            figure=px.scatter(df[df['anomaly']==-1], x='ts', y='payload_size', 
                              color='event_type', hover_data=['src_ip','dst_ip'],
                              title="Détails des anomalies")
        )
    ])
])

# 4️⃣ Lancer le serveur
if __name__ == '__main__':
    app.run(debug=True)


import pandas as pd
import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import plotly.express as px
import os
import numpy as np

# 1️⃣ Chemin vers le CSV
BASE_DIR = os.path.dirname(os.path.dirname(__file__))
CSV_FILE = os.path.join(BASE_DIR, "data", "processed", "events_with_anomalies.csv")

# 2️⃣ Charger les données
df = pd.read_csv(CSV_FILE)
df['ts'] = pd.to_datetime(df['ts'], utc=True, errors='coerce')
df['anomaly_label'] = df['anomaly'].apply(lambda x: 'Anomalie' if x == -1 else 'Normal')

# 3️⃣ Ajouter une colonne 'severity' simulée pour démonstration
np.random.seed(42)
df['severity'] = np.random.choice(['Low', 'Medium', 'High', 'Critical'], size=len(df))

# 4️⃣ Créer des listes uniques pour les Dropdowns
event_types = [{'label': t, 'value': t} for t in sorted(df['event_type'].dropna().unique())]
ips = [{'label': ip, 'value': ip} for ip in sorted(df['src_ip'].dropna().unique())]

# Convertir 'proto' en string pour éviter TypeError
df['proto'] = df['proto'].astype(str)
protocols = [{'label': p, 'value': p} for p in sorted(df['proto'].unique())]

# Même pour severity si tu veux être sûr
df['severity'] = df['severity'].astype(str)
severities = [{'label': s, 'value': s} for s in sorted(df['severity'].unique())]

# 4️⃣ Créer des listes uniques pour les Dropdowns
event_types = [{'label': t, 'value': t} for t in sorted(df['event_type'].unique())]
ips = [{'label': ip, 'value': ip} for ip in sorted(df['src_ip'].unique())]
protocols = [{'label': p, 'value': p} for p in sorted(df['proto'].unique())]
severities = [{'label': s, 'value': s} for s in sorted(df['severity'].unique())]

# 5️⃣ Créer l'application Dash
app = dash.Dash(__name__)
app.title = "Tableau de bord - Détection d'incidents"

# 6️⃣ Layout
app.layout = html.Div([
    html.H1("Détection d'incidents de sécurité avec IA"),
    html.Hr(),

    html.Div([
        html.Label("Filtrer par type d'incident"),
        dcc.Dropdown(id='incident-type-dropdown', options=event_types, multi=True, value=[t['value'] for t in event_types]),

        html.Label("Filtrer par IP source"),
        dcc.Dropdown(id='ip-dropdown', options=ips, multi=True, value=[i['value'] for i in ips]),

        html.Label("Filtrer par protocole"),
        dcc.Dropdown(id='proto-dropdown', options=protocols, multi=True, value=[p['value'] for p in protocols]),
    ], style={'width': '30%', 'display': 'inline-block', 'verticalAlign': 'top'}),

    html.Div([
        dcc.Graph(id='graph-incidents'),
        dcc.Graph(id='severity-graph'),
        dcc.Graph(id='timeline-graph')
    ], style={'width': '65%', 'display': 'inline-block', 'paddingLeft': '20px'})
])

# 7️⃣ Callbacks

@app.callback(
    Output('graph-incidents', 'figure'),
    Input('incident-type-dropdown', 'value'),
    Input('ip-dropdown', 'value'),
    Input('proto-dropdown', 'value')
)
def update_incident_graph(selected_types, selected_ips, selected_protos):
    filtered_df = df[
        df['event_type'].isin(selected_types) &
        df['src_ip'].isin(selected_ips) &
        df['proto'].isin(selected_protos)
    ]
    fig = px.bar(filtered_df, x='event_type', color='anomaly_label',
                 title="Nombre d'incidents par type et statut",
                 labels={'event_type':'Type', 'anomaly_label':'Statut'})
    return fig

@app.callback(
    Output('severity-graph', 'figure'),
    Input('incident-type-dropdown', 'value'),
    Input('ip-dropdown', 'value'),
    Input('proto-dropdown', 'value')
)
def update_severity_graph(selected_types, selected_ips, selected_protos):
    filtered_df = df[
        df['event_type'].isin(selected_types) &
        df['src_ip'].isin(selected_ips) &
        df['proto'].isin(selected_protos)
    ]
    fig = px.histogram(filtered_df, x='severity', color='severity',
                       title="Nombre d'incidents par gravité")
    return fig

@app.callback(
    Output('timeline-graph', 'figure'),
    Input('incident-type-dropdown', 'value'),
    Input('ip-dropdown', 'value'),
    Input('proto-dropdown', 'value')
)
def update_timeline_graph(selected_types, selected_ips, selected_protos):
    filtered_df = df[
        df['event_type'].isin(selected_types) &
        df['src_ip'].isin(selected_ips) &
        df['proto'].isin(selected_protos)
    ]
    fig = px.scatter(filtered_df, x='ts', y='event_type', color='severity',
                     hover_data=['src_ip','dst_ip','proto','raw_message'],
                     title="Timeline des alertes réseau et emails")
    return fig

# 8️⃣ Lancer le serveur
if __name__ == '__main__':
    app.run(debug=True)

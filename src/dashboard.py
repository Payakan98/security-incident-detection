# src/dashboard.py
import pandas as pd
import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import plotly.express as px
import os

# Chemins
BASE_DIR = os.path.dirname(os.path.dirname(__file__))
CSV_FILE = os.path.join(BASE_DIR, "data", "processed", "events_with_anomalies.csv")

# Charger les données
df = pd.read_csv(CSV_FILE)
df['ts'] = pd.to_datetime(df['ts'], utc=True, errors='coerce')
df['anomaly_label'] = df['anomaly'].apply(lambda x: 'Anomalie' if x == -1 else 'Normal')

# Créer l'application Dash
app = dash.Dash(__name__)
app.title = "Tableau de bord - Détection d'incidents"

# Layout du dashboard
app.layout = html.Div([
    html.H1("Détection d'incidents de sécurité avec IA"),
    html.Hr(),

    # Dropdowns pour filtrer
    html.Div([
        html.Label("Filtrer par type d'incident"),
        dcc.Dropdown(
            id='event-type-dropdown',
            options=[{'label': t, 'value': t} for t in df['event_type'].unique()],
            value=df['event_type'].unique().tolist(),
            multi=True
        ),
        html.Label("Filtrer par IP source"),
        dcc.Dropdown(
            id='src-ip-dropdown',
            options=[{'label': ip, 'value': ip} for ip in df['src_ip'].unique()],
            value=df['src_ip'].unique().tolist(),
            multi=True
        ),
        html.Label("Filtrer par protocole"),
        dcc.Dropdown(
            id='proto-dropdown',
            options=[{'label': p, 'value': p} for p in df['proto'].unique()],
            value=df['proto'].unique().tolist(),
            multi=True
        )
    ], style={'margin-bottom': '30px'}),

    # Graphique : événements par protocole
    dcc.Graph(id='protocol-count'),

    # Graphique : anomalies par IP
    dcc.Graph(id='src-ip-anomalies'),

    # Graphique : timeline des incidents
    dcc.Graph(id='timeline-graph')
])

# Callbacks pour rendre le dashboard interactif
@app.callback(
    [Output('protocol-count', 'figure'),
     Output('src-ip-anomalies', 'figure'),
     Output('timeline-graph', 'figure')],
    [Input('event-type-dropdown', 'value'),
     Input('src-ip-dropdown', 'value'),
     Input('proto-dropdown', 'value')]
)
def update_graphs(selected_types, selected_ips, selected_protos):
    # Filtrer les données selon la sélection
    filtered_df = df[
        df['event_type'].isin(selected_types) &
        df['src_ip'].isin(selected_ips) &
        df['proto'].isin(selected_protos)
    ]

    # Graphique : événements par protocole et anomalies
    protocol_fig = px.histogram(
        filtered_df, x='proto', color='anomaly_label',
        barmode='group', title="Nombre d'événements par protocole",
        labels={'proto':'Protocole', 'count':'Nombre'}
    )

    # Graphique : anomalies par IP source
    anomalies_fig = px.histogram(
        filtered_df[filtered_df['anomaly']==-1], x='src_ip',
        title="Anomalies détectées par IP source",
        labels={'src_ip':'IP Source', 'count':'Nombre'}
    )

    # Graphique : timeline des incidents
    timeline_fig = px.scatter(
        filtered_df, x='ts', y='event_type', color='anomaly_label',
        hover_data=['src_ip','dst_ip','proto','payload_size'],
        title="Timeline des alertes réseau et emails"
    )

    return protocol_fig, anomalies_fig, timeline_fig

# Lancer le serveur
if __name__ == '__main__':
    app.run(debug=True)

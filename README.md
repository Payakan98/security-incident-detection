\# Détection d’incidents de sécurité avec IA



\## Description

Prototype en Python pour analyser automatiquement les logs réseau, emails et alertes de sécurité (IDS/IPS, antivirus) afin de détecter et prioriser les incidents critiques.



\## Fonctionnalités

\- Ingestion et normalisation des fichiers PCAP, JSON (IDS/IPS) et CSV (emails)

\- Détection d’anomalies et classification des incidents avec scikit-learn

\- Visualisation des incidents via un tableau de bord interactif (Dash / Plotly)

\- Réduction des faux positifs et priorisation des menaces



\## Structure du projet

Detection\_AI/

│

├─ data/

│ ├─ raw/ # Fichiers bruts (PCAP, eve.json, emails.csv)

│ └─ processed/ # Fichiers transformés

│

├─ src/

│ ├─ ingest.py # Script d’ingestion des données

│ ├─ dashboard.py # Tableau de bord interactif

│ └─ generate\_pcap.py # Script d’exemple pour générer des PCAP

│

├─ .gitignore

├─ README.md

└─ requirements.txt





\## Installation

1\. Cloner le dépôt :

```bash

git clone https://github.com/Payakan98/security-incident-detection.git

cd Detection\_AI



2.Créer un environnement virtuel et installer les dépendances :



python -m venv .venv

source .venv/bin/activate    # Linux/macOS

.venv\\Scripts\\activate       # Windows

pip install -r requirements.txt



Usage



Mettre tes fichiers dans data/raw/ : capture.pcap, eve.json, emails.csv



Exécuter l’ingestion :



python src/ingest.py





Lancer le tableau de bord :



python src/dashboard.py



Technologies utilisées



Python, Pandas, scikit-learn, Dash, Plotly



Wireshark / Tshark pour l’analyse réseau



Environnements Linux / Windows



Auteur



Islem Chokri




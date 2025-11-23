\# Détection d’Incidents de Sécurité avec IA



!\[Security AI](https://img.shields.io/badge/Status-Prototype-blue) !\[Python](https://img.shields.io/badge/Python-3.13-green) !\[License](https://img.shields.io/badge/License-MIT-yellow)



\## 🔎 Description



Ce projet propose un \*\*prototype de détection d’incidents de sécurité avec intelligence artificielle\*\*.  

Il permet de :  

\- Ingestion et normalisation de fichiers réseau (PCAP), alertes IDS/IPS et emails.  

\- Détection d’anomalies dans les événements.  

\- Visualisation interactive des incidents via un \*\*tableau de bord Dash\*\*.  



L’objectif est de réduire les faux positifs et de prioriser les menaces critiques pour les analystes SOC.



---



\## ⚙️ Installation



1\. \*\*Cloner le dépôt :\*\*

&nbsp;	git clone https://github.com/Payakan98/security-incident-detection.git

&nbsp;	cd Detection\_AI



2.Créer un environnement virtuel et installer les dépendances :



&nbsp;	python -m venv .venv

&nbsp;	# Windows

&nbsp;	.venv\\Scripts\\activate

&nbsp;	# Linux / Mac

&nbsp;	source .venv/bin/activate

&nbsp;	pip install -r requirements.txt



3.Mettre vos fichiers de données dans data/raw/ :



* capture.pcap (traces réseau)
* eve.json (logs IDS/IPS)
* emails.csv (alertes emails)



\##Usage



1.Ingestion et préparation des données :

&nbsp;	python src/ingest.py

Cela génère data/processed/events\_with\_anomalies.csv.



2.Lancer le tableau de bord interactif :



&nbsp;	python src/dashboard.py



3.Ouvrir dans votre navigateur sur http://127.0.0.1:8050.



\##Dashboard interactif



Le tableau de bord offre :



* Filtres interactifs : type d’incident, IP source/destination, protocole.
* Histogrammes pour suivre les incidents par gravité et protocole.
* Timeline des alertes réseau et emails pour visualiser la chronologie des incidents.
* Tableau des anomalies avec détails sur chaque événement.



\##Exemple de visualisation

&nbsp;Par type et status

!\[Capture d'écran 1](assets/nb\_incidents\_type.png)  



&nbsp;Timeline des incidents

!\[Capture d'écran 2](assets/incidents\_timeline.png)  



&nbsp;Par gravite

!\[Capture d'écran 3](assets/nb\_incidents\_gravite.png)



\## Structure du projet

Detection\_AI/

├─ data/

│  ├─ raw/              # Fichiers sources : PCAP, logs IDS, emails

│  └─ processed/        # Données normalisées générées par ingest.py

├─ src/

│  ├─ ingest.py         # Script d’ingestion et normalisation

│  ├─ dashboard.py      # Tableau de bord interactif

│  └─ generate\_sample\_data.py # Génération de fichiers temporaires

├─ .venv/               # Environnement virtuel

├─ requirements.txt     # Dépendances Python

└─ README.md



\##Technologies \& Librairies

* Python 3.13
* Pandas \& NumPy pour la manipulation de données
* Dash \& Plotly pour visualisation interactive
* Scapy / Pyshark pour l’analyse PCAP
* JSON / CSV pour ingestion des logs



\##Contribution

Les contributions sont les bienvenues !



Ajouter de nouvelles sources de logs ou alertes.



Intégrer de nouveaux modèles de détection d’anomalies.



Améliorer l’interface du tableau de bord.



\##Auteur: Islem Chokri




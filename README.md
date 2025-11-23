\# Détection d’Incidents de Sécurité avec IA



!\[Security AI](https://img.shields.io/badge/Status-Prototype-blue) !\[Python](https://img.shields.io/badge/Python-3.13-green) !\[License](https://img.shields.io/badge/License-MIT-yellow)



\## Description

Ce projet propose un \*\*prototype d’analyse automatique de logs et alertes de sécurité\*\* (réseau, IDS/IPS, emails) basé sur l’\*\*intelligence artificielle\*\*. Il permet de détecter des anomalies, de classifier les incidents et de visualiser les menaces critiques dans un tableau de bord interactif.



Le projet est conçu pour :  

\- Réduire les faux positifs dans les alertes de sécurité.  

\- Prioriser les incidents critiques pour un traitement rapide.  

\- Fournir une interface intuitive pour explorer et analyser les événements.



---



\## Fonctionnalités

\- \*\*Ingestion de données hétérogènes\*\* : PCAP, logs JSON IDS/IPS, alertes emails.  

\- \*\*Analyse et détection d’anomalies\*\* avec Python et scikit-learn.  

\- \*\*Classification automatique des incidents\*\* pour hiérarchiser les menaces.  

\- \*\*Tableau de bord interactif\*\* avec Dash et Plotly pour visualiser les incidents.  

\- \*\*Extensible et modulaire\*\* : facile d’ajouter de nouvelles sources ou modèles IA.  



---



\## Installation \& Usage



1\. \*\*Préparer l’environnement\*\*  

&nbsp;  Crée un environnement virtuel et installe les dépendances :

&nbsp;  ```bash

&nbsp;  python -m venv .venv

&nbsp;  source .venv/bin/activate   # Linux / Mac

&nbsp;  .venv\\Scripts\\activate      # Windows

&nbsp;  pip install -r requirements.txt



2.Préparer les fichiers d’entrée

&nbsp; Place tes fichiers dans data/raw/ :



* capture.pcap : capture réseau
* eve.json : logs IDS/IPS
* emails.csv : alertes emails



&nbsp;   Optionnel : générer des fichiers d’exemple pour tester :

&nbsp;      python src/generate\_sample\_data.py



3.Exécuter l’ingestion des données

&nbsp; Transforme les fichiers bruts en tables structurées :

&nbsp;    python src/ingest.py



4.Lancer le tableau de bord

Visualise et analyse les incidents détectés :



python src/dashboard.py



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
* Analyse réseau \& logs : Pyshark, pandas
* Machine Learning / IA : scikit-learn
* Emails / alertes : mailparser (ou CSV simplifié)
* Visualisation : Dash, Plotly
* Versioning \& workflow : Git, GitHub



\##Exemples de visualisation

Tableau de bord interactif avec filtre par type d’incident, adresse IP, protocole.



Graphiques pour suivre le nombre d’incidents par gravité.



Timeline des alertes réseau et emails.



\##Contribution

Les contributions sont les bienvenues !



Ajouter de nouvelles sources de logs ou alertes.



Intégrer de nouveaux modèles de détection d’anomalies.



Améliorer l’interface du tableau de bord.



\##Auteur: Islem Chokri




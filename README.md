# Enquête réseau — Extraction d'image depuis un PCAP

## Contexte
Dans le cadre d’un cours du BTS CIEL sur l’analyse de trafic réseau, les étudiants doivent extraire une donnée « sensible » depuis une capture réseau.  
Contexte pédagogique proposé :  
Une entreprise de design a signalé des fuites d’un prototype. Lors d’une surveillance légale d’un compte lié à un artiste, nos systèmes ont détecté un transfert suspect. La capture réseau fournie contient un fichier image transmis en clair. On suppose que l’image contient un identifiant (mot de passe) permettant l’accès à un dossier partagé. Il faut donc vérifier l'échange, et afficher le mot de passe. 

## Objectifs pédagogiques
- Savoir ouvrir et parcourir un fichier PCAP avec Wireshark.  
- Identifier et isoler une session TCP (handshake, flux de données).  
- Suivre un flux TCP et extraire le contenu binaire (raw bytes).  
- Reconstituer un fichier image à partir du flux réseau et vérifier son intégrité.  
- Rédiger un compte-rendu technique synthétique (IP, ports, timestamps, méthode).

## Prérequis
- Ordinateur avec Wireshark installé (version récente recommandée).  
- (Optionnel pour le enseigants) Python + Pillow si vous souhaitez automatiser la génération du fichier de capture.

## Fichiers fournis
- `pcap-image-extraction.py` — script permettant de générer le fichier `capture_suspect.pcap`. Vous pouvez modifier les adresses IP/MAC du client et serveur, ainsi que le nombre de paquets de « bruit ».  
- `capture_suspect.pcap` — capture réseau contenant la session à analyser.  
- `password.jpg` — (optionnel) image de référence / solution.

## Consignes
1. Générer le fichier `capture_suspect.pcap` à l’aide du script Python :  
   ```bash
   python ./pcap-image-extraction.py
1. Ouvrez `capture_suspect.pcap` dans **Wireshark**.  
2. Utilisez des filtres pour repérer le trafic intéressant (ex. `tcp`, `http`, ...).  
4. Clic droit sur un paquet de la session → **Follow → TCP Stream**.  
5. Dans la fenêtre *Follow TCP Stream*, choisissez **Show data as: Bytes / Raw** (ou *Octets bruts*).  
6. Cliquez sur **Save As...** et enregistrez le flux en binaire, par ex. `extracted.jpg`.  
7. Ouvrez `extracted.jpg` avec un visualiseur d’image pour lire le mot inscrit.  

## Conseils pédagogiques pour l’enseignant
- Pour les débutants : fournir l’IP ou le port cible comme indice.  
- Pour rendre l’exercice plus dur : ajouter du trafic bruité ou fragmenter l’image plus finement.  

## Licence & usage
Ce dépôt est créé à des fins pédagogiques. Libre d’usage.
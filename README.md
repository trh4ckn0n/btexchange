# Secure Terminal Messenger - trcom

Un outil de messagerie sécurisé qui permet la communication cryptée entre un serveur et un client. Il supporte la connexion via réseau local (TCP/IP) ou Bluetooth.

## Fonctionnalités

- **Chiffrement AES** : Utilisation du chiffrement AES avec une clé partagée pour sécuriser les messages.
- **Transfert de fichiers** : Possibilité d'envoyer et de recevoir des fichiers via une connexion sécurisée.
- **Bluetooth** : Support des connexions Bluetooth pour la communication entre appareils.
- **Scan réseau** : Fonctionnalité de balayage des hôtes disponibles dans un réseau local.
- **Interface utilisateur** : Interface textuelle conviviale via `rich` et `questionary`.

## Installation

### Prérequis

- Python 3.7+
- PIP

### Installation des dépendances

Clonez le projet et installez les dépendances nécessaires via `requirements.txt` :

```bash
git clone https://github.com/username/trcom.git
cd trcom
pip install -r requirements.txt
```

### Mode serveur
 
Démarrez un serveur pour recevoir des connexions :

```bash
python app.py --mode server --port 9999 --key tonmotdepasse
```
 
### Mode client
 
Démarrez un client pour se connecter au serveur (via IP ou Bluetooth) :

```bash
python app.py --mode client --scan --port 9999 --key tonmotdepasse
```

### Connexion Bluetooth
 
Si vous souhaitez utiliser Bluetooth, ajoutez l'option `--bluetooth` :

```bash
python3 app.py --mode client --bluetooth --scan
```

### Scan réseau
 
Si vous ne connaissez pas l'adresse IP du serveur, vous pouvez scanner le réseau local avec l'option `--scan` :

```bash
python3 app.py --mode client --scan --port 9999 --key "votre_clé_de_chiffrement"
```

# app.py - Communication sécurisée en AES entre deux appareils en réseau local (client + serveur)
# author - trhacknon

import socket
import threading
import argparse
import os
import sys
import base64
import hashlib
from rich import print
from rich.prompt import Prompt
from rich.console import Console
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

console = Console()

# Fonction utilitaire AES
class AESCipher:
    def __init__(self, key: str):
        digest = hashlib.sha256(key.encode()).digest()
        self.key = digest
        self.backend = default_backend()

    def encrypt(self, data: bytes) -> bytes:
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        return iv + encrypted

    def decrypt(self, data: bytes) -> bytes:
        iv = data[:16]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(data[16:]) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(decrypted) + unpadder.finalize()

# Fonction pour gérer l'envoi de fichiers
def send_file(sock, aes):
    filepath = Prompt.ask("[bold yellow][?][/bold yellow] Chemin du fichier à envoyer")
    if not os.path.exists(filepath):
        console.print("[red]Fichier introuvable.")
        return
    with open(filepath, "rb") as f:
        data = f.read()
    filename = os.path.basename(filepath)
    sock.sendall(b"__FILE__" + aes.encrypt(filename.encode()) + b"__SEP__" + aes.encrypt(data))
    console.print(f"[green]Fichier '{filename}' envoyé.")

# Fonction pour recevoir messages/fichiers

def handle_recv(sock, aes):
    while True:
        try:
            data = sock.recv(65536)
            if data.startswith(b"__FILE__"):
                parts = data[9:].split(b"__SEP__")
                filename = aes.decrypt(parts[0]).decode()
                filedata = aes.decrypt(parts[1])
                with open(f"received_{filename}", "wb") as f:
                    f.write(filedata)
                console.print(f"[cyan]Fichier reçu :[/cyan] received_{filename}")
            else:
                msg = aes.decrypt(data).decode()
                console.print(f"[bold blue]<< {msg}")
        except Exception as e:
            console.print("[red]Erreur :", e)
            break

# Fonction pour envoyer messages

def handle_send(sock, aes):
    while True:
        try:
            msg = Prompt.ask("[bold green]>>[/bold green]")
            if msg.lower().startswith("/file"):
                send_file(sock, aes)
            elif msg.lower() == "/exit":
                sock.close()
                sys.exit()
            else:
                sock.sendall(aes.encrypt(msg.encode()))
        except Exception as e:
            console.print("[red]Erreur d'envoi :", e)
            break

# Lancer le serveur

def start_server(port, key):
    aes = AESCipher(key)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", port))
    s.listen(1)
    console.print(f"[green]En attente de connexion sur le port {port}...")
    conn, addr = s.accept()
    console.print(f"[bold green]Connecté avec {addr}")
    threading.Thread(target=handle_recv, args=(conn, aes), daemon=True).start()
    handle_send(conn, aes)

# Lancer le client

def start_client(host, port, key):
    aes = AESCipher(key)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((host, port))
        console.print(f"[green]Connecté à {host}:{port}")
        threading.Thread(target=handle_recv, args=(s, aes), daemon=True).start()
        handle_send(s, aes)
    except Exception as e:
        console.print("[red]Connexion impossible :", e)

# Programme principal

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="trcom - Communication locale sécurisée en AES")
    parser.add_argument("--mode", choices=["server", "client"], required=True, help="Mode de fonctionnement")
    parser.add_argument("--host", help="Adresse IP du serveur (client uniquement)")
    parser.add_argument("--port", type=int, default=9999, help="Port d'écoute ou de connexion")
    parser.add_argument("--key", required=True, help="Clé de chiffrement partagée (même des deux côtés)")
    args = parser.parse_args()

    os.makedirs(".trcom_logs", exist_ok=True)

    if args.mode == "server":
        start_server(args.port, args.key)
    else:
        if not args.host:
            console.print("[red]--host requis en mode client")
            sys.exit(1)
        start_client(args.host, args.port, args.key)

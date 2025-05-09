import socket
import threading
import argparse
import os
import sys
import base64
import hashlib
import ipaddress
import concurrent.futures
import questionary
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import time
import bluetooth  # Importation pour Bluetooth

console = Console()

# Animation logo
def show_logo():
    logo = Text("""
 ████████╗██████╗ ██╗  ██╗ █████╗  ██████╗███╗   ██╗ ██████╗ ███╗   ██╗
 ╚══██╔══╝██╔══██╗██║  ██║██╔══██╗██╔════╝████╗  ██║██╔═══██╗████╗  ██║
    ██║   ██████╔╝███████║███████║██║     ██╔██╗ ██║██║   ██║██╔██╗ ██║
    ██║   ██╔═══╝ ██╔══██║██╔══██║██║     ██║╚██╗██║██║   ██║██║╚██╗██║
    ██║   ██║     ██║  ██║██║  ██║╚██████╗██║ ╚████║╚██████╔╝██║ ╚████║
    ╚═╝   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═══╝

              [trhacknon] Secure Terminal Messenger - trcom
    """, style="bold magenta")
    console.print(Panel(logo, style="green"))
    time.sleep(1)

# AES
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
        return iv + encryptor.update(padded_data) + encryptor.finalize()

    def decrypt(self, data: bytes) -> bytes:
        iv = data[:16]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(data[16:]) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(decrypted) + unpadder.finalize()

# Scan réseau local
def scan_network(port):
    local_ip = socket.gethostbyname(socket.gethostname())
    subnet = local_ip.rsplit('.', 1)[0] + '.0/24'
    found = []

    def try_connect(ip):
        try:
            s = socket.socket()
            s.settimeout(0.5)
            s.connect((str(ip), port))
            s.close()
            return str(ip)
        except:
            return None

    console.print("[yellow]Scan du réseau en cours...[/yellow]")
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(try_connect, ip) for ip in ipaddress.IPv4Network(subnet)]
        for f in concurrent.futures.as_completed(futures):
            if f.result():
                found.append(f.result())

    if found:
        choices = [f"{i}: {ip}" for i, ip in enumerate(found)]
        choice = questionary.select("Choisis un hôte à connecter :", choices=choices).ask()
        return found[int(choice.split(":")[0])]
    else:
        console.print("[red]Aucun hôte détecté.")
        sys.exit(1)

# Fonction Bluetooth pour scanner les appareils
def scan_bluetooth():
    console.print("[yellow]Scan Bluetooth en cours...[/yellow]")
    nearby_devices = bluetooth.discover_devices(duration=8, lookup_names=True, lookup_oui=True)
    if nearby_devices:
        choices = [f"{i}: {name} ({addr})" for i, (addr, name) in enumerate(nearby_devices)]
        choice = questionary.select("Choisis un appareil Bluetooth :", choices=choices).ask()
        return nearby_devices[int(choice.split(":")[0])][0]
    else:
        console.print("[red]Aucun appareil Bluetooth trouvé.")
        sys.exit(1)

# Envoi fichier
def send_file(sock, aes):
    filepath = questionary.path("Chemin du fichier à envoyer :").ask()
    if not filepath or not os.path.exists(filepath):
        console.print("[red]Fichier introuvable.")
        return

    with open(filepath, "rb") as f:
        data = f.read()
    filename = os.path.basename(filepath)
    sock.sendall(b"**FILE**" + aes.encrypt(filename.encode()) + b"**SEP**" + aes.encrypt(data))
    console.print(f"[green]Fichier '{filename}' envoyé.")

# Réception
def handle_recv(sock, aes):
    while True:
        try:
            data = sock.recv(65536)
            if data.startswith(b"**KEY**"):
                peer_key = data[8:].decode()
                console.print(f"[cyan]Clé reçue :[/cyan] {peer_key}")
            elif data.startswith(b"**FILE**"):
                parts = data[9:].split(b"**SEP**")
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

# Envoi
def handle_send(sock, aes):
    while True:
        try:
            msg = questionary.text(">>").ask()
            if not msg:
                continue
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

def start_server(port, key, is_bluetooth=False, bt_addr=None):
    aes = AESCipher(key)
    if is_bluetooth:
        server_sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
        server_sock.bind(("", bluetooth.PORT_ANY))
        server_sock.listen(1)
        console.print(f"[green]En attente de connexion Bluetooth...")
        client_sock, client_info = server_sock.accept()
        console.print(f"[bold green]Connecté avec {client_info}")
    else:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind(("0.0.0.0", port))
        server_sock.listen(1)
        console.print(f"[green]En attente de connexion sur le port {port}...")
        client_sock, addr = server_sock.accept()
        console.print(f"[bold green]Connecté avec {addr}")
    client_sock.sendall(b"**KEY**" + key.encode())
    threading.Thread(target=handle_recv, args=(client_sock, aes), daemon=True).start()
    handle_send(client_sock, aes)

def start_client(host, port, key, is_bluetooth=False):
    aes = AESCipher(key)
    if is_bluetooth:
        client_sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
        client_sock.connect((host, 1))  # Port 1 est le port par défaut pour RFCOMM
        console.print(f"[green]Connecté à Bluetooth {host}")
        client_sock.sendall(b"**KEY**" + key.encode())
        threading.Thread(target=handle_recv, args=(client_sock, aes), daemon=True).start()
        handle_send(client_sock, aes)
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((host, port))
            console.print(f"[green]Connecté à {host}:{port}")
            s.sendall(b"**KEY**" + key.encode())
            threading.Thread(target=handle_recv, args=(s, aes), daemon=True).start()
            handle_send(s, aes)
        except Exception as e:
            console.print("[red]Connexion impossible :", e)

# Entrée principale
if __name__ == "__main__":
    os.makedirs(".trcom_logs", exist_ok=True)
    show_logo()

    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["server", "client"])
    parser.add_argument("--host")
    parser.add_argument("--port", type=int, default=9999)
    parser.add_argument("--key")
    parser.add_argument("--scan", action="store_true")
    parser.add_argument("--bluetooth", action="store_true", help="Utiliser Bluetooth pour la connexion")
    args = parser.parse_args()

    if not args.mode:
        args.mode = questionary.select("Mode ?", choices=["server", "client"]).ask()

    if not args.key:
        args.key = questionary.text("Clé de chiffrement partagée :").ask()

    if args.bluetooth:
        if args.mode == "server":
            start_server(args.port, args.key, is_bluetooth=True)
        else:
            if args.scan:
                bt_addr = scan_bluetooth()
                start_client(bt_addr, args.port, args.key, is_bluetooth=True)
            else:
                start_client(args.host, args.port, args.key, is_bluetooth=True)
    else:
        if args.mode == "server":
            start_server(args.port, args.key)
        else:
            if args.scan:
                args.host = scan_network(args.port)
            elif not args.host:
                args.host = questionary.text("Adresse IP du serveur :").ask()
            start_client(args.host, args.port, args.key)

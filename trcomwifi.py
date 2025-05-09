import os
import socket
import hashlib
import questionary
import threading
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from rich.console import Console

console = Console()

class AESCipher:
    def __init__(self, key: str):
        # Génération de la clé en utilisant SHA-256
        digest = hashlib.sha256(key.encode()).digest()
        self.key = digest
        self.backend = default_backend()

    def encrypt(self, data: bytes) -> bytes:
        # Génération d'un IV aléatoire pour chaque chiffrement
        iv = os.urandom(16)
        
        # Padding des données avec PKCS7 pour que la taille soit un multiple de 16 octets
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        # Initialisation de l'algorithme AES en mode CBC
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        
        # Retourne l'IV suivi des données chiffrées
        return iv + encryptor.update(padded_data) + encryptor.finalize()

    def decrypt(self, data: bytes) -> bytes:
        # Extraction de l'IV des données chiffrées
        iv = data[:16]
        
        # Initialisation de l'algorithme AES en mode CBC
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        
        # Déchiffrement des données
        decrypted = decryptor.update(data[16:]) + decryptor.finalize()

        # Unpadding des données après déchiffrement
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(decrypted) + unpadder.finalize()

def send_message(sock, aes):
    while True:
        message = questionary.text("Votre message ou nom de fichier :").ask()
        if message.lower() == "exit":
            console.print("[red]Déconnexion du serveur...[/red]")
            sock.close()
            break

        # Vérifier si l'utilisateur souhaite envoyer un fichier
        if os.path.isfile(message):
            # Si c'est un fichier, l'envoyer avec un préfixe **FILE**
            with open(message, 'rb') as file:
                file_data = file.read()
                # Préfixer avec **FILE** et envoyer le nom du fichier
                file_message = f"**FILE**{os.path.basename(message)}".encode()
                sock.sendall(file_message)
                sock.sendall(file_data)  # Envoyer le contenu du fichier
            console.print(f"[green]Fichier '{message}' envoyé avec succès ![/green]")
        else:
            # Sinon, envoyer un message classique
            encrypted_message = aes.encrypt(message.encode())
            sock.sendall(encrypted_message)  # Envoi du message chiffré

def handle_recv(sock, aes):
    while True:
        try:
            data = sock.recv(65536)
            if not data:
                break  # Connexion fermée

            # Vérification du préfixe pour le type de données reçues
            if data.startswith(b"**KEY**"):
                peer_key = data[8:].decode()
                console.print(f"[cyan]Clé reçue :[/cyan] {peer_key}")
            elif data.startswith(b"**FILE**"):
                # Le message est un fichier
                file_name = data[7:].decode()
                console.print(f"[cyan]Réception du fichier : {file_name}[/cyan]")

                # Recevoir le contenu du fichier
                file_data = sock.recv(65536)  # Assurez-vous d'avoir un large buffer pour le fichier
                if file_data:
                    # Enregistrer le fichier dans le dossier 'received_files'
                    if not os.path.exists('received_files'):
                        os.makedirs('received_files')
                    with open(f'received_files/{file_name}', 'wb') as file:
                        file.write(file_data)
                    console.print(f"[green]Fichier {file_name} enregistré avec succès ![/green]")
            else:
                # Décryptage et affichage du message reçu
                msg = aes.decrypt(data).decode()
                console.print(f"[bold blue]<< {msg}")
        except Exception as e:
            console.print(f"[red]Erreur : {e}")
            break

def main():
    console.print("[bold green]Sécurisé avec AES et clé partagée.[/bold green]")

    # Demander la clé de chiffrement partagée et l'adresse IP du serveur
    key = questionary.text("Clé de chiffrement partagée :").ask()
    mode = questionary.select("Mode ?", choices=["client", "serveur"]).ask()

    # Création de l'objet AES pour le chiffrement
    aes = AESCipher(key)

    if mode == "client":
        ip = questionary.text("Adresse IP du serveur :").ask()
        port = 9999  # Le port à utiliser
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, port))

        # Clé envoyée au serveur
        sock.sendall(b"**KEY**" + key.encode())

        # Démarrage des threads pour gérer la réception et l'envoi en parallèle
        recv_thread = threading.Thread(target=handle_recv, args=(sock, aes))
        send_thread = threading.Thread(target=send_message, args=(sock, aes))

        recv_thread.start()
        send_thread.start()

        # Attente de la fin des threads
        recv_thread.join()
        send_thread.join()

    else:
        # Serveur - écoute sur le port spécifié
        port = 9999
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('0.0.0.0', port))
        sock.listen(1)
        console.print(f"[cyan]Serveur en écoute sur le port {port}...[/cyan]")
        
        conn, addr = sock.accept()
        console.print(f"[cyan]Connexion de {addr} établie.[/cyan]")

        # Réception de la clé du client
        data = conn.recv(1024)
        if data.startswith(b"**KEY**"):
            peer_key = data[8:].decode()
            console.print(f"[cyan]Clé reçue :[/cyan] {peer_key}")

        # Démarrage des threads pour gérer la réception et l'envoi en parallèle
        recv_thread = threading.Thread(target=handle_recv, args=(conn, aes))
        send_thread = threading.Thread(target=send_message, args=(conn, aes))

        recv_thread.start()
        send_thread.start()

        # Attente de la fin des threads
        recv_thread.join()
        send_thread.join()

if __name__ == "__main__":
    main()

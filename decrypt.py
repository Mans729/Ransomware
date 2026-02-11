#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from tqdm import tqdm

def load_key(key_path):
    """Charge la clé depuis le fichier JSON sauvegardé."""
    try:
        with open(key_path, 'r') as f:
            data = json.load(f)
        
        # On récupère la chaîne base64 et on la convertit en bytes
        key_b64 = data.get("key_b64")
        if not key_b64:
            print(" [!] Format de fichier clé invalide (key_b64 manquant).")
            return None
            
        return base64.b64decode(key_b64)
    except Exception as e:
        print(f" [!] Erreur lors du chargement de la clé : {e}")
        return None

def decrypt_file(filepath, key_bytes):
    """Déchiffre un fichier (AES-GCM)."""
    try:
        # Initialisation du moteur AES-GCM avec la clé
        aesgcm = AESGCM(key_bytes)
        
        with open(filepath, 'rb') as f:
            # 1. On lit les 12 premiers octets (le Nonce/IV)
            nonce = f.read(12)
            # 2. On lit le reste (les données chiffrées + le tag d'intégrité)
            ciphertext = f.read()
        
        # 3. Déchiffrement
        # Si la clé est mauvaise ou le fichier corrompu, cela lèvera une exception
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        # 4. Écriture du fichier original (Écrase le fichier chiffré)
        with open(filepath, 'wb') as f:
            f.write(plaintext)
            
        return True
    except Exception as e:
        # Cette erreur arrive souvent si on utilise la mauvaise clé
        return False

def main():
    print("=== OUTIL DE DÉCHIFFREMENT ===")
    
    # 1. Demander le fichier de clé
    key_path = input(" Chemin vers le fichier clé (.json) : ").strip().strip("'").strip('"')
    
    if not os.path.isfile(key_path):
        print(" [!] Fichier clé introuvable.")
        sys.exit(1)
        
    key_bytes = load_key(key_path)
    if not key_bytes:
        sys.exit(1)
    print(f" [v] Clé chargée avec succès.")

    # 2. Demander le dossier à déchiffrer
    target_path = input(" Chemin du dossier ou fichier à DÉCHIFFRER : ").strip().strip("'").strip('"')
    
    if not os.path.exists(target_path):
        print(" [!] Cible introuvable.")
        sys.exit(1)

    # Liste des fichiers à traiter
    files_to_decrypt = []
    if os.path.isfile(target_path):
        files_to_decrypt.append(target_path)
    else:
        for root, dirs, files in os.walk(target_path):
            for file in files:
                # On évite de déchiffrer le script lui-même ou la clé
                if not file.endswith(".py") and not file.endswith(".json"):
                    files_to_decrypt.append(os.path.join(root, file))

    if not files_to_decrypt:
        print(" [!] Aucun fichier trouvé.")
        sys.exit()

    print(f" [*] {len(files_to_decrypt)} fichiers identifiés pour déchiffrement.")
    confirm = input(" Confirmer le déchiffrement ? (O/N) : ").lower()
    
    if confirm != 'o':
        print(" Annulation.")
        sys.exit()

    # 3. Lancement du processus
    success_count = 0
    error_count = 0
    
    for filepath in tqdm(files_to_decrypt, desc="Déchiffrement"):
        if decrypt_file(filepath, key_bytes):
            success_count += 1
        else:
            error_count += 1
            print(f" [x] Échec sur : {filepath} (Mauvaise clé ?)")

    print("\n=== RAPPORT ===")
    print(f" [v] Déchiffrés : {success_count}")
    print(f" [x] Échecs     : {error_count}")

if __name__ == "__main__":
    main()
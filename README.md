# TD-03 : Ransomware Simulator (Outil Éducatif)

Ce projet est un simulateur de ransomware développé dans un cadre pédagogique pour le cours de cybersécurité. Il illustre des concepts de chiffrement modernes : gestion de clés symétriques, chiffrement in-place et exfiltration de clés.

⚠️ AVERTISSEMENT

Ce programme effectue un chiffrement destructif (écrasement des fichiers originaux). À UTILISER UNIQUEMENT dans un environnement de laboratoire isolé (machine virtuelle) et sur des fichiers de test.

**Sommaire**

- **Description**: simulateur pédagogique montrant génération/stockage de clés, exfiltration SFTP et chiffrement AES-GCM in-place.
- **Langage**: Python 3.8+
- **Usage principal**: `main.py` (génération de clé, exfiltration, chiffrement)
- **Restauration**: `decrypt.py` (décryptage à partir du fichier clé JSON)

**Fonctionnalités**

Le projet couvre les fonctionnalités demandées :

| Fonctionnalité | Détails |
|---|---|
| **Vérification des dépendances** | ✅ Vérification automatique de Python 3.8+ et proposition d'installation des bibliothèques manquantes. |
| **Menu Principal** | ✅ Interface textuelle interactive et robuste. |
| **Génération de Clés** | ✅ Support AES-256 (aléatoire) et dérivation via PBKDF2. |
| **Stockage Sécurisé** | ✅ Sauvegarde JSON dans `/var/keys/` avec permissions restreintes (Unix) — permissions `600`. |
| **Transfert SFTP** | ✅ Exfiltration simulée de la clé vers un serveur distant via `paramiko`. |
| **Chiffrement** | ✅ AES-GCM (in-place) avec traitement récursif des dossiers. |
| **Expérience Utilisateur** | ✅ Barre de progression pour opérations longues (`tqdm`). |

🛠️ Prérequis et installation

Système recommandé : Linux (VM). Windows possible.

- Python 3.8 ou supérieur
- Installer les dépendances :

```bash
pip install -r requirements.txt
```

(Le script `main.py` propose d'installer automatiquement les dépendances si elles sont absentes.)

🚀 Utilisation — Chiffrement (`main.py`)

Lancer le script principal (les droits administrateur peuvent être nécessaires pour écrire dans `/var/keys/`) :

```bash
sudo python3 main.py
```

Étapes typiques :

1. **Génération de clé (Option 1)**
   - Choisir l'algorithme : AES (clé aléatoire AES-256) ou PBKDF2 (clé dérivée d'un mot de passe).
   - La clé est sauvegardée localement (ex : `/var/keys/key_AES_256_YYYYMMDDHHMMSS.json`).
   - Le script détecte l'existence d'une clé et propose de la recharger plutôt que de la régénérer.

2. **Exfiltration (Option 2)**
   - Envoyer la clé générée vers un serveur distant via SFTP (paramètres fournis par l'utilisateur) pour simuler l'exfiltration.

3. **Chiffrement (Option 3)**
   - Sélectionner un fichier ou un dossier cible.
   - Le script chiffre récursivement les fichiers trouvés en utilisant AES-GCM.
   - Mode : chiffrement in-place — le fichier original est écrasé par les données chiffrées préfixées du Nonce (12 octets).

🔓 Utilisation — Déchiffrement (`decrypt.py`)

Ce script restaure les fichiers chiffrés. Il nécessite impérativement le fichier de clé `.json` généré lors de la phase de chiffrement.

```bash
sudo python3 decrypt.py
```

- **Entrée Clé**: chemin vers le fichier clé (ex : `/var/keys/key_AES_256_YYYYMMDDHHMMSS.json`).
- **Cible**: dossier ou fichier chiffré.
- **Processus**: le script extrait le Nonce depuis le début du fichier, déchiffre le contenu et restaure le fichier original.

📂 Structure du projet

Conforme aux contraintes techniques :

```
td3_chiffrement/
├── main.py            # Script principal (génération, SFTP, chiffrement)
├── decrypt.py         # Script de restauration
├── requirements.txt   # Dépendances (cryptography, paramiko, tqdm)
└── README.md          # Documentation
```

🔒 Détails techniques

- **Algorithme de chiffrement** : AES-GCM (authenticité + confidentialité).
- **Dérivation de clé** : PBKDF2-HMAC-SHA256 (100000 itérations + salt unique).
- **Format de stockage de la clé** : JSON contenant les métadonnées nécessaires (algorithme, salt, iterations, clé encodée en base64 si applicable).
- **Nonce** : 12 octets préfixés au contenu chiffré dans le fichier.
- **Gestion des erreurs** : blocs `try/except` pour erreurs I/O et erreurs réseau (SFTP).
- **Permissions** : les fichiers de clés sont écrits avec permission `600` sur les systèmes Unix.

Sécurité et éthique

Ce dépôt est fourni à des fins éducatives uniquement. N'utilisez jamais ce code contre des systèmes ou des données sans autorisation explicite. Toute utilisation malveillante est strictement interdite.

Support

Pour toute question pédagogique ou remarque, contactez l'équipe enseignante responsable du TD.

---

*Fait pour le TD-03 — simulateur pédagogique de ransomware.*

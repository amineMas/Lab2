# Lab 2 — SAST avec Semgrep

**Durée :** 1h &nbsp;|&nbsp; **Stack :** Python / Flask &nbsp;|&nbsp; **Outil :** Semgrep

---

## Contexte

L'API interne `freemobile-netops-api` (gestion d'équipements réseau NOC) va passer en production.
Un audit SAST est requis. L'application contient **6 vulnérabilités** à détecter et corriger.

---

## Prérequis

```bash
# Vérifier les installations
docker --version
semgrep --version   # sinon : pip install semgrep
```

---

## Lancer l'application

```bash
git clone https://github.com/RomdhaniYacine/Lab2.git
cd Lab2
docker compose up
```

Tester que l'app répond :

```bash
curl http://localhost:5000/health
curl http://localhost:5000/api/v1/equipment
```

---

## Étape 1 — Scanner avec Semgrep (en ligne de commande)

### 1.1 — Premier scan

```bash
semgrep --config p/python app.py
```

Semgrep affiche les vulnérabilités détectées avec le fichier, la ligne, et une explication.

### 1.2 — Voir le code incriminé

```bash
semgrep --config p/python app.py --verbose
```

### 1.3 — Exporter le rapport en JSON

```bash
semgrep --config p/python app.py --json > semgrep-report.json
cat semgrep-report.json | python3 -m json.tool
```

**Questions :**
- Combien de vulnérabilités ont été détectées ?
- Quelles sont celles que Semgrep a **manquées** en regardant le code ? (MD5, random)
- Quel est l'exit code de Semgrep quand il trouve des problèmes ?

```bash
echo "Exit code : $?"
# 0 = aucun finding  |  1 = findings détectés
```

---

## Étape 2 — Corriger le code

Voici les 6 corrections à appliquer dans `app.py` :

### Vuln 1 — SQL Injection (ligne ~60)

```python
# Avant — concaténation directe → SQLi
rows = conn.execute(
    f"SELECT * FROM equipment WHERE hostname LIKE '%{query}%'"
).fetchall()

# Après — requête paramétrée
rows = conn.execute(
    "SELECT * FROM equipment WHERE hostname LIKE ? OR site LIKE ?",
    (f"%{query}%", f"%{query}%")
).fetchall()
```

### Vuln 2 — Command Injection (ligne ~73)

```python
# Avant — shell=True + input user
result = subprocess.run(f"ping -c 2 {ip}", shell=True, ...)

# Après — liste d'args + validation IP
import ipaddress
try:
    ipaddress.ip_address(ip)
except ValueError:
    return jsonify({"error": "IP invalide"}), 400
result = subprocess.run(["ping", "-c", "2", ip], capture_output=True, text=True, timeout=10)
```

### Vuln 3 — MD5 pour les mots de passe (ligne ~88)

```python
# Avant — MD5 sans sel, cassable
hashed = hashlib.md5(password.encode()).hexdigest()

# Après — SHA-256 avec sel
import os
salt = os.urandom(16).hex()
hashed = hashlib.sha256((salt + password).encode()).hexdigest()
```

### Vuln 4 — Insecure Deserialization pickle (ligne ~100)

```python
# Avant — pickle sur données HTTP → RCE possible
config = pickle.loads(raw)

# Après — JSON uniquement
import json
try:
    config = json.loads(raw)
except json.JSONDecodeError:
    return jsonify({"error": "JSON invalide"}), 400
```

### Vuln 5 — eval() sur input utilisateur (ligne ~111)

```python
# Avant — eval() → exécution de code arbitraire
result = eval(rule)

# Après — ast.literal_eval() limité aux types simples
import ast
try:
    result = ast.literal_eval(rule)
except (ValueError, SyntaxError):
    return jsonify({"error": "Expression invalide"}), 400
```

### Vuln 6 — Token généré avec random (ligne ~121)

```python
# Avant — random prévisible, pas cryptographiquement sûr
token = str(random.randint(100000, 999999))

# Après — secrets pour tout usage sécurité
import secrets
token = secrets.token_hex(32)
```

### Vérifier les corrections

```bash
semgrep --config p/python app.py
echo "Exit code : $?"
# Résultat attendu : 0 finding, exit code 0
```

---

## Étape 3 — Pipeline CI GitHub Actions

Ouvrez `.github/workflows/security.yml` et décommentez le bloc `TODO` :

```yaml
      # Remplacer les lignes commentées par :
      - name: Semgrep scan
        run: semgrep --config p/python --error app.py
```

Committer et pousser :

```bash
git add app.py .github/workflows/security.yml
git commit -m "fix: corrections SAST + pipeline Semgrep"
git push
```

Vérifier le pipeline sur `https://github.com/RomdhaniYacine/Lab2/actions`.

**Avec le code vulnérable :** le pipeline échoue (exit code 1).  
**Avec le code corrigé :** le pipeline passe (exit code 0).

---

## Checklist de réussite

```
[ ] semgrep --config p/python app.py  →  0 finding après corrections
[ ] SQL injection corrigée  (requête paramétrée)
[ ] Command injection corrigée  (liste d'args + validation IP)
[ ] MD5 remplacé  (sha256 avec sel)
[ ] pickle remplacé  (json.loads)
[ ] eval() remplacé  (ast.literal_eval)
[ ] random remplacé  (secrets.token_hex)
[ ] Pipeline CI vert sur GitHub
```

---

## Solution

Le code corrigé et le pipeline complet sont dans `solution/`.

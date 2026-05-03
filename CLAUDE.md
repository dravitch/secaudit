# SECAUDIT — Instructions Claude Code
> Déposer ce fichier à la racine du repo `dravitch/secaudit` sous le nom `CLAUDE.md`
> Claude Code (Opus 4.7) lit ce fichier au démarrage de chaque session.

---

## 0. Contexte du projet

Tu travailles sur **SecAudit / Mini-Mythos** : un agent de sécurité passif et semi-actif
qui audite la robustesse des sites web modernes, avec un focus sur la surface phishing
(clonage d'interface, typosquatting, absence SPF/DMARC/DNSSEC).

Site de référence initial : `https://telemo.gov.gn` (portail marchés publics Guinée).

**Ce que tu dois construire dans ce repo :**

1. L'environnement NixOS reproductible (`shell.nix` + `flake.nix`)
2. Le pipeline Python en 5 sprints (recon passif → scan → phishing surface → vecteurs → CriticAgent)
3. Le dashboard HTML/CSS/JS (fichier `ui/dashboard.html` — version Oblivion déjà conçue)
4. Les résultats de scan restent **privés** : jamais committés, jamais pushés

---

## 1. Mindsets obligatoires (à respecter pour tout code écrit)

```
1.  Ground Truth or Silence      — aucune affirmation sans preuve dans les logs
2.  Minimal Working Example First — 1 fichier, 1 outil, 1 test avant d'étendre
3.  One Fact Per Step            — valider un fait vérifiable à chaque étape
4.  No Hidden State              — toutes les hypothèses explicites dans le JSON
9.  Test Before Trust            — chaque wrapper testé sur 127.0.0.1 ou DVWA avant usage
10. API Contract First           — schéma JSON finding défini avant les agents
7.  Fail Fast, Explain Faster    — si CriticAgent retourne REJECTED, le rapport explique
15. Explainability First         — rapport lisible par auditeur humain en 30 secondes
```

---

## 2. Structure cible du repo

Crée exactement cette arborescence si elle n'existe pas :

```
secaudit/
├── CLAUDE.md                  ← ce fichier
├── README.md                  ← à générer
├── .gitignore                 ← inclure results/, .env, *.json sauf schemas/
├── shell.nix                  ← environnement NixOS non-flake (prioritaire)
├── flake.nix                  ← version flake (alternative)
├── flake.lock                 ← généré par nix flake lock
│
├── config/
│   ├── scope.yaml             ← cibles autorisées (OBLIGATOIRE avant tout scan)
│   └── settings.py            ← ANTHROPIC_API_KEY, seuils, modèles
│
├── agents/
│   ├── analyst_agent.py       ← Claude Sonnet : interprète findings bruts
│   └── critic_agent.py        ← modèle indépendant, temperature=0, prompt adversarial
│
├── tools/
│   ├── recon.py               ← wrapper nmap + theHarvester → JSON
│   ├── scanner.py             ← wrapper humble + testssl.sh → JSON
│   ├── phishing_surface.py    ← clone surface : assets, SRI, typosquat
│   └── validator.py           ← vérifications manuelles curl/httpx
│
├── schemas/
│   └── finding.py             ← Pydantic : schéma Finding (contrat API)
│
├── reports/
│   ├── reporter.py            ← génère Markdown depuis findings validés
│   └── templates/
│       └── report.md.j2       ← template Jinja2
│
├── ui/
│   └── dashboard.html         ← dashboard Oblivion (déjà conçu, à intégrer)
│
├── results/                   ← JAMAIS commité (.gitignore)
│   └── .gitkeep
│
├── tests/
│   ├── test_schema.py
│   ├── test_recon.py
│   └── test_critic.py
│
└── main.py                    ← orchestrateur séquentiel S1→S5
```

---

## 3. Environnement NixOS — `shell.nix`

Crée `shell.nix` à la racine avec ce contenu :

```nix
{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  name = "secaudit";

  buildInputs = with pkgs; [
    # Python
    python311
    python311Packages.pip
    python311Packages.virtualenv
    uv                          # gestionnaire de paquets Python rapide

    # Outils réseau passifs
    nmap
    curl
    httpie
    dnsutils                    # dig, nslookup
    whois

    # Outils sécurité web
    nikto
    testssl

    # Build deps pour paquets Python natifs
    gcc
    libffi
    openssl.dev
    zlib

    # Utilitaires
    jq
    git
    gnumake
  ];

  shellHook = ''
    echo "╔══════════════════════════════════════╗"
    echo "║  SecAudit — Mini-Mythos Environment  ║"
    echo "║  NixOS shell ready                   ║"
    echo "╚══════════════════════════════════════╝"

    # Crée le venv Python si absent
    if [ ! -d ".venv" ]; then
      echo "[uv] Creating virtual environment..."
      uv venv .venv
    fi

    source .venv/bin/activate

    # Installe les dépendances Python si requirements.txt présent
    if [ -f "requirements.txt" ]; then
      echo "[uv] Syncing dependencies..."
      uv pip install -r requirements.txt
    fi

    export SECAUDIT_ENV=nixos
    echo "[ok] Environment activated — python: $(python --version)"
  '';
}
```

---

## 4. Environnement NixOS — `flake.nix` (alternative reproductible)

Crée `flake.nix` à la racine :

```nix
{
  description = "SecAudit — Mini-Mythos security pipeline";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in {
        devShells.default = pkgs.mkShell {
          name = "secaudit";

          packages = with pkgs; [
            python311
            uv
            nmap
            curl
            dnsutils
            whois
            nikto
            testssl
            jq
            git
            gcc
            openssl.dev
            zlib
            libffi
          ];

          shellHook = ''
            echo "[secaudit] flake dev shell — $(uname -r)"
            if [ ! -d ".venv" ]; then
              uv venv .venv
            fi
            source .venv/bin/activate
            if [ -f "requirements.txt" ]; then
              uv pip install -r requirements.txt --quiet
            fi
            export SECAUDIT_ENV=nixos-flake
          '';
        };
      }
    );
}
```

Après création : `nix flake lock` pour générer `flake.lock`.

---

## 5. Dépendances Python — `requirements.txt`

Crée `requirements.txt` :

```
# Core
httpx>=0.27.0
pydantic>=2.6.0
python-dotenv>=1.0.0
jinja2>=3.1.0
pyyaml>=6.0.1

# Anthropic
anthropic>=0.28.0

# Analyse sécurité
beautifulsoup4>=4.12.3
lxml>=5.2.0

# CLI & affichage
typer>=0.12.0
rich>=13.7.0

# Tests
pytest>=8.0.0
pytest-asyncio>=0.23.0
respx>=0.21.0
```

---

## 6. Schéma Finding — `schemas/finding.py`

**Créer en premier** (Mindset 10 — API Contract First) :

```python
"""
schemas/finding.py
Contrat API central — tout agent produit et consomme ce schéma.
"""
from pydantic import BaseModel, Field
from typing import Literal, Optional
from datetime import datetime


class Finding(BaseModel):
    # Identité
    id: str = Field(..., description="UUID du finding")
    sprint: int = Field(..., ge=1, le=5)
    tool: str
    target: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Description
    title: str
    finding: str = Field(..., description="Description brute du résultat")
    evidence: list[str] = Field(default_factory=list, description="Preuves objectives (logs, codes HTTP)")

    # Analyse AnalystAgent
    analyst_conclusion: str
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    # Verdict CriticAgent
    critic_verdict: Literal["CONFIRMED", "NUANCED", "REJECTED", "PENDING"] = "PENDING"
    critic_rationale: str = ""
    confidence_score: float = Field(0.0, ge=0.0, le=1.0)
    flags: list[Literal[
        "CONTEXT_DEPENDENT",
        "NEEDS_RETEST",
        "FALSE_POSITIVE_RISK",
        "PHISHING_VECTOR",
        "CHAIN_DEPENDENCY"
    ]] = Field(default_factory=list)
```

Ne commence aucun agent avant que ce schéma soit validé par `pytest tests/test_schema.py`.

---

## 7. Fichier de scope — `config/scope.yaml`

Crée ce fichier. **Aucun scan ne démarre si la cible n'est pas listée ici.**

```yaml
# config/scope.yaml
# Cibles autorisées — modifier avant chaque engagement

authorized_targets:
  - host: "telemo.gov.gn"
    protocol: "https"
    sprint_max: 5          # tous les sprints autorisés
    notes: "Portail marchés publics Guinée — audit passif uniquement"

# Cibles de test local (toujours autorisées)
  - host: "127.0.0.1"
    protocol: "http"
    sprint_max: 5
    notes: "DVWA local pour tests"

  - host: "localhost"
    protocol: "http"
    sprint_max: 5
    notes: "Tests unitaires"

# Règles globales
rules:
  active_scan_requires_explicit: true   # Sprint 2+ nécessite confirmation
  results_public: false                  # Jamais de résultats dans le repo
  results_dir: "./results"               # Local uniquement
```

---

## 8. `.gitignore`

Crée `.gitignore` :

```
# Résultats — JAMAIS publics
results/
*.findings.json
*_report.md
*_report.json

# Secrets
.env
.env.*
config/secrets.py

# Python
.venv/
__pycache__/
*.pyc
*.pyo
.pytest_cache/

# NixOS
.direnv/
result
result-*

# Éditeurs
.vscode/
.idea/
*.swp

# OS
.DS_Store
Thumbs.db
```

---

## 9. Ordre d'implémentation (sessions Claude Code)

Respecter cet ordre strict (Mindset 2 — MWE First) :

### Session 1 — Fondation
```
1. Créer arborescence complète (mkdir -p + touch)
2. Créer shell.nix et flake.nix
3. Créer requirements.txt
4. Créer schemas/finding.py
5. Écrire tests/test_schema.py et valider : pytest tests/test_schema.py
6. Commit : "chore: project scaffold + nix environment + Finding schema"
```

### Session 2 — Sprint 1 (recon passif)
```
1. Créer tools/recon.py (nmap wrapper → Finding JSON)
2. Créer tests/test_recon.py — tester sur 127.0.0.1
3. Créer tools/scanner.py (humble-like HTTP headers via httpx)
4. Tester : python tools/recon.py --target 127.0.0.1
5. Commit : "feat(s1): recon + HTTP surface tools"
```

### Session 3 — Sprint 2 (TLS/DNS)
```
1. Ajouter testssl.sh wrapper dans tools/scanner.py
2. Ajouter checks DNS (dig via subprocess) : DNSSEC, SPF, DMARC
3. Tester sur telemo.gov.gn (passif uniquement)
4. Commit : "feat(s2): TLS + DNS checks"
```

### Session 4 — Sprint 3+4 (phishing surface)
```
1. Créer tools/phishing_surface.py
   - Login page parser (BeautifulSoup)
   - SRI checker sur assets externes
   - Typosquat generator (DGA-light : homoglyphes, insertions, suppression)
2. Tester sur telemo.gov.gn
3. Commit : "feat(s3-s4): phishing surface + delivery vectors"
```

### Session 5 — Agents IA
```
1. Créer agents/analyst_agent.py (prompt AnalystAgent ci-dessous)
2. Créer agents/critic_agent.py (prompt CriticAgent ci-dessous)
3. Tester : python -m pytest tests/test_critic.py
4. Commit : "feat(s5): AnalystAgent + CriticAgent"
```

### Session 6 — Orchestrateur + Dashboard
```
1. Créer main.py avec pipeline S1→S5
2. Créer reports/reporter.py
3. Intégrer ui/dashboard.html (déjà conçu)
4. Test end-to-end sur 127.0.0.1/DVWA
5. Commit : "feat: full pipeline + dashboard integration"
```

---

## 10. Prompts des agents IA

### AnalystAgent — `agents/analyst_agent.py`

```python
ANALYST_SYSTEM_PROMPT = """
Tu es un analyste de sécurité expert. Tu reçois des données brutes de scan (JSON)
et tu dois produire une analyse structurée.

Règles strictes :
- N'affirme rien sans preuve dans les données (Ground Truth or Silence)
- Chaque conclusion doit citer une evidence spécifique
- Si les données sont insuffisantes : severity=INFO, conclusion="Données insuffisantes — NEEDS_RETEST"
- Retourne UNIQUEMENT du JSON valide correspondant au schéma Finding
- Pas de markdown, pas de prose, uniquement JSON

Format de sortie : liste de Finding objects (JSON array)
"""
```

### CriticAgent — `agents/critic_agent.py`

```python
CRITIC_SYSTEM_PROMPT = """
Tu es un agent contradictoire. Tu reçois des findings produits par un analyste
et tu dois les challenger avec rigueur.

Pour chaque finding :
1. Vérifie que l'evidence citée supporte réellement la conclusion
2. Identifie les variables confondantes possibles (VPN, CDN, contexte réseau)
3. Attribue un confidence_score entre 0.0 et 1.0
4. Retourne un verdict : CONFIRMED / NUANCED / REJECTED

Exemples de raisonnement critique attendu :
- Erreurs DNS présentes MAIS disparaissent derrière VPN → NUANCED, CONTEXT_DEPENDENT
- SPF absent confirmé par dig TXT ∅ + test envoi → CONFIRMED 0.94
- Header absent MAIS site derrière WAF qui le strip → NUANCED, NEEDS_RETEST

Règles :
- temperature=0 (tu es appelé avec temperature=0, sois déterministe)
- Ne jamais retourner CONFIRMED sans citer une vérification indépendante
- Retourne UNIQUEMENT du JSON valide (array de findings avec champs critic_*)
- Pas de markdown, pas de prose
"""
```

---

## 11. Logique de barrière (à implémenter dans `reports/reporter.py`)

```python
def classify_finding(f: Finding) -> str:
    """
    Retourne la section du rapport où va ce finding.
    """
    if f.critic_verdict == "REJECTED":
        return "findings_rejected"
    if f.critic_verdict == "PENDING":
        return "findings_pending"
    if f.confidence_score >= 0.75 and f.critic_verdict == "CONFIRMED":
        return "findings_confirmed"      # → rapport principal
    if f.confidence_score >= 0.50 or f.critic_verdict == "NUANCED":
        return "findings_investigate"    # → section "à investiguer"
    return "findings_rejected"
```

---

## 12. Commandes de test rapide

Une fois l'environnement prêt (`nix-shell` ou `nix develop`) :

```bash
# Vérifier l'env
nix-shell --run "python --version && nmap --version && dig --version"

# Schéma
pytest tests/test_schema.py -v

# Sprint 1 — recon local
python tools/recon.py --target 127.0.0.1 --output results/test_recon.json

# Sprint 1 — headers HTTP
python tools/scanner.py --target https://telemo.gov.gn --output results/test_headers.json

# Sprint 2 — DNS
python tools/scanner.py --target telemo.gov.gn --mode dns --output results/test_dns.json

# Sprint 3 — phishing surface
python tools/phishing_surface.py --target https://telemo.gov.gn --output results/test_phishing.json

# Pipeline complet
python main.py --target telemo.gov.gn --sprints 1,2,3,4,5

# Dashboard
python -m http.server 8080 --directory ui/
# → ouvrir http://localhost:8080/dashboard.html
```

---

## 13. Contraintes de sécurité (non négociables)

- **Jamais de scan actif** (ZAP, Nikto en mode actif, SQLmap) sur une cible sans autorisation explicite dans `config/scope.yaml`
- **Jamais de résultats** dans le repo (`.gitignore` strict sur `results/`)
- **Jamais de clés API** dans le code — utiliser `.env` + `python-dotenv`
- **Jamais de publication** de vulnérabilités sans disclosure responsible
- Les sprints S3 et S4 (phishing surface) sont **passifs** : lecture seule, aucune connexion active, aucun formulaire soumis

---

## 14. Variables d'environnement (`.env` — non commité)

```env
ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxx
CLAUDE_MODEL_ANALYST=claude-sonnet-4-6
CLAUDE_MODEL_CRITIC=claude-sonnet-4-6
CRITIC_TEMPERATURE=0
CONFIDENCE_THRESHOLD_CONFIRM=0.75
CONFIDENCE_THRESHOLD_INVESTIGATE=0.50
RESULTS_DIR=./results
SECAUDIT_LOG_LEVEL=INFO
```

---

## 15. README.md à générer

Génère `README.md` avec :
- Description du projet (2 paragraphes max)
- Structure du repo (copier §2)
- Instructions d'installation NixOS :
  ```bash
  git clone https://github.com/dravitch/secaudit
  cd secaudit
  nix-shell          # ou : nix develop (flake)
  cp .env.example .env && nano .env
  pytest tests/
  python main.py --target telemo.gov.gn
  ```
- Lien vers CLAUDE.md pour les instructions complètes
- Mention : résultats privés, jamais dans le repo

---

*Ce fichier est le point d'entrée de chaque session Claude Code.
Lis-le en entier avant toute action. Respecte l'ordre des sessions (§9).*

-------------------------------------------------------------------
19 h 15
Claude a répondu : Session 1 parfaite — 9/9, env NixOS propre, uv à 37 packages en 12ms.

Session 1 parfaite — 9/9, env NixOS propre, uv à 37 packages en 12ms. Le contrat API tient.

Avant de dire go pour Session 2, un point de clarification rapide :

En attendant ta réponse, voici ce que Session 2 va produire concrètement pour que tu saches quoi reviewer dans la PR :

tools/recon.py — nmap via subprocess sur le(s) port(s) 80/443, output XML parsé, 1 Finding par port ouvert avec evidence = la ligne nmap brute. Test : test_recon.py mocke subprocess avec respx-style patch.

tools/scanner.py — 60 headers analysés via httpx, chaque header manquant ou mal configuré → 1 Finding. La liste des headers vient d'une constante dans le fichier, pas d'un outil externe. Ça garde la dépendance à zéro et le code auditable.

Ce qui ne sera PAS dans Session 2 : testssl.sh (c'est Session 3 / Sprint 2 DNS+TLS), phishing surface (Session 4). On reste strict sur l'ordre du CLAUDE.md.

Dis-moi tes choix et je donne le go à Claude Code.

-------------------------------------------------------------------

## PROMPT #2

Session 2 — Sprint 1 (CLAUDE.md §9)

Implémente tools/recon.py et tools/scanner.py dans cet ordre strict :

1. tools/recon.py
   - Wrapper nmap via subprocess (pas de librairie python-nmap)
   - Scan ports 80 et 443, output XML parsé avec xml.etree
   - 1 Finding par port ouvert, severity selon port (443=LOW/INFO, autre=MEDIUM)
   - evidence = ligne nmap brute exacte
   - Vérifier scope.yaml avant tout scan (rejeter si cible absente)
   - CLI : python tools/recon.py --target <host> --output results/<file>.json

2. tests/test_recon.py
   - Mocker subprocess.run pour éviter un vrai nmap
   - Tester : port ouvert → Finding valide, port fermé → liste vide,
     cible hors scope → ValueError, output JSON roundtrip avec Finding schema
   - pytest tests/test_recon.py -v → GREEN obligatoire avant d'aller plus loin

3. tools/scanner.py
   - Analyse HTTP headers via httpx (primary) + subprocess curl (fallback si timeout >10s)
   - 60 headers analysés (liste exhaustive dans le fichier comme constante HEADERS_CHECKS)
   - 1 Finding par header absent ou mal configuré
   - evidence = valeur brute du header ou "header absent" + méthode (httpx|curl)
   - severity : CSP absent=HIGH, X-Frame-Options absent=MEDIUM, Server exposé=LOW, etc.
   - CLI : python tools/scanner.py --target https://<host> --output results/<file>.json

4. tests/test_scanner.py
   - Mocker httpx.get avec respx
   - Tester : header absent → Finding severity correct, header présent → pas de Finding,
     httpx timeout → fallback curl déclenché, output conforme schema
   - pytest tests/ -v → tous GREEN

5. Exécuter sur telemo.gov.gn (dans scope.yaml ✓)
   python tools/recon.py --target telemo.gov.gn --output results/s1_recon_telemo.json
   python tools/scanner.py --target https://telemo.gov.gn --output results/s1_headers_telemo.json
   Afficher un résumé console (rich table) : N findings, severity breakdown

6. Commit : "feat(s1): recon + HTTP surface tools"
   NE PAS commiter results/ (gitignore actif)
   PR mise à jour ou nouvelle PR selon workflow actuel

------------------------------------------

Lecture des deux JSON bruts avant tout jugement.Audit complet. Voici le verdict avant de donner le prompt.

---

## Audit Sprint 1 — Verdict : ✅ GO Sprint 2 (TLS/DNS), avec 3 observations à corriger dans la même session

### Ce qui est solide

**Structure JSON** — conforme au schéma Finding à 100%. Tous les champs obligatoires présents, `critic_verdict: PENDING` correct à ce stade, `evidence` contient les valeurs brutes réelles. Le roundtrip Pydantic passera sans friction.

**29/29 tests** — couverture sérieuse, fallback curl testé, scope enforcement vérifié avant subprocess. C'est exactement Mindset 9.

**Résultats réels cohérents** — le scanner a tourné en live sur telemo.gov.gn. Les findings reflètent ce qu'on voit : Apache exposé, JSESSIONID sans SameSite, CSP présente mais permissive.

---

### 3 observations à corriger en Session 3 (pas bloquantes pour avancer, mais à adresser)

**1. HSTS manquant dans le JSON mais présent dans le résumé console**
Le résumé console dit `HIGH: 2 (HSTS missing, CSP missing)` mais dans le JSON livré il n'y a pas de finding `HSTS missing` — seulement 12 findings dont aucun sur HSTS. Soit il est dans un JSON non livré, soit il y a un bug de sérialisation. Claude Code doit vérifier et corriger.

**2. Deux findings CSP redondants sans flag CHAIN_DEPENDENCY**
`CSP allows unsafe-inline` et `CSP allows unsafe-eval` partagent exactement la même `evidence` brute — c'est correct techniquement, mais ils devraient porter le flag `CHAIN_DEPENDENCY` l'un vers l'autre. Le CriticAgent le détectera de toute façon, mais autant le marquer dès la source.

**3. `ipmsperf_uuid` — signal fort ignoré**
Le cookie `Set-Cookie` révèle `ipmsperf_uuid` avec 4 valeurs différentes dans une seule réponse. C'est une signature de load balancer ou de CDN de monitoring (probablement Imperva/Incapsula). Ce n'est pas juste un finding CSRF — c'est une information d'infrastructure critique pour Sprint 3 (phishing surface) et pour comprendre si un WAF est en place. Le scanner doit flaguer `CONTEXT_DEPENDENT` et noter la présence probable d'un WAF/CDN.

**4. Apache sans version** — finding `LOW` correct, mais l'evidence dit juste `Server: Apache` sans version. C'est en fait *mieux* que nginx/1.18.0 du mock dashboard — à noter dans le critic_rationale futur : Apache a masqué sa version, ce qui est une bonne pratique. Le CriticAgent devra nuancer.

---
### PROMPT #3 — Sprint 2 (TLS + DNS)

```
Session 3 — Sprint 2 (CLAUDE.md §9)

Implémente tools/scanner.py --mode dns et le wrapper testssl.sh.
Corrige également les 3 observations de l'audit Sprint 1 avant de commencer.

── CORRECTIONS SPRINT 1 (à faire en premier) ──────────────────────────────

1. Vérifier pourquoi HSTS missing n'apparaît pas dans s1_headers_telemo.json
   alors que le résumé console l'affiche. Corriger le bug de sérialisation
   s'il existe, ou confirmer que le finding existe dans un fichier non livré.
   Ajouter test : test_hsts_completely_missing_yields_high_finding.

2. Sur les findings CSP unsafe-inline + unsafe-eval : ajouter flag
   CHAIN_DEPENDENCY automatiquement quand deux findings partagent la même
   evidence source. Implémenter dans tools/scanner.py, couvrir par test.

3. Détecter la signature ipmsperf_uuid dans Set-Cookie → ajouter finding
   INFO "WAF/CDN détecté (Imperva/Incapsula signature)" avec flag
   CONTEXT_DEPENDENT. Evidence = les noms de cookies ipmsperf_uuid.
   Impact : Sprint 3 phishing surface devra tenir compte du WAF.

── SPRINT 2 — TLS ─────────────────────────────────────────────────────────

4. tools/scanner.py --mode tls
   Wrapper subprocess autour de testssl.sh (disponible via nix-shell).
   Checks requis :
   - Protocoles actifs : TLSv1.3 (ok), TLSv1.2 (warn), TLSv1.1 (fail),
     TLSv1.0 (fail), SSLv3 (critical)
   - Certificat : expiration (warn si <30j, fail si <7j), Let's Encrypt vs
     commercial, SAN match
   - Forward Secrecy : ECDHE présent (ok) vs absent (high)
   - HSTS preload : vérifier présence dans liste preload Chromium via
     dig/curl (pas d'appel externe, juste noter absent/présent)
   - Output : 1 Finding par anomalie, evidence = ligne testssl.sh brute
   - CLI : python tools/scanner.py --target telemo.gov.gn --mode tls
           --output results/s2_tls_telemo.json

5. tests/test_scanner_tls.py
   Mocker subprocess.run (testssl.sh) avec des sorties JSON/texte
   représentatives. Tester : TLS1.1 détecté → HIGH, TLS1.3 seul → 0
   findings, cert expirant dans 10j → FAIL, FS absent → HIGH.
   pytest tests/ -v → 29 + N nouveaux = tous GREEN avant d'aller plus loin.

── SPRINT 2 — DNS ─────────────────────────────────────────────────────────

6. tools/scanner.py --mode dns
   Checks via subprocess dig (disponible nix-shell) :
   - DNSSEC : dig +dnssec telemo.gov.gn → DNSKEY présent/absent
   - SPF : dig TXT telemo.gov.gn | grep v=spf → présent/absent/syntaxe
   - DMARC : dig TXT _dmarc.telemo.gov.gn → p=reject/quarantine/none/absent
   - DKIM : dig TXT default._domainkey.telemo.gov.gn → présent/absent
   - MX : dig MX telemo.gov.gn → serveurs mail identifiés (info phishing)
   - Severity mapping :
       DNSSEC absent → CRITICAL
       SPF absent → CRITICAL
       DMARC absent → CRITICAL
       DMARC p=none → HIGH (politique sans effet)
       DKIM absent → HIGH
       MX présent → INFO (avec CHAIN_DEPENDENCY sur SPF/DMARC)
   - CLI : python tools/scanner.py --target telemo.gov.gn --mode dns
           --output results/s2_dns_telemo.json

7. tests/test_scanner_dns.py
   Mocker subprocess.run (dig). Tester chaque check en isolation.
   pytest tests/ -v → tous GREEN.

── EXÉCUTION LIVE ─────────────────────────────────────────────────────────

8. Depuis nix-shell (testssl.sh et dig disponibles) :
   python tools/scanner.py --target telemo.gov.gn --mode tls \
     --output results/s2_tls_telemo.json
   python tools/scanner.py --target telemo.gov.gn --mode dns \
     --output results/s2_dns_telemo.json
   Afficher résumé rich table pour chaque run.

9. Commit : "feat(s2): TLS + DNS checks + Sprint 1 corrections"
   results/ non commités (gitignore).
   PR mise à jour.

── LIVRER ─────────────────────────────────────────────────────────────────

Fournir :
- Log pytest complet (tous tests, pas de résumé)
- Contenu s2_tls_telemo.json
- Contenu s2_dns_telemo.json
- Résumé console rich des deux runs
```

---------------------------------------------------
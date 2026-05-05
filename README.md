# SecAudit — Mini-Mythos

Agent de sécurité passif et semi-actif qui audite la robustesse des sites web
modernes, avec un focus sur la surface phishing (clonage d'interface,
typosquatting, absence SPF/DMARC/DNSSEC). Pipeline en 5 sprints (recon passif →
scan → phishing surface → vecteurs → CriticAgent), orchestré par deux agents
LLM (AnalystAgent Anthropic + CriticAgent DeepSeek contradictoire).

Site de référence initial : `https://telemo.gov.gn` (portail marchés publics
Guinée). Les résultats de scan restent **strictement privés** : jamais
committés, jamais pushés.

<img width="1000" height="383" alt="image" src="https://github.com/user-attachments/assets/9b78f798-9fa3-46a9-98e7-00d7bd3bb547" />

## Structure du repo

```
secaudit/
├── CLAUDE.md                  ← instructions Claude Code (point d'entrée)
├── README.md
├── shell.nix / flake.nix      ← environnement NixOS reproductible
├── requirements.txt
├── config/
│   ├── scope.yaml             ← cibles autorisées (OBLIGATOIRE avant scan)
│   └── settings.py            ← seuils, modèles
├── agents/
│   ├── analyst_agent.py       ← Anthropic Claude Sonnet
│   ├── deepseek_critic_agent.py  ← API native deepseek.com
│   └── factory.py             ← provider dispatch
├── tools/
│   ├── recon.py               ← wrapper nmap → JSON
│   ├── scanner.py             ← HTTP headers, TLS (testssl), DNS (dig)
│   └── phishing_surface.py    ← assets, SRI, typosquats + WHOIS filter
├── schemas/
│   └── finding.py             ← Pydantic : contrat API Finding
├── reports/
│   ├── reporter.py
│   └── templates/report.md.j2
├── ui/
│   └── dashboard.html         ← dashboard Oblivion (offline-first)
├── scripts/                   ← utilitaires de debug/stats (hors prod)
│   ├── mock_pipeline_demo.py
│   └── stats_s5.py
├── results/                   ← JAMAIS commité
├── tests/
├── test_api_keys.py           ← vérif env (Anthropic + DeepSeek)
└── main.py                    ← orchestrateur séquentiel S1→S5
```

## Prérequis

| Dépendance          | Version min | Usage                       |
|---------------------|-------------|-----------------------------|
| Python              | 3.11+       | Orchestrateur               |
| nmap                | 7.x         | Sprint 1 — recon            |
| dig (`dnsutils`)    | 9.x         | Sprint 2 — DNS              |
| testssl.sh          | 3.x         | Sprint 2 — TLS              |
| `ANTHROPIC_API_KEY` | —           | Sprint 5 — AnalystAgent     |
| `DEEPSEEK_API_KEY`  | —           | Sprint 5 — CriticAgent      |

## Installation

### NixOS (recommandé)

```bash
git clone https://github.com/dravitch/secaudit
cd secaudit
nix-shell                    # ou : nix develop (flake)
cp .env.example .env
nano .env                    # ANTHROPIC_API_KEY + DEEPSEEK_API_KEY
python test_api_keys.py
python main.py --target telemo.gov.gn --sprints 1,2,3,4,5
```

Le `shellHook` crée le venv Python (`.venv`) via `uv` et installe
`requirements.txt`. `nmap`, `dig` et `testssl` sont fournis par les
`buildInputs` du shell.

### Ubuntu / Debian

```bash
git clone https://github.com/dravitch/secaudit
cd secaudit
sudo apt-get install -y nmap dnsutils testssl.sh
pip install uv
uv venv .venv && source .venv/bin/activate
uv pip install -r requirements.txt
cp .env.example .env
nano .env                    # ANTHROPIC_API_KEY + DEEPSEEK_API_KEY
python test_api_keys.py
python main.py --target telemo.gov.gn --sprints 1,2,3,4,5
```

### Windows 11 (via WSL2 recommandé)

```powershell
# Dans PowerShell admin :
wsl --install -d Ubuntu-24.04
# Redémarre, puis dans le shell WSL2 ouvert : suis les instructions Ubuntu.
```

Alternative native Windows : exécuter `secaudit-setup.ps1` (PowerShell 7+,
admin requis). `nmap` et `testssl.sh` doivent être installés manuellement
sur Windows natif — WSL2 reste fortement recommandé.

## Avant de lancer

```bash
# Vérifier que les deux clés API répondent (Anthropic + DeepSeek native).
python test_api_keys.py
# variantes :
python test_api_keys.py --anthropic-only
python test_api_keys.py --deepseek-only
```

`test_api_keys.py` n'est pas dans la suite pytest — c'est un check
d'environnement. À lancer après chaque rotation de clé ou changement de plan.

## Lancer le pipeline

```bash
# Pipeline complet S1 → S5 (avec IA)
python main.py --target telemo.gov.gn --sprints 1,2,3,4,5

# Pipeline sans IA (vérification hebdo, zéro coût)
python main.py --target telemo.gov.gn --sprints 1,2,3 --no-ai

# Dashboard local — charger results/s5_critic_*.json via le bouton "Charger JSON"
python -m http.server 8080 --directory ui/
# → http://localhost:8080/dashboard.html

# Stats rapides post-run
python scripts/stats_s5.py
```

## Statut actuel

- **Sessions 1 → 7 — faites** : pipeline complet, AnalystAgent (Anthropic) +
  CriticAgent (DeepSeek native API), reporter Markdown, dashboard Oblivion,
  filtre WHOIS sur typosquats (Restricted Domains exclus).
- Voir la roadmap complète dans `CLAUDE.md` §9.

## Sécurité (non négociable)

- Aucun scan actif sans cible explicite dans `config/scope.yaml`.
- Aucun résultat dans le repo (`.gitignore` strict sur `results/`).
- Aucune clé API en dur — utiliser `.env` + `python-dotenv`.
- Sprints S3/S4 (phishing surface) sont **passifs** : lecture seule, aucun
  formulaire soumis. Le seul appel hors target est la lookup WhoisFreaks
  pour classer un TLD comme registrable ou Restricted.

## Référence

Toutes les instructions complètes (mindsets, prompts agents, ordre des
sessions) sont dans [`CLAUDE.md`](./CLAUDE.md), point d'entrée de chaque
session Claude Code.

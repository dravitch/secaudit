# SecAudit — Mini-Mythos

Agent de sécurité passif et semi-actif qui audite la robustesse des sites web
modernes, avec un focus sur la surface phishing (clonage d'interface,
typosquatting, absence SPF/DMARC/DNSSEC). Pipeline en 5 sprints (recon passif →
scan → phishing surface → vecteurs → CriticAgent), orchestré par deux agents
Anthropic (AnalystAgent + CriticAgent contradictoire).

Site de référence initial : `https://telemo.gov.gn` (portail marchés publics
Guinée). Les résultats de scan restent **strictement privés** : jamais
committés, jamais pushés.

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
│   ├── analyst_agent.py       ← Claude Sonnet : interprète findings bruts
│   └── critic_agent.py        ← agent contradictoire, temperature=0
├── tools/
│   ├── recon.py               ← wrapper nmap + theHarvester → JSON
│   ├── scanner.py             ← wrapper humble + testssl.sh → JSON
│   ├── phishing_surface.py    ← clone surface : assets, SRI, typosquat
│   └── validator.py           ← vérifications curl/httpx
├── schemas/
│   └── finding.py             ← Pydantic : contrat API Finding
├── reports/
│   ├── reporter.py
│   └── templates/report.md.j2
├── ui/
│   └── dashboard.html         ← dashboard Oblivion
├── results/                   ← JAMAIS commité
├── tests/
└── main.py                    ← orchestrateur séquentiel S1→S5
```

## Installation (NixOS)

```bash
git clone https://github.com/dravitch/secaudit
cd secaudit
nix-shell                       # ou : nix develop (flake)
cp .env.example .env && nano .env
python3 -m pytest tests/
```

Le `shellHook` crée automatiquement le venv Python (`.venv`) via `uv` et
installe `requirements.txt`.

## Avant de lancer

```bash
# Vérifier que les deux clés API répondent (Anthropic + HF Router → DeepSeek).
python test_api_keys.py
# variantes :
python test_api_keys.py --anthropic-only
python test_api_keys.py --hf-only
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
```

## Statut actuel

- **Sessions 1 → 6 — faites** : pipeline complet, agents multi-fournisseurs
  (Anthropic + HF/DeepSeek), reporter Markdown, dashboard Oblivion.
- Voir la roadmap complète dans `CLAUDE.md` §9.

## Sécurité (non négociable)

- Aucun scan actif sans cible explicite dans `config/scope.yaml`.
- Aucun résultat dans le repo (`.gitignore` strict sur `results/`).
- Aucune clé API en dur — utiliser `.env` + `python-dotenv`.
- Sprints S3/S4 (phishing surface) sont **passifs** : lecture seule, aucun
  formulaire soumis.

## Référence

Toutes les instructions complètes (mindsets, prompts agents, ordre des
sessions) sont dans [`CLAUDE.md`](./CLAUDE.md), point d'entrée de chaque
session Claude Code.

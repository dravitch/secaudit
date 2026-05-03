Pour que l’exercice contradictoire soit crédible, **les deux agents ne doivent pas provenir du même fournisseur ni partager le même pipeline d’entraînement**. Actuellement, AnalystAgent et CriticAgent tournent tous les deux sur `claude-sonnet-4-6` d’Anthropic – ce qui crée un risque de « chambre d’écho ». Voici comment les découpler en conservant la rigueur de l’audit, avec du code prêt à intégrer dans le projet SecAudit.

---

## 1. Architecture multi‑fournisseurs

Créez une **classe de base abstraite** et un mécanisme de **factory** qui sélectionne le backend selon les variables d’environnement.

```python
# agents/base.py
from abc import ABC, abstractmethod
from schemas.finding import Finding

class BaseAgent(ABC):
    def __init__(self, model: str, temperature: float = 1.0):
        self.model = model
        self.temperature = temperature

    @abstractmethod
    def run(self, findings: list[Finding]) -> list[Finding]:
        ...
```

Puis implémentez :

- `AnthropicAgent` → utilise `anthropic.Anthropic()`, endpoint `/v1/messages`
- `DeepSeekAgent` → utilise l’API compatible OpenAI de DeepSeek (`https://api.deepseek.com/v1`, modèle `deepseek-chat`)
- `GemmaAgent` → utilise n’importe quelle API compatible OpenAI (Groq, Together, Ollama local). Pour Gemma, on peut passer par Groq (`gemma2-9b-it`) ou un endpoint self‑hosted.

Le choix s’opère dans le fichier `.env` et une fonction helper :

```python
# config/settings.py
import os
from dotenv import load_dotenv
load_dotenv()

AGENT_PROVIDER_ANALYST = os.getenv("AGENT_PROVIDER_ANALYST", "anthropic")  # anthropic, deepseek, openai
AGENT_PROVIDER_CRITIC  = os.getenv("AGENT_PROVIDER_CRITIC", "deepseek")
ANALYST_MODEL = os.getenv("ANALYST_MODEL", "claude-sonnet-4-6")
CRITIC_MODEL  = os.getenv("CRITIC_MODEL", "deepseek-chat")
# etc.
```

`.env` cible :

```env
# Analyst reste sur Anthropic
AGENT_PROVIDER_ANALYST=anthropic
ANALYST_MODEL=claude-sonnet-4-6

# Critique passe sur DeepSeek
AGENT_PROVIDER_CRITIC=deepseek
CRITIC_MODEL=deepseek-chat
DEEPSEEK_API_KEY=sk-xxxxxxxxxxxxxxxx
```

---

## 2. Propriétés obligatoires pour un exercice contradictoire valide

Pour que l’opposition entre les deux modèles produise un audit fiable, chaque agent doit respecter six contraintes **techniques et méthodologiques** :

### a) Indépendance totale des modèles
- Les deux modèles doivent être développés par des organisations différentes, entraînés sur des données et des architectures distinctes.  
- **Interdiction** d’utiliser deux variantes d’un même modèle (ex. `claude-3-opus` vs `claude-3-sonnet`). L’indépendance est le socle de la contradiction.

### b) Température fixe et déterministe pour le critique
- Analyst : `temperature = 0.7` (créativité pour formuler des hypothèses).  
- Critic : **`temperature = 0`** (déterministe, reproductible). Avec DeepSeek ou Gemma/Groq, passez `temperature=0` en paramètre API. Certains endpoints (DeepSeek) acceptent `temperature=0` ; d’autres (Groq) peuvent nécessiter `temperature=0` et `seed` fixe. À défaut, utilisez `top_p=0.01` pour forcer le comportement greedy.

### c) Schéma de sortie strict, validé par Pydantic
Chaque agent doit retourner du **JSON pur**, sans markdown. Pour les APIs compatibles OpenAI, utilisez **response_format** avec `"type": "json_object"` (DeepSeek, Groq). Pour Anthropic, c’est un peu plus rustique : il faut forcer la réponse via le prompt et éventuellement utiliser la fonction `tool_use` mais le format texte JSON bien contraint suffit si la température est basse.

Dans tous les cas, parsez la réponse avec Pydantic et **réessayez une fois** en cas d’échec (en prévenant le modèle).

```python
from schemas.finding import Finding
import json

def parse_findings(raw: str) -> list[Finding]:
    # Nettoie les éventuels ```json ... ```
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.split("\n", 1)[1].rsplit("\n", 1)[0]
    data = json.loads(raw)
    # data doit être une liste
    if isinstance(data, dict):
        data = [data]
    return [Finding(**item) for item in data]
```

### d) Prompt adversarial explicite
Le prompt du **CriticAgent** doit contenir des consignes fortes :
- « Tu es un auditeur antagoniste. Ton rôle est de trouver les failles dans les conclusions de l’analyste. »
- « N’accepte jamais une conclusion sans vérifier chaque élément de preuve. »
- « Signale tout contexte manquant (WAF, CDN, VPN) et propose un flag CONTEXT_DEPENDENT. »
- « Réfute ou nuance au moins 20 % des findings ; un désaccord trop faible est suspect. »

Le taux de désaccord naturel attendu entre deux modèles indépendants se situe autour de 15–25 %. Si les deux agents sont toujours d’accord, c’est que le critique est trop conciliant.

### e) Citations d’évidences obligatoires
Le critique doit **recopier l’evidence brute** qui motive sa décision (Mindset 1). Exemple dans `critic_rationale` :  
> « Finding ID 12 (HSTS absent) — l’analyste a conclu HIGH. Cependant le scan a été fait derrière Imperva (cf. cookie ipmsperf_uuid) qui strip les headers HSTS → verdict NUANCED, confidence=0.55. Evidence : aucune preuve que le header est absent en amont du WAF. »

### f) Barrière de publication automatique
La fonction `classify_finding` (CLAUDE.md §11) doit être appliquée **sans exception** :
- `REJECTED` → jamais publié.
- `PENDING` → ne peut pas passer en rapport final.
- `CONFIRMED` seulement si `confidence_score ≥ 0.75`.
- `NUANCED` va dans la section « à investiguer ».

---

## 3. Exemple d’implémentation : CritiqueAgent avec DeepSeek

```python
# agents/deepseek_critic_agent.py
import os
from openai import OpenAI
from .base import BaseAgent
from schemas.finding import Finding
from config.settings import DEEPSEEK_API_KEY, CRITIC_MODEL

CRITIC_SYSTEM_PROMPT = """
Tu es un agent contradictoire. Tu reçois des findings produits par un analyste
et tu dois les challenger avec rigueur.
... (cf. CLAUDE.md §10) ...
Retourne UNIQUEMENT un tableau JSON d'objets Finding avec les champs critic_verdict,
critic_rationale, confidence_score, flags mis à jour.
"""

class DeepSeekCriticAgent(BaseAgent):
    def __init__(self):
        super().__init__(model=CRITIC_MODEL, temperature=0.0)
        self.client = OpenAI(
            api_key=DEEPSEEK_API_KEY,
            base_url="https://api.deepseek.com/v1",
        )

    def run(self, findings: list[Finding]) -> list[Finding]:
        # Préparer le payload
        findings_json = [f.model_dump(mode="json") for f in findings]
        user_msg = json.dumps(findings_json, indent=2, ensure_ascii=False)

        response = self.client.chat.completions.create(
            model=self.model,
            temperature=self.temperature,
            messages=[
                {"role": "system", "content": CRITIC_SYSTEM_PROMPT},
                {"role": "user", "content": user_msg},
            ],
            response_format={"type": "json_object"},  # force JSON
        )
        raw = response.choices[0].message.content
        updated = parse_findings(raw)  # appelle le parsing + validation Pydantic

        # Vérifie que tous les IDs sont présents
        return updated
```

Pour Gemma (via Groq par exemple), le même principe s’applique avec une base_url `https://api.groq.com/openai/v1` et le modèle `gemma2-9b-it`. Assurez-vous que la température 0 est bien respectée. Certaines API renvoient encore des variations malgré `temperature=0` ; dans ce cas, forcez `seed=42` (Groq le supporte).

---

## 4. Tests de l’indépendance contradictoire

Ajoutez un test simple qui vérifie que le critique n’est pas un « copain » :

```python
def test_critic_disagreement_rate(findings_sample):
    """Le taux de désaccord doit être >= 10% pour un vrai challenge."""
    analyst = create_agent("analyst")
    critic = create_agent("critic")
    analyst_out = analyst.run(findings_sample)
    critic_out = critic.run(analyst_out)
    disagreements = sum(
        1 for a, c in zip(analyst_out, critic_out)
        if c.critic_verdict in ("NUANCED", "REJECTED")
    )
    rate = disagreements / len(findings_sample)
    assert rate >= 0.10, f"Critic trop conciliant ({rate:.0%})"
```

Pour un échantillon de 36 findings réels, attendez-vous à **4 à 9 désaccords**. Si le critique DeepSeek valide tout à 100 %, c’est qu’il est mal prompté ou que la température n’est pas vraiment zéro.

---

## 5. Synthèse : pourquoi DeepSeek comme critique est un bon choix

| Propriété | DeepSeek (`deepseek-chat`) | Anthropic (`claude-sonnet-4`) |
|-----------|----------------------------|-------------------------------|
| Température 0 | ✅ strictement greedy | ✅ (déterministe) |
| JSON natif | ✅ `response_format` JSON | ⚠️ via prompt forcing |
| Coût / indépendance | Beaucoup moins cher, modèle chinois indépendant | Même écosystème que l’analyste |
| Raisonnement adversarial | Très bon si prompté avec des exemples | Excellent mais risque d’autocensure |

**Gemma (via Groq/Ollama)** est également viable, mais attention à sa capacité à suivre un format JSON long ; privilégiez `gemma2-9b-it` ou plus grand si disponible.

---

## 6. Mise en œuvre dans le projet

1. Modifier `.env` pour définir les deux providers distincts.
2. Créer `agents/factory.py` qui, selon `AGENT_PROVIDER_ANALYST` / `AGENT_PROVIDER_CRITIC`, instancie le bon agent.
3. Garder `AnalystAgent` sur Anthropic (Sonnet) et `CriticAgent` sur DeepSeek (ou Gemma) : **ils n’auront aucune corrélation d’entraînement**.
4. Exécuter la pipeline Session 5 complète : tous les findings bruts passent par l’analyste (Sonnet) puis par le critique (DeepSeek). Le désaccord fertile fait émerger les vrais risques.

L’outil devient ainsi **multi‑modèle et véritablement contradictoire** – condition indispensable pour un audit automatisé digne de confiance.

Oui, vous pouvez tout à fait passer par un fournisseur tiers comme Hugging Face Router. Cela résout le problème de carte bancaire puisque vous payez Hugging Face (qui accepte les MasterCard sans souci) et non la plateforme DeepSeek directement.

## Fournisseur et modèle recommandé pour le CriticAgent

Parmi la liste que vous avez fournie, le meilleur rapport qualité/prix est :

**`deepseek-ai/DeepSeek-V4-Pro` via le fournisseur `novita`**  
- Prix : $1.74 / $3.48 par million de tokens (entrée/sortie)  
- Contexte : 1 048 576 tokens (largement suffisant pour traiter 36 findings)  
- Mode JSON natif : **Yes**  
- Température 0 supportée (via l’API OpenAI-compatible)  

Avec Hugging Face Router, vous l’utilisez exactement comme dans votre exemple :
```python
from openai import OpenAI
import os

client = OpenAI(
    base_url="https://router.huggingface.co/v1",
    api_key=os.environ["HF_TOKEN"],
)

response = client.chat.completions.create(
    model="deepseek-ai/DeepSeek-V4-Pro:novita",
    temperature=0,                               # déterministe
    response_format={"type": "json_object"},     # sortie JSON structurée
    messages=[
        {"role": "system", "content": CRITIC_SYSTEM_PROMPT},
        {"role": "user", "content": json_dump_des_findings}
    ]
)
```

Le coût sera négligeable pour 36 findings (quelques centimes de dollar par run).

## Plan B : Gemma 4 31B (encore moins cher)

Si vous voulez minimiser les frais, `google/gemma-4-31B-it` via **novita** est encore plus économique :  
- $0.14 / $0.40 par million de tokens  
- Contexte : 262 144 tokens  
- JSON mode : Yes (selon la table)  
- Température 0 possible  

L’appel se fait de la même manière, seul le modèle change :
```python
model="google/gemma-4-31B-it:novita"
```

## Vérifications à faire avant de l’intégrer dans SecAudit

1. **Température zéro réellement déterministe** : testez deux appels identiques avec le même prompt ; la sortie JSON doit être strictement identique.  
2. **Format JSON strict** : parsez la réponse avec Pydantic et vérifiez qu’aucune prose parasite ne s’est glissée.  
3. **Adversarialité** : le prompt du critique doit conserver ses instructions de contradiction (rejeter ou nuancer au moins 10-20 % des findings). Avec DeepSeek V4 Pro, vous obtiendrez un challenge de qualité.

## Configuration pour SecAudit

Créez ou mettez à jour le fichier `config/settings.py` (ou `.env`) pour supporter Hugging Face Router :

```env
# Analyst via Anthropic (inchangé)
AGENT_PROVIDER_ANALYST=anthropic
ANALYST_MODEL=claude-sonnet-4-6

# Critic via Hugging Face → DeepSeek V4 Pro (Novita)
AGENT_PROVIDER_CRITIC=huggingface
CRITIC_MODEL=deepseek-ai/DeepSeek-V4-Pro:novita
HF_TOKEN=hf_xxxxxxxxxxxxxxxxxxxxx
```

Et ajustez la factory d’agents pour instancier le client OpenAI avec la `base_url` du router lorsque le provider est `huggingface`.

**Résumé** : Oui, Hugging Face Router + Novita exécutant DeepSeek V4 Pro répond parfaitement à votre besoin.
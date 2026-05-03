#!/usr/bin/env python3
"""
test_api_keys.py — SecAudit / Mini-Mythos
Teste la validité de ANTHROPIC_API_KEY et HF_TOKEN avant de lancer le pipeline.
Gère les cas : clé manquante, invalide, budget épuisé, quota HF dépassé.

Usage :
    python test_api_keys.py
    python test_api_keys.py --verbose
    python test_api_keys.py --anthropic-only
    python test_api_keys.py --hf-only

Note HuggingFace Router :
    Le HF Router expose une API compatible OpenAI — le client 'openai' est
    donc le bon client, mais le backend réel est DeepSeek (via Novita).
    Le modèle s'appelle "deepseek-ai/DeepSeek-V4-Pro" (sans ":novita") dans
    les appels au router. Le provider Novita est sélectionné côté HF.
"""

import os
import sys
import json
import argparse
import re
import subprocess
from datetime import datetime, timezone

# ── Dépendance Anthropic ─────────────────────────────────────────────────────
try:
    import anthropic
except ImportError:
    print("[ERREUR] 'anthropic' non installé — lance : uv pip install anthropic")
    sys.exit(1)

# ── Dépendance openai (client HF Router — backend DeepSeek) ─────────────────
# Le HF Router implémente l'API OpenAI-compatible. Le client 'openai' est
# requis même si le modèle derrière est DeepSeek. On tente une installation
# automatique dans le venv actif avant d'abandonner.
try:
    from openai import OpenAI, AuthenticationError, RateLimitError, BadRequestError
except ImportError:
    print("[INFO] 'openai' absent — tentative d'installation automatique...")
    result = subprocess.run(
        [sys.executable, "-m", "uv", "pip", "install", "openai", "--quiet"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        print("[INFO] 'openai' installé avec succès.")
        from openai import OpenAI, AuthenticationError, RateLimitError, BadRequestError
    else:
        print("[ERREUR] Impossible d'installer 'openai' automatiquement.")
        print("  Lance manuellement : uv pip install openai")
        print(f"  Détail : {result.stderr.strip()[:200]}")
        sys.exit(1)

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # .env chargé manuellement si dotenv absent

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    RICH = True
    console = Console()
except ImportError:
    RICH = False
    console = None


# ── Helpers d'affichage ──────────────────────────────────────────────────────

def ok(msg):
    if RICH:
        console.print(f"  [bold green]✓[/bold green]  {msg}")
    else:
        print(f"  ✓  {msg}")

def warn(msg):
    if RICH:
        console.print(f"  [bold yellow]⚠[/bold yellow]  {msg}")
    else:
        print(f"  ⚠  {msg}")

def fail(msg):
    if RICH:
        console.print(f"  [bold red]✗[/bold red]  {msg}")
    else:
        print(f"  ✗  {msg}")

def info(msg):
    if RICH:
        console.print(f"  [dim]→[/dim]  {msg}")
    else:
        print(f"  →  {msg}")

def header(title):
    if RICH:
        console.print(f"\n[bold cyan]{title}[/bold cyan]")
        console.print("─" * 50)
    else:
        print(f"\n{title}")
        print("─" * 50)


# ── Parsing du message de budget épuisé ─────────────────────────────────────

def parse_budget_reset(error_message: str) -> str:
    """
    Extrait l'heure de reset depuis le message :
    "You're out of extra usage · resets 11:45 pm (UTC)"
    Retourne une string lisible ou None si non trouvé.
    """
    pattern = r"resets\s+(\d{1,2}:\d{2}\s*(?:am|pm))\s*\(UTC\)"
    match = re.search(pattern, error_message, re.IGNORECASE)
    if match:
        return match.group(1).strip() + " UTC"
    # Essai alternatif : "resets in Xh Ym"
    pattern2 = r"resets in\s+([\dh\s]+m)"
    match2 = re.search(pattern2, error_message, re.IGNORECASE)
    if match2:
        return f"dans {match2.group(1).strip()}"
    return None


# ── Test 1 : ANTHROPIC_API_KEY ───────────────────────────────────────────────

def test_anthropic(verbose: bool = False) -> dict:
    header("1 · Anthropic API (AnalystAgent)")

    result = {
        "provider": "anthropic",
        "status": "unknown",
        "model": os.getenv("ANALYST_MODEL", "claude-sonnet-4-5"),
        "detail": ""
    }

    api_key = os.getenv("ANTHROPIC_API_KEY", "")

    # Clé absente
    if not api_key:
        fail("ANTHROPIC_API_KEY absent du .env")
        result["status"] = "missing"
        result["detail"] = "Variable ANTHROPIC_API_KEY non définie"
        return result

    # Clé présente mais format invalide
    if not api_key.startswith("sk-ant-"):
        warn(f"Clé présente mais format inattendu ({api_key[:10]}...)")
        info("Format attendu : sk-ant-api03-...")

    info(f"Clé détectée : {api_key[:14]}...{api_key[-4:]}")

    # Lire le modèle depuis .env (même logique que l'AnalystAgent)
    analyst_model = os.getenv("ANALYST_MODEL", "claude-sonnet-4-5")
    info(f"Modèle cible   : {analyst_model}")

    try:
        client = anthropic.Anthropic(api_key=api_key)
        response = client.messages.create(
            model=analyst_model,
            max_tokens=20,
            messages=[{"role": "user", "content": "Reply with: OK"}]
        )
        # Sécuriser l'accès au contenu (peut être vide si stop_reason inattendu)
        raw_reply = ""
        if response.content and hasattr(response.content[0], "text"):
            raw_reply = response.content[0].text or ""
        reply = raw_reply.strip()
        ok(f"Connexion réussie — réponse : '{reply}'")
        info(f"Modèle : {response.model}")
        info(f"Tokens utilisés : {response.usage.input_tokens} in / {response.usage.output_tokens} out")
        result["status"] = "ok"
        result["detail"] = f"Réponse : {reply}"

    except anthropic.AuthenticationError as e:
        fail("Clé invalide ou révoquée")
        if verbose:
            info(str(e))
        result["status"] = "invalid_key"
        result["detail"] = str(e)

    except anthropic.PermissionDeniedError as e:
        msg = str(e)
        reset_time = parse_budget_reset(msg)
        if reset_time or "out of extra usage" in msg.lower() or "usage" in msg.lower():
            fail(f"Budget épuisé")
            if reset_time:
                warn(f"Reset prévu à : {reset_time}")
            else:
                warn("Heure de reset non trouvée dans le message d'erreur")
            info("Solution : attendre le reset OU upgrader le plan sur console.anthropic.com")
            result["status"] = "budget_exhausted"
            result["detail"] = f"Reset à {reset_time}" if reset_time else msg
        else:
            fail(f"Accès refusé : {msg}")
            result["status"] = "permission_denied"
            result["detail"] = msg

    except anthropic.RateLimitError as e:
        msg = str(e)
        reset_time = parse_budget_reset(msg)
        fail("Rate limit atteint")
        if reset_time:
            warn(f"Reset prévu à : {reset_time}")
        info("Solution : patienter quelques minutes ou vérifier les limites du plan")
        result["status"] = "rate_limit"
        result["detail"] = f"Reset à {reset_time}" if reset_time else msg

    except anthropic.APIConnectionError as e:
        fail(f"Impossible de joindre api.anthropic.com")
        if verbose:
            info(str(e))
        result["status"] = "connection_error"
        result["detail"] = str(e)

    except anthropic.APIStatusError as e:
        # Catch-all pour les autres codes HTTP (402, 429, 500...)
        msg = str(e)
        reset_time = parse_budget_reset(msg)
        if e.status_code == 402 or "out of extra usage" in msg.lower():
            fail(f"Budget épuisé (HTTP {e.status_code})")
            if reset_time:
                warn(f"Reset prévu à : {reset_time}")
            result["status"] = "budget_exhausted"
            result["detail"] = f"Reset à {reset_time}" if reset_time else msg
        else:
            fail(f"Erreur API HTTP {e.status_code}")
            if verbose:
                info(msg)
            result["status"] = f"api_error_{e.status_code}"
            result["detail"] = msg

    except Exception as e:
        fail(f"Erreur inattendue : {type(e).__name__}")
        if verbose:
            info(str(e))
        result["status"] = "unexpected_error"
        result["detail"] = str(e)

    return result


# ── Test 2 : HF_TOKEN (HuggingFace Router → DeepSeek V4 Pro) ────────────────

def test_huggingface(verbose: bool = False) -> dict:
    header("2 · HuggingFace Router → DeepSeek V4 Pro (CriticAgent)")

    result = {
        "provider": "huggingface",
        "status": "unknown",
        "model": "deepseek-ai/DeepSeek-V4-Pro",
        "detail": ""
    }

    hf_token = os.getenv("HF_TOKEN", "")

    # Le HF Router utilise le nom du modèle SANS suffixe ":provider"
    # (ex: "deepseek-ai/DeepSeek-V4-Pro" et non "deepseek-ai/DeepSeek-V4-Pro:novita")
    # Le provider Novita est sélectionné automatiquement côté HF Router.
    critic_model_raw = os.getenv("CRITIC_MODEL", "deepseek-ai/DeepSeek-V4-Pro:novita")
    critic_model = critic_model_raw.split(":")[0]  # retire ":novita" si présent
    result["model"] = critic_model

    # Token absent
    if not hf_token:
        fail("HF_TOKEN absent du .env")
        result["status"] = "missing"
        result["detail"] = "Variable HF_TOKEN non définie"
        return result

    # Format basique
    if not hf_token.startswith("hf_"):
        warn(f"Token présent mais format inattendu ({hf_token[:8]}...)")
        info("Format attendu : hf_xxxxxxxxxxxxxxxxxxxxx")

    info(f"Token détecté  : {hf_token[:8]}...{hf_token[-4:]}")
    if critic_model != critic_model_raw:
        info(f"Modèle (brut)  : {critic_model_raw}")
        info(f"Modèle (router): {critic_model}  ← suffixe :novita retiré pour HF Router")
    else:
        info(f"Modèle cible   : {critic_model}")

    # Pré-check : vérifier que le modèle est bien listé et live sur le router
    info("Vérification live du modèle sur router.huggingface.co/v1/models ...")
    try:
        import urllib.request
        req = urllib.request.Request(
            "https://router.huggingface.co/v1/models",
            headers={"Authorization": f"Bearer {hf_token}"}
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            models_data = json.loads(resp.read())
        model_ids = [m["id"] for m in models_data.get("data", [])]
        if critic_model in model_ids:
            ok(f"Modèle confirmé live sur le router")
            # Chercher le provider Novita dans les détails
            for m in models_data.get("data", []):
                if m["id"] == critic_model:
                    providers = [p["provider"] for p in m.get("providers", [])]
                    live = [p["provider"] for p in m.get("providers", []) if p.get("status") == "live"]
                    info(f"Providers disponibles : {providers}")
                    info(f"Providers live        : {live}")
                    if "novita" not in live:
                        warn("Novita n'est pas en statut 'live' — le fallback HF prendra un autre provider")
        else:
            warn(f"Modèle '{critic_model}' absent de la liste du router")
            info(f"Modèles disponibles : {model_ids[:5]}...")
    except Exception as e:
        warn(f"Pré-check modèles échoué (non bloquant) : {type(e).__name__}")

    try:
        client = OpenAI(
            base_url="https://router.huggingface.co/v1",
            api_key=hf_token,
        )

        response = client.chat.completions.create(
            model=critic_model,
            temperature=0,
            max_tokens=32,
            # Pas de response_format ici — test de connectivité uniquement.
            # Le json_object mode est activé dans le vrai CriticAgent.
            messages=[
                {
                    "role": "system",
                    "content": "You are a helpful assistant."
                },
                {
                    "role": "user",
                    "content": "Reply with the single word: READY"
                }
            ]
        )

        choice = response.choices[0]
        finish_reason = getattr(choice, "finish_reason", "unknown")
        raw = getattr(choice.message, "content", None)

        # Garde contre content=None (stream vide ou stop_reason=content_filter)
        if raw is None:
            warn(f"Connexion OK mais contenu vide (finish_reason={finish_reason})")
            info("Le modèle a peut-être filtré la réponse — test de connectivité validé")
            result["status"] = "ok"
            result["detail"] = f"Connexion OK, content=None (finish={finish_reason})"
        else:
            reply = raw.strip()
            ok(f"Connexion réussie — réponse : '{reply}' (finish={finish_reason})")

            result["status"] = "ok"
            result["detail"] = f"Réponse : '{reply}'"

        info(f"Modèle retourné : {getattr(response, 'model', critic_model)}")
        if hasattr(response, "usage") and response.usage:
            info(f"Tokens : {response.usage.prompt_tokens} in / "
                 f"{response.usage.completion_tokens} out")

    except AuthenticationError as e:
        msg = str(e)
        fail("Token HF invalide ou révoqué")
        info("Vérifier sur huggingface.co/settings/tokens")
        if verbose:
            info(msg)
        result["status"] = "invalid_token"
        result["detail"] = msg

    except RateLimitError as e:
        msg = str(e)
        reset_time = parse_budget_reset(msg)
        fail("Quota HuggingFace dépassé")
        if reset_time:
            warn(f"Reset prévu à : {reset_time}")
        else:
            warn("Vérifier les quotas sur huggingface.co/settings/billing")
        info("Solution : patienter ou recharger le crédit HF")
        result["status"] = "quota_exceeded"
        result["detail"] = f"Reset à {reset_time}" if reset_time else msg

    except BadRequestError as e:
        msg = str(e)
        # Modèle introuvable ou non supporté sur ce provider
        if "model" in msg.lower() or "not found" in msg.lower():
            fail(f"Modèle introuvable : {critic_model}")
            info("Vérifier le nom exact sur huggingface.co/models")
            info("Alternative : deepseek-ai/DeepSeek-V4-Flash:novita (moins cher)")
        else:
            fail(f"Requête invalide : {msg[:80]}")
        result["status"] = "bad_request"
        result["detail"] = msg

    except Exception as e:
        msg = str(e)
        # Détecter budget épuisé dans les exceptions génériques
        reset_time = parse_budget_reset(msg)
        if "out of extra usage" in msg.lower() or "budget" in msg.lower():
            fail("Budget HuggingFace épuisé")
            if reset_time:
                warn(f"Reset prévu à : {reset_time}")
            result["status"] = "budget_exhausted"
            result["detail"] = f"Reset à {reset_time}" if reset_time else msg
        elif "connection" in msg.lower() or "timeout" in msg.lower():
            fail("Impossible de joindre router.huggingface.co")
            if verbose:
                info(msg)
            result["status"] = "connection_error"
            result["detail"] = msg
        else:
            fail(f"Erreur inattendue : {type(e).__name__}")
            if verbose:
                info(msg)
            result["status"] = "unexpected_error"
            result["detail"] = msg

    return result


# ── Rapport final ────────────────────────────────────────────────────────────

def print_summary(results: list[dict]):
    header("Résumé")

    all_ok = all(r["status"] == "ok" for r in results)

    if RICH:
        table = Table(box=box.ROUNDED, show_header=True)
        table.add_column("Provider", style="bold")
        table.add_column("Modèle")
        table.add_column("Statut")
        table.add_column("Détail")

        status_colors = {
            "ok": "green",
            "missing": "red",
            "invalid_key": "red",
            "invalid_token": "red",
            "budget_exhausted": "yellow",
            "quota_exceeded": "yellow",
            "rate_limit": "yellow",
            "connection_error": "red",
            "bad_request": "red",
        }

        status_labels = {
            "ok": "✓ OK",
            "missing": "✗ MANQUANT",
            "invalid_key": "✗ CLÉ INVALIDE",
            "invalid_token": "✗ TOKEN INVALIDE",
            "budget_exhausted": "⚠ BUDGET ÉPUISÉ",
            "quota_exceeded": "⚠ QUOTA DÉPASSÉ",
            "rate_limit": "⚠ RATE LIMIT",
            "connection_error": "✗ CONNEXION",
            "bad_request": "✗ REQUÊTE",
        }

        for r in results:
            color = status_colors.get(r["status"], "red")
            label = status_labels.get(r["status"], r["status"].upper())
            table.add_row(
                r["provider"],
                r["model"],
                f"[{color}]{label}[/{color}]",
                r["detail"][:60]
            )

        console.print(table)

        if all_ok:
            console.print(Panel(
                "[bold green]Les deux clés sont valides.[/bold green]\n"
                "Tu peux lancer : [cyan]python main.py --target telemo.gov.gn "
                "--sprints 1,2,3,4,5[/cyan]",
                title="✓ Pipeline prêt",
                border_style="green"
            ))
        else:
            problems = [r for r in results if r["status"] != "ok"]
            lines = []
            for p in problems:
                if p["status"] == "budget_exhausted":
                    lines.append(
                        f"[yellow]{p['provider'].upper()}[/yellow] : "
                        f"budget épuisé — {p['detail']}\n"
                        f"  → Attendre le reset ou recharger sur "
                        + ("console.anthropic.com"
                           if p["provider"] == "anthropic"
                           else "huggingface.co/settings/billing")
                    )
                elif p["status"] == "missing":
                    lines.append(
                        f"[red]{p['provider'].upper()}[/red] : "
                        f"clé absente — ajouter dans .env"
                    )
                else:
                    lines.append(
                        f"[red]{p['provider'].upper()}[/red] : "
                        f"{p['status']} — {p['detail'][:60]}"
                    )
            console.print(Panel(
                "\n".join(lines),
                title="✗ Problèmes détectés",
                border_style="red"
            ))
    else:
        for r in results:
            print(f"  {r['provider']:12} {r['model']:40} {r['status']:20} {r['detail'][:50]}")
        if all_ok:
            print("\n✓ Les deux clés sont valides. Pipeline prêt.")
        else:
            print("\n✗ Problèmes détectés — voir détails ci-dessus.")

    return 0 if all_ok else 1


# ── Point d'entrée ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Teste ANTHROPIC_API_KEY et HF_TOKEN avant le pipeline SecAudit"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Afficher les messages d'erreur complets"
    )
    parser.add_argument(
        "--anthropic-only",
        action="store_true",
        help="Tester uniquement la clé Anthropic"
    )
    parser.add_argument(
        "--hf-only",
        action="store_true",
        help="Tester uniquement le token HuggingFace"
    )
    args = parser.parse_args()

    if RICH:
        console.print(Panel(
            f"[bold]SecAudit — Vérification des clés API[/bold]\n"
            f"[dim]{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}[/dim]",
            border_style="cyan"
        ))
    else:
        print(f"\nSecAudit — Vérification des clés API")
        print(f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n")

    results = []

    if not args.hf_only:
        results.append(test_anthropic(verbose=args.verbose))

    if not args.anthropic_only:
        results.append(test_huggingface(verbose=args.verbose))

    exit_code = print_summary(results)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()

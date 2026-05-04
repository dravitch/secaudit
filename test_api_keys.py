#!/usr/bin/env python3
"""
test_api_keys.py — SecAudit / Mini-Mythos
Teste la validité de ANTHROPIC_API_KEY et DEEPSEEK_API_KEY avant de lancer
le pipeline. Gère les cas : clé manquante, invalide, budget épuisé,
quota dépassé.

Usage :
    python test_api_keys.py
    python test_api_keys.py --verbose
    python test_api_keys.py --anthropic-only
    python test_api_keys.py --deepseek-only
"""

import os
import sys
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

# ── Dépendance openai (client DeepSeek — API OpenAI-compatible) ─────────────
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
    pass

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


def parse_budget_reset(error_message: str) -> str:
    pattern = r"resets\s+(\d{1,2}:\d{2}\s*(?:am|pm))\s*\(UTC\)"
    match = re.search(pattern, error_message, re.IGNORECASE)
    if match:
        return match.group(1).strip() + " UTC"
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

    if not api_key:
        fail("ANTHROPIC_API_KEY absent du .env")
        result["status"] = "missing"
        result["detail"] = "Variable ANTHROPIC_API_KEY non définie"
        return result

    if not api_key.startswith("sk-ant-"):
        warn(f"Clé présente mais format inattendu ({api_key[:10]}...)")
        info("Format attendu : sk-ant-api03-...")

    info(f"Clé détectée : {api_key[:14]}...{api_key[-4:]}")

    analyst_model = os.getenv("ANALYST_MODEL", "claude-sonnet-4-5")
    info(f"Modèle cible   : {analyst_model}")

    try:
        client = anthropic.Anthropic(api_key=api_key)
        response = client.messages.create(
            model=analyst_model,
            max_tokens=20,
            messages=[{"role": "user", "content": "Reply with: OK"}]
        )
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
            fail("Budget épuisé")
            if reset_time:
                warn(f"Reset prévu à : {reset_time}")
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
        result["status"] = "rate_limit"
        result["detail"] = f"Reset à {reset_time}" if reset_time else msg

    except anthropic.APIConnectionError as e:
        fail("Impossible de joindre api.anthropic.com")
        if verbose:
            info(str(e))
        result["status"] = "connection_error"
        result["detail"] = str(e)

    except anthropic.APIStatusError as e:
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


# ── Test 2 : DEEPSEEK_API_KEY (DeepSeek native API) ─────────────────────────

def test_deepseek(verbose: bool = False) -> dict:
    header("2 · DeepSeek API native (CriticAgent)")

    critic_model = os.getenv("CRITIC_MODEL", "deepseek-chat")
    result = {
        "provider": "deepseek",
        "status": "unknown",
        "model": critic_model,
        "detail": "",
    }

    api_key = os.getenv("DEEPSEEK_API_KEY", "")

    if not api_key:
        fail("DEEPSEEK_API_KEY absent du .env")
        info("Récupérer une clé sur https://platform.deepseek.com/api_keys")
        result["status"] = "missing"
        result["detail"] = "Variable DEEPSEEK_API_KEY non définie"
        return result

    if not api_key.startswith("sk-"):
        warn(f"Clé présente mais format inattendu ({api_key[:6]}...)")
        info("Format attendu : sk-xxxxxxxxxxxx")

    info(f"Clé détectée : {api_key[:6]}...{api_key[-4:]}")
    info(f"Modèle cible : {critic_model}")

    try:
        client = OpenAI(
            base_url="https://api.deepseek.com/v1",
            api_key=api_key,
        )
        response = client.chat.completions.create(
            model=critic_model,
            temperature=0,
            max_tokens=32,
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "Reply with the single word: READY"},
            ],
        )
        choice = response.choices[0]
        finish_reason = getattr(choice, "finish_reason", "unknown")
        raw = getattr(choice.message, "content", None)
        if raw is None:
            warn(f"Connexion OK mais contenu vide (finish_reason={finish_reason})")
            result["status"] = "ok"
            result["detail"] = f"Connexion OK, content=None (finish={finish_reason})"
        else:
            reply = raw.strip()
            ok(f"Connexion réussie — réponse : '{reply}' (finish={finish_reason})")
            result["status"] = "ok"
            result["detail"] = f"Réponse : '{reply}'"

        info(f"Modèle retourné : {getattr(response, 'model', critic_model)}")
        if getattr(response, "usage", None):
            info(
                f"Tokens : {response.usage.prompt_tokens} in / "
                f"{response.usage.completion_tokens} out"
            )

    except AuthenticationError as e:
        fail("Clé DeepSeek invalide ou révoquée")
        info("Vérifier sur platform.deepseek.com/api_keys")
        if verbose:
            info(str(e))
        result["status"] = "invalid_key"
        result["detail"] = str(e)

    except RateLimitError as e:
        msg = str(e)
        reset_time = parse_budget_reset(msg)
        fail("Quota DeepSeek dépassé")
        if reset_time:
            warn(f"Reset prévu à : {reset_time}")
        result["status"] = "quota_exceeded"
        result["detail"] = f"Reset à {reset_time}" if reset_time else msg

    except BadRequestError as e:
        msg = str(e)
        if "model" in msg.lower() or "not found" in msg.lower():
            fail(f"Modèle introuvable : {critic_model}")
            info("Modèles supportés : deepseek-chat, deepseek-reasoner")
        else:
            fail(f"Requête invalide : {msg[:80]}")
        result["status"] = "bad_request"
        result["detail"] = msg

    except Exception as e:
        msg = str(e)
        reset_time = parse_budget_reset(msg)
        if "balance" in msg.lower() or "out of" in msg.lower():
            fail("Solde DeepSeek insuffisant")
            if reset_time:
                warn(f"Reset prévu à : {reset_time}")
            result["status"] = "budget_exhausted"
            result["detail"] = f"Reset à {reset_time}" if reset_time else msg
        elif "connection" in msg.lower() or "timeout" in msg.lower():
            fail("Impossible de joindre api.deepseek.com")
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
            "budget_exhausted": "⚠ BUDGET ÉPUISÉ",
            "quota_exceeded": "⚠ QUOTA DÉPASSÉ",
            "rate_limit": "⚠ RATE LIMIT",
            "connection_error": "✗ CONNEXION",
            "bad_request": "✗ REQUÊTE",
        }

        for r in results:
            color = status_colors.get(r["status"], "red")
            label = status_labels.get(r["status"], r["status"].upper())
            table.add_row(r["provider"], r["model"], f"[{color}]{label}[/{color}]", r["detail"][:60])

        console.print(table)

        if all_ok:
            console.print(Panel(
                "[bold green]Les deux clés sont valides.[/bold green]\n"
                "Tu peux lancer : [cyan]python main.py --target telemo.gov.gn "
                "--sprints 1,2,3,4,5[/cyan]",
                title="✓ Pipeline prêt",
                border_style="green",
            ))
        else:
            problems = [r for r in results if r["status"] != "ok"]
            lines = []
            for p in problems:
                if p["status"] == "budget_exhausted":
                    where = (
                        "console.anthropic.com"
                        if p["provider"] == "anthropic"
                        else "platform.deepseek.com"
                    )
                    lines.append(
                        f"[yellow]{p['provider'].upper()}[/yellow] : "
                        f"budget épuisé — {p['detail']}\n"
                        f"  → Attendre le reset ou recharger sur {where}"
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
            console.print(Panel("\n".join(lines), title="✗ Problèmes détectés", border_style="red"))
    else:
        for r in results:
            print(f"  {r['provider']:12} {r['model']:30} {r['status']:20} {r['detail'][:50]}")
        if all_ok:
            print("\n✓ Les deux clés sont valides. Pipeline prêt.")
        else:
            print("\n✗ Problèmes détectés — voir détails ci-dessus.")

    return 0 if all_ok else 1


def main():
    parser = argparse.ArgumentParser(
        description="Teste ANTHROPIC_API_KEY et DEEPSEEK_API_KEY avant le pipeline SecAudit"
    )
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Afficher les messages d'erreur complets")
    parser.add_argument("--anthropic-only", action="store_true",
                        help="Tester uniquement la clé Anthropic")
    parser.add_argument("--deepseek-only", action="store_true",
                        help="Tester uniquement la clé DeepSeek")
    args = parser.parse_args()

    if RICH:
        console.print(Panel(
            f"[bold]SecAudit — Vérification des clés API[/bold]\n"
            f"[dim]{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}[/dim]",
            border_style="cyan",
        ))
    else:
        print("\nSecAudit — Vérification des clés API")
        print(f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n")

    results = []
    if not args.deepseek_only:
        results.append(test_anthropic(verbose=args.verbose))
    if not args.anthropic_only:
        results.append(test_deepseek(verbose=args.verbose))

    sys.exit(print_summary(results))


if __name__ == "__main__":
    main()

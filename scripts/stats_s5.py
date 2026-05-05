#!/usr/bin/env python3
"""scripts/stats_s5.py — résumé contradictoire du CriticAgent (verdict counts)."""
import json
import pathlib
import sys

CRITIC_FILE = pathlib.Path("results/s5_critic.json")


def main() -> int:
    if not CRITIC_FILE.exists():
        print(f"Fichier introuvable : {CRITIC_FILE}")
        return 1

    findings = json.loads(CRITIC_FILE.read_text())
    total = len(findings)
    if total == 0:
        print("Aucun finding dans s5_critic.json")
        return 0

    confirmed = sum(1 for f in findings if f["critic_verdict"] == "CONFIRMED")
    nuanced = sum(1 for f in findings if f["critic_verdict"] == "NUANCED")
    rejected = sum(1 for f in findings if f["critic_verdict"] == "REJECTED")
    pending = sum(1 for f in findings if f["critic_verdict"] == "PENDING")
    disagree = nuanced + rejected
    rate = disagree / total * 100

    print(f"Total      : {total}")
    print(f"CONFIRMED  : {confirmed}")
    print(f"NUANCED    : {nuanced}")
    print(f"REJECTED   : {rejected}")
    print(f"PENDING    : {pending}")
    print(f"Désaccord  : {disagree}/{total} = {rate:.1f}%")
    return 0


if __name__ == "__main__":
    sys.exit(main())

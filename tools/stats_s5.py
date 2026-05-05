#!/usr/bin/env python3
"""Affiche le résumé contradictoire du CriticAgent."""
import json
import pathlib

CRITIC_FILE = pathlib.Path("results/s5_critic.json")

if not CRITIC_FILE.exists():
    print(f"Fichier introuvable : {CRITIC_FILE}")
    exit(1)

findings = json.loads(CRITIC_FILE.read_text())

total     = len(findings)
confirmed = sum(1 for f in findings if f["critic_verdict"] == "CONFIRMED")
nuanced   = sum(1 for f in findings if f["critic_verdict"] == "NUANCED")
rejected  = sum(1 for f in findings if f["critic_verdict"] == "REJECTED")
pending   = sum(1 for f in findings if f["critic_verdict"] == "PENDING")
disagree  = nuanced + rejected
rate      = disagree / total * 100

print(f"Total      : {total}")
print(f"CONFIRMED  : {confirmed}")
print(f"NUANCED    : {nuanced}")
print(f"REJECTED   : {rejected}")
print(f"PENDING    : {pending}")
print(f"Désaccord  : {disagree}/{total} = {rate:.1f}%")
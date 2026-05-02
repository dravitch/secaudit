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

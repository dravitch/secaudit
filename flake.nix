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

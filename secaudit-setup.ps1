# secaudit-setup.ps1
# SecAudit / Mini-Mythos - Script d'installation et de lancement Windows 11
#
# Usage :
#   .\secaudit-setup.ps1                        # Installation + run complet
#   .\secaudit-setup.ps1 -SkipInstall           # Repo deja installe, relancer seulement
#   .\secaudit-setup.ps1 -NoAI                  # Pipeline sans agents IA (S1+S2+S3)
#   .\secaudit-setup.ps1 -SkipScan              # Ouvrir le dashboard directement
#   .\secaudit-setup.ps1 -Target monsite.com    # Cible differente de telemo.gov.gn
#
# Prerequis installes automatiquement si absents :
#   Git, Python 3.11+, uv, openai (pip)
#
# Le depot GitHub est public - aucun compte GitHub requis pour cloner.

param(
    [switch]$SkipInstall,
    [switch]$NoAI,
    [switch]$SkipScan,
    [string]$Target    = "telemo.gov.gn",
    [string]$Sprints   = "1,2,3,4,5",
    [string]$RepoUrl   = "https://github.com/dravitch/secaudit.git",
    [string]$InstallDir = "$env:USERPROFILE\SecAudit\secaudit"
)

$ErrorActionPreference = "Stop"
$Host.UI.RawUI.WindowTitle = "SecAudit / Mini-Mythos - Setup & Run"
$StartTime = Get-Date
$script:Errors = 0

# ─────────────────────────────────────────────────────────────────────────────
# Fonctions d'affichage
# ─────────────────────────────────────────────────────────────────────────────
function Write-Banner {
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║        SecAudit / Mini-Mythos  v0.1.0           ║" -ForegroundColor Cyan
    Write-Host "  ║   Outil d'audit de securite web automatise       ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host "  Cible    : $Target" -ForegroundColor White
    Write-Host "  Sprints  : $Sprints" -ForegroundColor White
    Write-Host "  Dossier  : $InstallDir" -ForegroundColor White
    Write-Host ""
}

function Write-Phase  { param($n, $msg) Write-Host "`n  ┌─ Phase $n - $msg" -ForegroundColor Cyan }
function Write-Step   { param($msg)     Write-Host "  │  >> $msg" -ForegroundColor White }
function Write-OK     { param($msg)     Write-Host "  │  [OK] $msg" -ForegroundColor Green }
function Write-Warn   { param($msg)     Write-Host "  │  [!!] $msg" -ForegroundColor Yellow }
function Write-Fail   { param($msg)     Write-Host "  │  [FAIL] $msg" -ForegroundColor Red; $script:Errors++ }
function Write-Done   { param($msg)     Write-Host "  └─ $msg" -ForegroundColor Cyan }
function Write-Gap    {                 Write-Host "  │" }

function Invoke-Step {
    param([string]$Label, [scriptblock]$Block, [switch]$AllowFail)
    Write-Step $Label
    try {
        & $Block
    } catch {
        if ($AllowFail) {
            Write-Warn "Non bloquant : $_"
        } else {
            Write-Fail "Erreur : $_"
            Write-Host ""
            Write-Host "  Arret du script. Corriger l'erreur ci-dessus et relancer." -ForegroundColor Red
            exit 1
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Phase 0 - Prerequis systeme
# ─────────────────────────────────────────────────────────────────────────────
function Test-Prerequisites {
    Write-Phase 0 "Verification des prerequis systeme"

    # Espace disque (minimum 1 Go sur le lecteur d'installation)
    Write-Step "Espace disque disponible..."
    $drive = Split-Path -Qualifier $InstallDir
    if (-not $drive) { $drive = "C:" }
    try {
        $disk = Get-PSDrive -Name ($drive.TrimEnd(':')) -ErrorAction SilentlyContinue
        if ($disk) {
            $freeGB = [math]::Round($disk.Free / 1GB, 1)
            if ($freeGB -lt 1) {
                Write-Fail "Espace insuffisant sur $drive : ${freeGB} Go disponibles (minimum 1 Go requis)"
                exit 1
            }
            Write-OK "Espace disque : ${freeGB} Go disponibles sur $drive"
        } else {
            Write-Warn "Impossible de verifier l'espace disque sur $drive - continuation"
        }
    } catch {
        Write-Warn "Verification espace disque ignoree : $_"
    }

    # Acces Internet - ping sur trois endpoints
    Write-Step "Acces Internet..."
    $internet = $false
    foreach ($checkHost in @("github.com", "pypi.org", "router.huggingface.co")) {
        try {
            $result = Test-NetConnection -ComputerName $checkHost -Port 443 -WarningAction SilentlyContinue -InformationLevel Quiet
            if ($result) { $internet = $true; break }
        } catch {}
    }
    if (-not $internet) {
        Write-Fail "Pas d'acces Internet detecte. Verifier la connexion reseau."
        exit 1
    }
    Write-OK "Acces Internet confirme"

    # Acces a la cible
    Write-Step "Acces a la cible ($Target)..."
    try {
        $targetHost = $Target -replace '^https?://', ''
        $result = Test-NetConnection -ComputerName $targetHost -Port 443 -WarningAction SilentlyContinue -InformationLevel Quiet
        if ($result) {
            Write-OK "Cible $Target accessible (port 443)"
        } else {
            Write-Warn "Cible $Target inaccessible sur port 443 - le scan continuera en mode degrade"
        }
    } catch {
        Write-Warn "Verification cible ignoree : $_"
    }

    # PowerShell version
    Write-Step "Version PowerShell..."
    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -lt 5) {
        Write-Fail "PowerShell $psVersion detecte. Version 5.1+ requise."
        exit 1
    }
    Write-OK "PowerShell $psVersion"

    # Windows 11 / 10
    Write-Step "Systeme d'exploitation..."
    $os = (Get-CimInstance Win32_OperatingSystem).Caption
    Write-OK $os

    Write-Done "Prerequis systeme OK"
}

# ─────────────────────────────────────────────────────────────────────────────
# Phase 1 - Installation des outils systeme
# ─────────────────────────────────────────────────────────────────────────────
function Install-SystemTools {
    Write-Phase 1 "Installation des outils systeme"

    # ── Git ──────────────────────────────────────────────────────────────────
    Write-Step "Git..."
    $git = Get-Command git -ErrorAction SilentlyContinue
    if ($git) {
        Write-OK "Git deja installe : $(git --version 2>&1)"
    } else {
        Write-Step "Git absent - telechargement via winget..."
        try {
            winget install --id Git.Git -e --source winget --silent --accept-package-agreements --accept-source-agreements 2>&1 | Out-Null
            # Recharger le PATH
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
            $git = Get-Command git -ErrorAction SilentlyContinue
            if ($git) {
                Write-OK "Git installe : $(git --version 2>&1)"
            } else {
                Write-Fail "Git installe mais non trouve dans PATH. Redemarrer le terminal et relancer."
                exit 1
            }
        } catch {
            Write-Fail "Impossible d'installer Git automatiquement."
            Write-Host "  Installer manuellement depuis : https://git-scm.com/download/win" -ForegroundColor Yellow
            exit 1
        }
    }

    # ── Python 3.11+ ─────────────────────────────────────────────────────────
    Write-Step "Python 3.11+..."
    $python = $null
    foreach ($cmd in @("python", "python3", "py")) {
        $c = Get-Command $cmd -ErrorAction SilentlyContinue
        if ($c) {
            $ver = & $cmd --version 2>&1
            if ($ver -match "3\.(\d+)" -and [int]$Matches[1] -ge 11) {
                $python = $cmd
                Write-OK "Python : $ver"
                break
            }
        }
    }
    if (-not $python) {
        Write-Step "Python 3.11+ absent - telechargement via winget..."
        try {
            winget install --id Python.Python.3.11 -e --source winget --silent --accept-package-agreements --accept-source-agreements 2>&1 | Out-Null
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
            $python = "python"
            Write-OK "Python installe : $(python --version 2>&1)"
        } catch {
            Write-Fail "Impossible d'installer Python automatiquement."
            Write-Host "  Installer manuellement depuis : https://www.python.org/downloads/" -ForegroundColor Yellow
            exit 1
        }
    }
    $script:Python = $python

    # ── uv ───────────────────────────────────────────────────────────────────
    Write-Step "uv (gestionnaire de packages Python)..."
    $uv = Get-Command uv -ErrorAction SilentlyContinue
    if ($uv) {
        Write-OK "uv deja installe : $(uv --version 2>&1)"
    } else {
        Write-Step "Installation de uv..."
        try {
            # Methode officielle uv (Windows)
            $uvInstall = Invoke-WebRequest -Uri "https://astral.sh/uv/install.ps1" -UseBasicParsing
            $uvScript = [System.Text.Encoding]::UTF8.GetString($uvInstall.Content)
            Invoke-Expression $uvScript 2>&1 | Out-Null
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User") + ";$env:USERPROFILE\.cargo\bin;$env:USERPROFILE\.local\bin"
            $uv = Get-Command uv -ErrorAction SilentlyContinue
            if ($uv) {
                Write-OK "uv installe : $(uv --version 2>&1)"
            } else {
                Write-Warn "uv installe mais non trouve - fallback sur pip"
            }
        } catch {
            Write-Warn "Installation uv echouee - fallback sur pip : $_"
        }
    }
    $script:UseUv = ($null -ne (Get-Command uv -ErrorAction SilentlyContinue))

    Write-Done "Outils systeme OK"
}

# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 - Depot GitHub (clone ou synchronisation)
# ─────────────────────────────────────────────────────────────────────────────
function Sync-Repository {
    Write-Phase 2 "Depot GitHub"

    if (Test-Path "$InstallDir\.git") {
        # Deja clone - synchroniser
        Write-Step "Depot existant detecte dans $InstallDir - synchronisation..."
        Push-Location $InstallDir
        try {
            cmd /c "git fetch origin 2>nul"
            cmd /c "git pull origin main 2>nul"
            cmd /c "git checkout main 2>nul"
            $lastCommit = (git log -1 --pretty=format:"%h %s (%cr)" 2>&1) -join ""
            Write-OK "Synchronise - dernier commit : $lastCommit"
        } catch {
            Write-Warn "Synchronisation git echouee (mode hors ligne ?) : $_"
        } finally {
            Pop-Location
        }
    } else {
        # Premier clone
        Write-Step "Clonage depuis $RepoUrl..."
        Write-Step "(depot public - aucun compte GitHub requis)"
        try {
            $cloneParent = Split-Path $InstallDir -Parent
            if (-not (Test-Path $cloneParent)) { New-Item -ItemType Directory -Path $cloneParent -Force | Out-Null }
            # Use Start-Process to avoid cmd quoting issues with paths containing backslashes
            $cloneArgs = "clone --quiet $RepoUrl $InstallDir"
            $proc = Start-Process -FilePath "git" -ArgumentList $cloneArgs -Wait -PassThru -WindowStyle Hidden
            if ($proc.ExitCode -ne 0) { throw "git clone exit code $($proc.ExitCode)" }
            $lastCommit = (git -C "$InstallDir" log -1 --pretty=format:"%h %s" 2>&1) -join ""
            Write-OK "Clone reussi : $lastCommit"
        } catch {
            Write-Fail "Clone echoue : $_"
            Write-Host "  Verifier que le depot $RepoUrl est public et accessible." -ForegroundColor Yellow
            exit 1
        }
    }

    Push-Location $InstallDir

    # Verifier .env
    # Cas special: .env present dans le dossier parent (migration depuis ancienne structure)
    $parentEnv = Join-Path (Split-Path $InstallDir -Parent) ".env"
    if ((Test-Path $parentEnv) -and (-not (Test-Path ".env"))) {
        Copy-Item $parentEnv ".env" -Force
        Write-OK ".env copie depuis le dossier parent"
    }
    if (-not (Test-Path ".env")) {
        if (Test-Path ".env.example") {
            Write-Step "Creation de .env depuis .env.example..."
            Copy-Item ".env.example" ".env"
            Write-Warn ".env cree - EDITER le fichier pour ajouter les cles API :"
            Write-Warn "  ANTHROPIC_API_KEY=sk-ant-..."
            Write-Warn "  HF_TOKEN=hf_..."
            Write-Host ""
            Write-Host "  Ouvrir .env dans le Bloc-notes ?" -ForegroundColor Yellow -NoNewline
            $resp = Read-Host " [O/n]"
            if ($resp -ne "n" -and $resp -ne "N") {
                Start-Process notepad "$InstallDir\.env" -Wait
            }
        } else {
            Write-Warn ".env absent et pas de .env.example - le pipeline IA ne pourra pas demarrer"
            Write-Warn "Creer $InstallDir\.env avec ANTHROPIC_API_KEY et HF_TOKEN"
        }
    } else {
        Write-OK ".env present"
    }

    Pop-Location
    Write-Done "Depot pret dans $InstallDir"
}

# ─────────────────────────────────────────────────────────────────────────────
# Phase 3 - Environnement Python (venv + dependances)
# ─────────────────────────────────────────────────────────────────────────────
function Install-PythonEnv {
    Write-Phase 3 "Environnement Python"
    Push-Location $InstallDir

    # Creer le venv
    $venvPath = ".venv"
    if (-not (Test-Path "$venvPath\Scripts\python.exe")) {
        Write-Step "Creation du venv Python..."
        if ($script:UseUv) {
            cmd /c "uv venv $venvPath 2>nul"
        } else {
            & $script:Python -m venv $venvPath 2>&1 | Out-Null
        }
        Write-OK "Venv cree dans $venvPath"
    } else {
        Write-OK "Venv existant reutilise"
    }

    # Chemin vers python du venv
    $script:VenvPython = "$InstallDir\$venvPath\Scripts\python.exe"
    $script:VenvPip    = "$InstallDir\$venvPath\Scripts\pip.exe"

    # Installer les dependances
    if (Test-Path "requirements.txt") {
        Write-Step "Installation des dependances (requirements.txt)..."
        if ($script:UseUv) {
            $out = uv pip install -r requirements.txt --python "$script:VenvPython" 2>&1
        } else {
            $out = & $script:VenvPip install -r requirements.txt --quiet 2>&1
        }
        if ($LASTEXITCODE -ne 0) {
            Write-Fail "Installation dependances echouee"
            $out | Select-Object -Last 5 | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
        } else {
            Write-OK "Dependances installees"
        }
    } else {
        Write-Warn "requirements.txt absent dans $InstallDir"
        Write-Warn "Le depot semble incomplet. Tentative de re-clone..."
        try {
            Remove-Item "$InstallDir\.git" -Recurse -Force -ErrorAction SilentlyContinue
            cmd /c "git clone --quiet $RepoUrl $InstallDir 2>nul"
            if (Test-Path "requirements.txt") {
                Write-OK "Re-clone reussi - requirements.txt retrouve"
                if ($script:UseUv) {
                    cmd /c "uv pip install -r requirements.txt --python \"$script:VenvPython\" 2>nul"
                } else {
                    & $script:VenvPip install -r requirements.txt --quiet 2>&1 | Out-Null
                }
                Write-OK "Dependances installees"
            } else {
                Write-Fail "requirements.txt toujours absent apres re-clone"
            }
        } catch {
            Write-Fail "Re-clone echoue : $_"
        }
    }

    # S'assurer que openai est installe (requis par test_api_keys.py + HFCriticAgent)
    Write-Step "Verification paquet openai..."
    cmd /c "`"$script:VenvPython`" -c `"import openai`" 2>nul"
    if ($LASTEXITCODE -ne 0) {
        Write-Step "Installation de openai..."
        if ($script:UseUv) {
            cmd /c "uv pip install openai --python `"$script:VenvPython`" --quiet 2>nul"
        } else {
            cmd /c "`"$script:VenvPip`" install openai --quiet 2>nul"
        }
        cmd /c "`"$script:VenvPython`" -c `"import openai`" 2>nul"
        if ($LASTEXITCODE -eq 0) {
            Write-OK "openai installe"
        } else {
            Write-Warn "openai non installe - le CriticAgent HuggingFace sera inoperant"
        }
    } else {
        Write-OK "openai present dans le venv"
    }

    # Verifier anthropic
    Write-Step "Verification paquet anthropic..."
    cmd /c "`"$script:VenvPython`" -c `"import anthropic`" 2>nul"
    if ($LASTEXITCODE -eq 0) {
        Write-OK "anthropic present dans le venv"
    } else {
        Write-Warn "anthropic non installe - verifier requirements.txt"
    }

    Pop-Location
    Write-Done "Environnement Python pret"
}

# ─────────────────────────────────────────────────────────────────────────────
# Phase 4 - Test des cles API
# ─────────────────────────────────────────────────────────────────────────────
function Test-ApiKeys {
    Write-Phase 4 "Test des cles API"
    Push-Location $InstallDir

    if (-not (Test-Path "test_api_keys.py")) {
        Write-Warn "test_api_keys.py absent - test des cles ignore"
        Pop-Location
        return
    }

    # Charger les variables du .env dans le processus courant
    if (Test-Path ".env") {
        Get-Content ".env" | ForEach-Object {
            if ($_ -match '^\s*([^#][^=]+)=(.+)$') {
                $key = $Matches[1].Trim()
                $val = $Matches[2].Trim().Trim('"').Trim("'")
                [System.Environment]::SetEnvironmentVariable($key, $val, "Process")
            }
        }
        Write-OK ".env charge dans le processus"
    }

    Write-Step "Test Anthropic API (AnalystAgent)..."
    $anthropicKey = [System.Environment]::GetEnvironmentVariable("ANTHROPIC_API_KEY", "Process")
    if (-not $anthropicKey) {
        Write-Warn "ANTHROPIC_API_KEY absent du .env - test Anthropic ignore"
        $script:AnthropicOK = $false
    } else {
        $result = & $script:VenvPython test_api_keys.py --anthropic-only 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-OK "Anthropic API : cle valide"
            $script:AnthropicOK = $true
        } else {
            # Detecter budget epuise
            $resetLine = $result | Where-Object { $_ -match "reset|budget|epuise|credit" } | Select-Object -First 1
            if ($resetLine) {
                Write-Warn "Anthropic : $resetLine"
            } else {
                Write-Warn "Anthropic API : cle invalide ou solde insuffisant"
                if ($result) { $result | Select-Object -Last 3 | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow } }
            }
            $script:AnthropicOK = $false
        }
    }

    Write-Step "Test HuggingFace Router (CriticAgent DeepSeek)..."
    $hfToken = [System.Environment]::GetEnvironmentVariable("HF_TOKEN", "Process")
    if (-not $hfToken) {
        Write-Warn "HF_TOKEN absent du .env - test HuggingFace ignore"
        $script:HFOK = $false
    } else {
        $result = & $script:VenvPython test_api_keys.py --hf-only 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-OK "HuggingFace Router : token valide, DeepSeek V4 Pro accessible"
            $script:HFOK = $true
        } else {
            $resetLine = $result | Where-Object { $_ -match "reset|budget|quota|epuise" } | Select-Object -First 1
            if ($resetLine) {
                Write-Warn "HuggingFace : $resetLine"
            } else {
                Write-Warn "HuggingFace : token invalide ou quota depasse"
                if ($result) { $result | Select-Object -Last 3 | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow } }
            }
            $script:HFOK = $false
        }
    }

    # Ajuster les sprints si IA indisponible
    if ((-not $script:AnthropicOK) -or (-not $script:HFOK)) {
        Write-Warn "Une ou les deux cles IA sont invalides - le pipeline sera lance en mode --no-ai"
        $script:ForceNoAI = $true
    } else {
        $script:ForceNoAI = $false
    }

    Pop-Location
    Write-Done "Test cles API termine"
}

# ─────────────────────────────────────────────────────────────────────────────
# Phase 5 - Tests unitaires pytest
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-Tests {
    Write-Phase 5 "Tests unitaires (pytest)"
    Push-Location $InstallDir

    $pytest = Get-Command "$InstallDir\.venv\Scripts\pytest.exe" -ErrorAction SilentlyContinue
    if (-not $pytest) {
        Write-Warn "pytest absent dans le venv - tests ignores"
        Pop-Location
        return
    }

    Write-Step "Lancement de pytest..."
    $output = & "$InstallDir\.venv\Scripts\pytest.exe" tests/ -v --tb=short 2>&1
    $summaryLine = $output | Where-Object { $_ -match "passed|failed|error" } | Select-Object -Last 1

    if ($summaryLine) {
        $passed  = if ($summaryLine -match "(\d+) passed")  { [int]$Matches[1] } else { 0 }
        $failed  = if ($summaryLine -match "(\d+) failed")  { [int]$Matches[1] } else { 0 }
        $errors  = if ($summaryLine -match "(\d+) error")   { [int]$Matches[1] } else { 0 }
        $skipped = if ($summaryLine -match "(\d+) skipped") { [int]$Matches[1] } else { 0 }
        $totalFail = $failed + $errors

        if ($totalFail -eq 0) {
            Write-OK "pytest : $passed PASS$(if ($skipped -gt 0) { ", $skipped skip" })"
        } else {
            Write-Warn "pytest : $totalFail FAIL / $passed PASS"
            $output | Where-Object { $_ -match "FAILED|ERROR" } | ForEach-Object {
                Write-Host "    $_" -ForegroundColor Yellow
            }
            Write-Warn "Des tests echouent mais le pipeline peut quand meme tourner"
        }
    } else {
        Write-Warn "Aucun test collecte - verifier le dossier tests/"
    }

    Pop-Location
    Write-Done "Tests unitaires termines"
}

# ─────────────────────────────────────────────────────────────────────────────
# Phase 6 - Pipeline de scan
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-Pipeline {
    Write-Phase 6 "Pipeline de scan"
    Push-Location $InstallDir

    if (-not (Test-Path "main.py")) {
        Write-Warn "main.py absent - pipeline ignore"
        Pop-Location
        return
    }

    # Construire les arguments
    $args = @("main.py", "--target", $Target, "--sprints", $Sprints)

    if ($NoAI -or $script:ForceNoAI) {
        $args += "--no-ai"
        Write-Step "Mode --no-ai active (sprints S1+S2+S3 uniquement)"
    } else {
        Write-Step "Mode complet (sprints $Sprints avec agents IA)"
    }

    Write-Step "Commande : python $($args -join ' ')"
    Write-Gap

    # Lancer le pipeline en streaming (affichage temps reel)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName               = $script:VenvPython
    $psi.Arguments              = $args -join " "
    $psi.WorkingDirectory       = $InstallDir
    $psi.UseShellExecute        = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true

    # Injecter les variables d'env du .env dans le processus fils
    if (Test-Path ".env") {
        Get-Content ".env" | ForEach-Object {
            if ($_ -match '^\s*([^#][^=]+)=(.+)$') {
                $k = $Matches[1].Trim()
                $v = $Matches[2].Trim().Trim('"').Trim("'")
                $psi.EnvironmentVariables[$k] = $v
            }
        }
    }

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    $proc.Start() | Out-Null

    # Lire stdout en temps reel
    while (-not $proc.StandardOutput.EndOfStream) {
        $line = $proc.StandardOutput.ReadLine()
        if ($line -match "FAIL|ERROR|Traceback") {
            Write-Host "  │  $line" -ForegroundColor Red
        } elseif ($line -match "CONFIRMED|CONFIRMED=") {
            Write-Host "  │  $line" -ForegroundColor Green
        } elseif ($line -match "NUANCED|WARNING|warn") {
            Write-Host "  │  $line" -ForegroundColor Yellow
        } else {
            Write-Host "  │  $line" -ForegroundColor White
        }
    }

    # Lire stderr
    $stderr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()

    if ($proc.ExitCode -ne 0) {
        Write-Fail "Pipeline termine avec exit code $($proc.ExitCode)"
        if ($stderr) {
            $stderr -split "`n" | Select-Object -Last 8 | ForEach-Object {
                Write-Host "  │  $_" -ForegroundColor Red
            }
        }
    } else {
        Write-OK "Pipeline termine avec succes"
    }

    # Lister les fichiers de resultat produits
    Write-Gap
    Write-Step "Fichiers de resultats produits :"
    $results = Get-ChildItem "$InstallDir\results" -Filter "*.json" -ErrorAction SilentlyContinue |
               Where-Object { $_.LastWriteTime -gt $StartTime } |
               Sort-Object LastWriteTime
    if ($results) {
        $results | ForEach-Object {
            $sizeKB = [math]::Round($_.Length / 1KB, 0)
            Write-OK "$($_.Name)  (${sizeKB} Ko)"
        }
    } else {
        Write-Warn "Aucun fichier JSON produit dans results/"
    }

    # Chercher le rapport MD
    $report = Get-ChildItem "$InstallDir\results" -Filter "*.md" -ErrorAction SilentlyContinue |
              Where-Object { $_.LastWriteTime -gt $StartTime } |
              Sort-Object LastWriteTime -Descending |
              Select-Object -First 1
    if ($report) {
        Write-OK "Rapport genere : $($report.FullName)"
        $script:ReportPath = $report.FullName
    }

    Pop-Location
    Write-Done "Pipeline termine"
}

# ─────────────────────────────────────────────────────────────────────────────
# Phase 7 - Ouverture du dashboard
# ─────────────────────────────────────────────────────────────────────────────
function Open-Dashboard {
    Write-Phase 7 "Dashboard SecAudit"
    Push-Location $InstallDir

    $dashPath = "$InstallDir\ui\dashboard.html"
    if (-not (Test-Path $dashPath)) {
        Write-Warn "Dashboard absent : $dashPath"
        Pop-Location
        return
    }

    # Choisir le port (8080 par defaut, fallback 8081)
    $port = 8080
    $portCheck = Test-NetConnection -ComputerName localhost -Port $port -WarningAction SilentlyContinue -InformationLevel Quiet
    if ($portCheck) {
        $port = 8081
        Write-Warn "Port 8080 occupe - utilisation du port $port"
    }

    $dashUrl = "http://localhost:$port/dashboard.html"

    Write-Step "Demarrage du serveur local sur le port $port..."

    # Lancer le serveur Python en arriere-plan
    $serverArgs = "-m http.server $port --directory `"$InstallDir\ui`""
    $serverProc = Start-Process -FilePath $script:VenvPython `
        -ArgumentList $serverArgs `
        -WorkingDirectory "$InstallDir\ui" `
        -WindowStyle Hidden `
        -PassThru

    $script:ServerProc = $serverProc
    Start-Sleep -Seconds 2

    # Verifier que le serveur repond
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:$port" -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
        Write-OK "Serveur local demarre : $dashUrl"
    } catch {
        Write-Warn "Serveur peut-etre pas encore pret - ouverture quand meme"
    }

    # Ouvrir le navigateur par defaut
    Write-Step "Ouverture du navigateur..."
    Start-Process $dashUrl
    Write-OK "Dashboard ouvert : $dashUrl"

    # Si un fichier JSON existe, indiquer comment le charger
    $latestJson = Get-ChildItem "$InstallDir\results" -Filter "s5_critic*.json" -ErrorAction SilentlyContinue |
                  Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($latestJson) {
        Write-Gap
        Write-Step "Pour charger les resultats dans le dashboard :"
        Write-Step "  1. Cliquer sur le bouton 'Charger JSON'"
        Write-Step "  2. Selectionner : $($latestJson.FullName)"
    }

    if ($script:ReportPath) {
        Write-Gap
        Write-Step "Rapport Markdown disponible :"
        Write-Step "  $($script:ReportPath)"
        Write-Host ""
        Write-Host "  Ouvrir le rapport dans le Bloc-notes ?" -ForegroundColor Yellow -NoNewline
        $resp = Read-Host " [O/n]"
        if ($resp -ne "n" -and $resp -ne "N") {
            Start-Process notepad $script:ReportPath
        }
    }

    Pop-Location
    Write-Done "Dashboard lance"
}

# ─────────────────────────────────────────────────────────────────────────────
# Resume final
# ─────────────────────────────────────────────────────────────────────────────
function Write-FinalSummary {
    $duration = (Get-Date) - $StartTime
    $durationStr = "{0:mm}m{0:ss}s" -f $duration

    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║              Resume d'execution                  ║" -ForegroundColor Cyan
    Write-Host "  ╠══════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "  ║  Duree totale  : $($durationStr.PadRight(30))  ║" -ForegroundColor White
    Write-Host "  ║  Cible         : $($Target.PadRight(30))  ║" -ForegroundColor White
    Write-Host "  ║  Anthropic API : $(if ($script:AnthropicOK) { 'OK'.PadRight(31) } else { 'indisponible'.PadRight(31) })  ║" -ForegroundColor $(if ($script:AnthropicOK) { 'Green' } else { 'Yellow' })
    Write-Host "  ║  HF Router     : $(if ($script:HFOK) { 'OK'.PadRight(31) } else { 'indisponible'.PadRight(31) })  ║" -ForegroundColor $(if ($script:HFOK) { 'Green' } else { 'Yellow' })

    if ($script:Errors -eq 0) {
        Write-Host "  ║                                                  ║"
        Write-Host "  ║  [OK] Environnement pret et pipeline lance       ║" -ForegroundColor Green
    } else {
        Write-Host "  ║                                                  ║"
        Write-Host "  ║  [$($script:Errors) erreur(s)] - voir details ci-dessus    ║" -ForegroundColor Red
    }
    Write-Host "  ╚══════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    if ($script:ServerProc -and -not $script:ServerProc.HasExited) {
        Write-Host "  Serveur local actif sur http://localhost:8080/dashboard.html" -ForegroundColor Cyan
        Write-Host "  Appuyer sur Entree pour arreter le serveur et quitter..." -ForegroundColor Gray
        Read-Host | Out-Null
        try { $script:ServerProc.Kill() } catch {}
        Write-Host "  Serveur arrete." -ForegroundColor Gray
    }
}


# =============================================================================
# RECUPERATION MANUELLE (si dependances manquantes apres le script)
# =============================================================================
function Show-ManualRecovery {
    cmd /c "$InstallDir\.venv\Scripts\python.exe -c \"import typer\" 2>nul"
    if ($LASTEXITCODE -eq 0) { return }

    Write-Host ""
    Write-Host "  ================================================================" -ForegroundColor Yellow
    Write-Host "  ATTENTION : dependances Python manquantes." -ForegroundColor Yellow
    Write-Host "  Copier-coller ces commandes dans PowerShell :" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    cd `"$InstallDir`"" -ForegroundColor Cyan
    Write-Host "    Set-ExecutionPolicy -Scope CurrentUser RemoteSigned -Force" -ForegroundColor Cyan
    Write-Host "    .\.venv\Scripts\Activate.ps1" -ForegroundColor Cyan
    Write-Host "    pip install -r requirements.txt" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Puis lancer le pipeline :" -ForegroundColor Yellow
    Write-Host "    python main.py --target telemo.gov.gn --sprints 1,2,3,4,5" -ForegroundColor Cyan
    Write-Host "  ================================================================" -ForegroundColor Yellow
    Write-Host ""
}

# ─────────────────────────────────────────────────────────────────────────────
# Point d'entree principal
# ─────────────────────────────────────────────────────────────────────────────

Write-Banner

# Initialisation des flags
$script:AnthropicOK  = $false
$script:HFOK         = $false
$script:ForceNoAI    = $false
$script:ReportPath   = $null
$script:ServerProc   = $null
$script:Python       = "python"
$script:UseUv        = $false
$script:VenvPython   = "python"

# Sequence d'execution
Test-Prerequisites

if (-not $SkipInstall) {
    Install-SystemTools
    Sync-Repository
    Install-PythonEnv
}

Test-ApiKeys

if (-not $SkipScan) {
    Invoke-Tests
    Invoke-Pipeline
}

Show-ManualRecovery
Open-Dashboard
Write-FinalSummary

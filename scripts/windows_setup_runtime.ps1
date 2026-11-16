<#
.SYNOPSIS
    Automated Windows x64 runtime & companion setup for NetFlow Sentinel v0.6.0.
.DESCRIPTION
    Prepares the isolated Python virtual environment (%LOCALAPPDATA%\NetFlowSentinelM6\.venv)
    using Python >= 3.12 and bounded runtime dependencies (requirements-runtime.txt),
    optionally verifies & installs a companion bundle ZIP/directory, and checks readiness.
    Requires no Rust, Node.js, Git, or Administrator privileges.
#>
[CmdletBinding()]
param(
    [string]$RuntimeDir = $(if ($env:NETWORK_ANOMALY_RUNTIME_DIR) { $env:NETWORK_ANOMALY_RUNTIME_DIR } else { Join-Path $env:LOCALAPPDATA "NetFlowSentinelM6" }),
    [string]$RepoRoot = $(if ($env:NETWORK_ANOMALY_REPO_ROOT) { $env:NETWORK_ANOMALY_REPO_ROOT } else { (Resolve-Path (Join-Path $PSScriptRoot "..")).Path }),
    [string]$PythonExe = "",
    [string]$WheelhouseDir = "",
    [string]$CompanionBundleZip = "",
    [string]$CompanionBundleDir = "",
    [string]$CompanionBundleSha256 = ""
)

$ErrorActionPreference = "Stop"

function Resolve-CompatiblePython {
    param([string]$ExplicitPython)
    $candidates = @()
    if (-not [string]::IsNullOrWhiteSpace($ExplicitPython)) {
        $candidates += ,@($ExplicitPython, @())
    }
    if (-not [string]::IsNullOrWhiteSpace($env:NETWORK_ANOMALY_PYTHON)) {
        $candidates += ,@($env:NETWORK_ANOMALY_PYTHON, @())
    }
    $candidates += @(
        ,@("py", @("-3.12")),
        ,@("py", @("-3.13")),
        ,@("py", @("-3.14")),
        ,@("py", @("-3")),
        ,@("python", @())
    )
    foreach ($verDir in @("Python312", "Python313", "Python314")) {
        if ($env:LOCALAPPDATA) {
            $p = Join-Path $env:LOCALAPPDATA "Programs\Python\$verDir\python.exe"
            if (Test-Path $p) { $candidates += ,@($p, @()) }
        }
        if ($env:ProgramFiles) {
            $p = Join-Path $env:ProgramFiles "$verDir\python.exe"
            if (Test-Path $p) { $candidates += ,@($p, @()) }
        }
    }
    foreach ($entry in $candidates) {
        $cmd = $entry[0]
        $prefix = $entry[1]
        try {
            $out = & $cmd @prefix -c "import sys; print(f'{sys.version_info[0]}.{sys.version_info[1]}|{sys.executable}')" 2>$null
            if ($LASTEXITCODE -eq 0 -and $out) {
                $parts = ($out | Select-Object -Last 1).Trim().Split("|", 2)
                if ($parts.Length -eq 2) {
                    $ver = [version]$parts[0]
                    if ($ver.Major -eq 3 -and $ver.Minor -ge 12) {
                        return $parts[1]
                    }
                }
            }
        } catch {
            continue
        }
    }
    throw "Python >= 3.12 (x64) is required for NetFlow Sentinel runtime dependencies (numpy 2.5+, xgboost 3.4+). Install Python 3.12 from https://www.python.org/downloads/windows/ or 'winget install Python.Python.3.12'."
}

if (-not (Test-Path (Join-Path $RepoRoot "scripts\run_api.py"))) {
    throw "Invalid RepoRoot '$RepoRoot': missing scripts\run_api.py"
}

$ReqFile = Join-Path $RepoRoot "requirements-runtime.txt"
if (-not (Test-Path $ReqFile)) {
    throw "Missing requirements-runtime.txt in '$RepoRoot'"
}

$BasePython = Resolve-CompatiblePython -ExplicitPython $PythonExe
Write-Host "[1/4] Using base Python: $BasePython"

New-Item -ItemType Directory -Force -Path $RuntimeDir | Out-Null
$VenvDir = Join-Path $RuntimeDir ".venv"
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"

if (-not (Test-Path $VenvPython)) {
    Write-Host "[2/4] Creating virtual environment at $VenvDir ..."
    & $BasePython -m venv $VenvDir
    if ($LASTEXITCODE -ne 0) {
        throw "Failed creating Python venv at '$VenvDir'."
    }
} else {
    Write-Host "[2/4] Reusing existing virtual environment at $VenvDir"
}

Write-Host "[3/4] Installing bounded runtime dependencies from requirements-runtime.txt ..."
if (-not [string]::IsNullOrWhiteSpace($WheelhouseDir)) {
    & $VenvPython -m pip install --no-index --find-links $WheelhouseDir -r $ReqFile
} else {
    & $VenvPython -m pip install --upgrade pip
    if ($LASTEXITCODE -ne 0) { throw "pip upgrade failed." }
    & $VenvPython -m pip install -r $ReqFile
}
if ($LASTEXITCODE -ne 0) {
    throw "Failed installing Python runtime dependencies."
}

$env:PYTHONPATH = Join-Path $RepoRoot "src"
& $VenvPython -c "import fastapi, uvicorn, httpx, pandas, joblib, sklearn, xgboost, pydantic, network_anomaly.api.main; print('Runtime import check OK')"
if ($LASTEXITCODE -ne 0) {
    throw "Python runtime dependency verification failed."
}

if (-not [string]::IsNullOrWhiteSpace($CompanionBundleZip)) {
    Write-Host "[4/4] Installing & verifying companion bundle ZIP into $RuntimeDir ..."
    $argsList = @(
        (Join-Path $RepoRoot "scripts\verify_companion_artifacts.py"),
        "--root", $RepoRoot,
        "--runtime-dir", $RuntimeDir,
        "--install-bundle-archive", $CompanionBundleZip
    )
    if (-not [string]::IsNullOrWhiteSpace($CompanionBundleSha256)) {
        $argsList += @("--expect-bundle-sha256", $CompanionBundleSha256.Trim())
    }
    & $VenvPython @argsList
    if ($LASTEXITCODE -ne 0) {
        throw "Companion bundle archive installation/verification failed."
    }
} elseif (-not [string]::IsNullOrWhiteSpace($CompanionBundleDir)) {
    Write-Host "[4/4] Installing & verifying companion bundle directory into $RuntimeDir ..."
    & $VenvPython (Join-Path $RepoRoot "scripts\verify_companion_artifacts.py") `
        --root $RepoRoot `
        --runtime-dir $RuntimeDir `
        --install-bundle-dir $CompanionBundleDir
    if ($LASTEXITCODE -ne 0) {
        throw "Companion bundle directory installation/verification failed."
    }
} else {
    Write-Host "[4/4] Checking companion artifacts status in $RuntimeDir ..."
    & $VenvPython (Join-Path $RepoRoot "scripts\verify_companion_artifacts.py") --root $RepoRoot --runtime-dir $RuntimeDir
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Python runtime is READY, but companion artifacts (4 models + preprocessor + demo CSV) are not yet installed in '$RuntimeDir'. Import the companion bundle in the desktop app or rerun with -CompanionBundleZip."
    }
}

Write-Host "Setup completed. Runtime directory: $RuntimeDir"

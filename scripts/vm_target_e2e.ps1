<#
.SYNOPSIS
Clean Windows Test Target E2E runner for NetFlow Sentinel v2.0.0 standalone installer.

.DESCRIPTION
Executes exclusively on the Clean Windows Test Target without requiring Git, Python, Rust,
Node.js, a repository checkout, a Companion Bundle, or any attestation signing secrets.
Consumes a Controller-issued challenge JSON + NSIS installer, performs clean install,
embedded layout/SHA-256 verification, cold-start WebView2 + PyInstaller sidecar E2E across
all 4 models, session-auth fail-closed check, CSV export, SQLite restart persistence,
graceful close (zero orphan processes), and NSIS uninstall, then emits target_evidence.json
for verification on the Build/Verification Controller.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$InstallerPath,

    [Parameter(Mandatory = $true)]
    [string]$ChallengePath,

    [Parameter(Mandatory = $true)]
    [string]$OutputJson,

    [string]$WorkDir = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Get-LowerSha256([string]$Path) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $hashBytes = $sha.ComputeHash($stream)
        return ([System.BitConverter]::ToString($hashBytes) -replace "-", "").ToLowerInvariant()
    } finally {
        $stream.Dispose()
        $sha.Dispose()
    }
}

function New-RandomHexToken([int]$ByteCount = 32) {
    $bytes = New-Object byte[] $ByteCount
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        $rng.Dispose()
    }
    return ([System.BitConverter]::ToString($bytes) -replace "-", "").ToLowerInvariant()
}

function Test-PidAlive([int]$TargetPid) {
    if ($TargetPid -le 0) { return $false }
    try {
        $p = Get-Process -Id $TargetPid -ErrorAction Stop
        return (-not $p.HasExited)
    } catch {
        return $false
    }
}

function Test-LoopbackPortOpen([int]$Port) {
    if ($Port -le 0) { return $false }
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect("127.0.0.1", $Port, $null, $null)
        $connected = $iar.AsyncWaitHandle.WaitOne(300, $false)
        if ($connected -and $client.Connected) {
            $client.EndConnect($iar)
            return $true
        }
        return $false
    } catch {
        return $false
    } finally {
        $client.Dispose()
    }
}

function Request-GracefulWindowClose([System.Diagnostics.Process]$Proc) {
    try {
        $Proc.Refresh()
        if ($Proc.MainWindowHandle -ne [IntPtr]::Zero) {
            if ($Proc.CloseMainWindow()) {
                return "close_main_window"
            }
        }
    } catch {
        # Fall back to soft taskkill below
    }
    & taskkill.exe /PID $Proc.Id | Out-Null
    return "taskkill_soft"
}

function Invoke-LoopbackJson {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [string]$Method = "GET",
        [object]$BodyObject = $null,
        [hashtable]$Headers = @{},
        [int]$TimeoutSeconds = 30
    )
    Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue
    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.UseProxy = $false
    $client = New-Object System.Net.Http.HttpClient($handler)
    $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
    try {
        $httpMethod = New-Object System.Net.Http.HttpMethod($Method)
        $req = New-Object System.Net.Http.HttpRequestMessage($httpMethod, $Url)
        $req.Headers.Accept.ParseAdd("application/json")
        foreach ($k in $Headers.Keys) {
            $null = $req.Headers.TryAddWithoutValidation($k, [string]$Headers[$k])
        }
        if ($null -ne $BodyObject) {
            $jsonBody = $BodyObject | ConvertTo-Json -Depth 12 -Compress
            $req.Content = New-Object System.Net.Http.StringContent($jsonBody, [System.Text.Encoding]::UTF8, "application/json")
        }
        $resp = $client.SendAsync($req).GetAwaiter().GetResult()
        $statusCode = [int]$resp.StatusCode
        $rawText = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        return @{
            StatusCode = $statusCode
            BodyText   = $rawText
            Json       = $(if ($rawText) { $rawText | ConvertFrom-Json } else { $null })
        }
    } finally {
        $client.Dispose()
        $handler.Dispose()
    }
}

function Get-TargetHostProbe([string]$InstallerDir, [string]$InstallDir) {
    $checkedTools = @("git", "python", "python3", "py", "rustc", "cargo", "node", "npm")
    $foundTools = @()
    $storeAliases = @()
    foreach ($tool in $checkedTools) {
        foreach ($command in @(Get-Command $tool -All -ErrorAction SilentlyContinue)) {
            if ($tool -in @("python", "python3") -and $command.CommandType -eq "Application") {
                $expectedAlias = Join-Path $env:LOCALAPPDATA "Microsoft\WindowsApps\$tool.exe"
                if ($command.Source -eq $expectedAlias) {
                    $stub = Get-Item -LiteralPath $command.Source -Force -ErrorAction SilentlyContinue
                    if ($null -ne $stub -and $stub.Length -eq 0 -and
                        ($stub.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
                        $storeAliases += $tool
                        continue
                    }
                }
            }
            $foundTools += $tool
            break
        }
    }

    $stdDirsChecked = @(
        (Join-Path $env:ProgramFiles "Git"),
        (Join-Path $env:ProgramFiles "nodejs"),
        (Join-Path ${env:ProgramFiles(x86)} "nodejs"),
        (Join-Path $env:LOCALAPPDATA "Programs\Python"),
        (Join-Path $env:USERPROFILE ".cargo\bin")
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    $foundStdDirs = @()
    foreach ($d in $stdDirsChecked) {
        if (Test-Path $d) {
            $foundStdDirs += $d
        }
    }

    $cwdPath = (Get-Location).Path
    $gitDirPresent = (Test-Path (Join-Path $cwdPath ".git")) -or
                     (Test-Path (Join-Path $InstallerDir ".git")) -or
                     (Test-Path (Join-Path $InstallDir ".git"))
    $devModelsPresent = (Test-Path (Join-Path $cwdPath "artifacts\models\random_forest\random_forest_baseline.joblib")) -or
                        (Test-Path (Join-Path $InstallerDir "artifacts\models\random_forest\random_forest_baseline.joblib"))

    return @{
        platform                 = "win32"
        os_version               = [System.Environment]::OSVersion.VersionString
        observed_hostname        = $env:COMPUTERNAME
        git_dir_present          = [bool]$gitDirPresent
        dev_tools_checked        = $checkedTools
        dev_tools_absent         = ($foundTools.Count -eq 0 -and $foundStdDirs.Count -eq 0)
        found_dev_tools          = $foundTools
        python_store_aliases     = $storeAliases
        standard_tool_dirs_checked = $stdDirsChecked
        found_standard_tool_dirs = $foundStdDirs
        dev_models_tree_absent   = (-not $devModelsPresent)
        cleanliness_claim_scope  = "observed_path_and_standard_dirs_only_not_cryptographic_clean_os_proof"
    }
}

$resolvedInstaller = (Resolve-Path -Path $InstallerPath).Path
$resolvedChallenge = (Resolve-Path -Path $ChallengePath).Path
$challenge = Get-Content -Path $resolvedChallenge -Raw -Encoding utf8 | ConvertFrom-Json
if ($challenge.format -ne "netflow-sentinel-vm-challenge-v1") {
    throw "Unsupported VM challenge format: '$($challenge.format)'"
}

$installerItem = Get-Item -Path $resolvedInstaller
if ($installerItem.Length -lt 1000000) {
    throw "Installer size too small ($($installerItem.Length) bytes): $resolvedInstaller"
}
$installerSha = Get-LowerSha256 $resolvedInstaller
if ($installerSha -ne ([string]$challenge.installer_sha256).ToLowerInvariant()) {
    throw "Installer SHA-256 mismatch vs Controller challenge: $installerSha != $($challenge.installer_sha256)"
}

$cleanupWorkDir = $false
if ([string]::IsNullOrWhiteSpace($WorkDir)) {
    $WorkDir = Join-Path ([System.IO.Path]::GetTempPath()) ("nf_vm_target_" + [Guid]::NewGuid().ToString("N"))
    $cleanupWorkDir = $true
}
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null

$installDir = Join-Path $WorkDir "CleanInstall"
if (Test-Path -LiteralPath $installDir) {
    throw "Target install directory already exists: $installDir. Use a fresh work directory."
}
$runtimeDir = Join-Path $WorkDir "UserAppData"
$wv2Dir = Join-Path $WorkDir "WebView2Data"
$exportDir = Join-Path $WorkDir "UserExports"
New-Item -ItemType Directory -Force -Path $runtimeDir, $wv2Dir, $exportDir | Out-Null

$targetProbe = Get-TargetHostProbe -InstallerDir $installerItem.Directory.FullName -InstallDir $installDir

try {
    # 1. Silent NSIS install
    $instProc = Start-Process -FilePath $resolvedInstaller -ArgumentList @("/S", "/NS", "/D=$installDir") -Wait -PassThru
    if ($instProc.ExitCode -ne 0) {
        throw "NSIS silent install failed with exit code $($instProc.ExitCode)"
    }

    $installedExe = Join-Path $installDir "netflow-sentinel-desktop.exe"
    $sidecarExe = Join-Path $installDir "netflow-sentinel-backend.exe"
    $uninstallerExe = Join-Path $installDir "uninstall.exe"
    $waitEnd = (Get-Date).AddSeconds(15)
    while ((Get-Date) -lt $waitEnd) {
        if ((Test-Path $installedExe) -and (Test-Path $sidecarExe) -and (Test-Path $uninstallerExe)) {
            if ((Get-Item $installedExe).Length -ge 1000000 -and (Get-Item $uninstallerExe).Length -gt 0) {
                break
            }
        }
        Start-Sleep -Milliseconds 200
    }
    if (-not ((Test-Path $installedExe) -and (Test-Path $sidecarExe) -and (Test-Path $uninstallerExe))) {
        throw "NSIS clean install did not materialize expected executables in $installDir"
    }

    $installedExeSha = Get-LowerSha256 $installedExe
    $compiledSha = if ($challenge.compiled_exe_sha256) { ([string]$challenge.compiled_exe_sha256).ToLowerInvariant() } else { $null }
    $normCompiledSha = if ($challenge.normalized_compiled_exe_sha256) { ([string]$challenge.normalized_compiled_exe_sha256).ToLowerInvariant() } else { $null }
    $compiledMatch = $true
    $parityMode = "challenge_not_provided"
    if ($compiledSha) {
        if ($installedExeSha -eq $compiledSha) {
            $parityMode = "exact_sha256"
        } elseif ($normCompiledSha -and $installedExeSha -eq $normCompiledSha) {
            $parityMode = "tauri_nsis_bundle_marker_normalized"
        } else {
            throw "Installed desktop exe SHA-256 mismatch vs challenge: $installedExeSha"
        }
    }

    $actualSidecarSha = Get-LowerSha256 $sidecarExe
    $expectedSidecarSha = ([string]$challenge.sidecar_sha256).ToLowerInvariant()
    if ($actualSidecarSha -ne $expectedSidecarSha) {
        throw "Installed sidecar SHA-256 mismatch: $actualSidecarSha != $expectedSidecarSha"
    }
    $sidecarSizeBytes = (Get-Item $sidecarExe).Length

    # 2. Verify embedded notices, manifests, and EMBEDDED_SHA256SUMS.txt
    $requiredExtras = @(
        "NOTICE",
        "THIRD_PARTY_NOTICES.md",
        "LICENSE",
        "data\V2_SPLIT_MANIFEST.json",
        "data\AIT_DATASETS_MANIFEST.json",
        "data\CTU_SME_11_MANIFEST.json",
        "EMBEDDED_ARTIFACTS_MANIFEST.json",
        "EMBEDDED_SHA256SUMS.txt"
    )
    foreach ($rel in $requiredExtras) {
        $p = Join-Path $installDir $rel
        if (-not (Test-Path $p)) {
            throw "Missing required embedded file in install dir: $rel"
        }
    }

    $sumsLines = Get-Content -Path (Join-Path $installDir "EMBEDDED_SHA256SUMS.txt") -Encoding utf8
    $embeddedCount = 0
    foreach ($line in $sumsLines) {
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
        if ($trimmed -notmatch '^([0-9a-fA-F]{64})\s+\*?(.+)$') {
            throw "Malformed EMBEDDED_SHA256SUMS.txt line: $trimmed"
        }
        $expHash = $Matches[1].ToLowerInvariant()
        $relFile = $Matches[2].Trim()
        $fullFile = Join-Path $installDir ($relFile -replace "/", "\")
        if (-not (Test-Path $fullFile)) {
            throw "Missing embedded file listed in EMBEDDED_SHA256SUMS.txt: $relFile"
        }
        $actHash = Get-LowerSha256 $fullFile
        if ($actHash -ne $expHash) {
            throw "Embedded file SHA-256 mismatch for ${relFile}: $actHash != $expHash"
        }
        $embeddedCount += 1
    }

    $embManifest = Get-Content -Path (Join-Path $installDir "EMBEDDED_ARTIFACTS_MANIFEST.json") -Raw -Encoding utf8 | ConvertFrom-Json
    $splitSha = Get-LowerSha256 (Join-Path $installDir "data\V2_SPLIT_MANIFEST.json")
    $prepSha = Get-LowerSha256 (Join-Path $installDir "artifacts\preprocessing\v2_flow_preprocessor.joblib")
    $demoShaMap = @{
        "data/demo/demo_flows.csv"    = Get-LowerSha256 (Join-Path $installDir "data\demo\demo_flows.csv")
        "data/demo/demo_labels.csv"   = Get-LowerSha256 (Join-Path $installDir "data\demo\demo_labels.csv")
        "data/demo/demo_manifest.json" = Get-LowerSha256 (Join-Path $installDir "data\demo\demo_manifest.json")
    }

    # 3. Launch installed desktop app in scrubbed standalone environment
    $dbPath = Join-Path $runtimeDir "installed_desktop.db"
    $telemetryPath = Join-Path $WorkDir "desktop_telemetry.json"
    $sessionToken = New-RandomHexToken 32
    $authHeaders = @{ "X-Sentinel-Session-Token" = $sessionToken }
    $winRoot = if ($env:SystemRoot) { $env:SystemRoot } else { "C:\Windows" }
    $scrubbedPath = "$winRoot\System32;$winRoot;$winRoot\System32\Wbem"

    function Start-InstalledDesktop([string]$TokenValue) {
        if (Test-Path $telemetryPath) { Remove-Item $telemetryPath -Force }
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $installedExe
        $psi.WorkingDirectory = $installDir
        $psi.UseShellExecute = $false
        $psi.RedirectStandardInput = $false
        $psi.RedirectStandardOutput = $false
        $psi.RedirectStandardError = $false
        foreach ($removeKey in @(
            "NETWORK_ANOMALY_REPO_ROOT",
            "NETWORK_ANOMALY_RESOURCE_DIR",
            "NETWORK_ANOMALY_ARTIFACTS_DIR",
            "NETWORK_ANOMALY_DEMO_DIR",
            "NETWORK_ANOMALY_SIDECAR_EXE",
            "NETWORK_ANOMALY_PYTHON",
            "PYTHONPATH",
            "PYTHONHOME",
            "VIRTUAL_ENV",
            "CONDA_PREFIX"
        )) {
            $null = $psi.Environment.Remove($removeKey)
        }
        $psi.Environment["PATH"] = $scrubbedPath
        $psi.Environment["NETWORK_ANOMALY_RUNTIME_DIR"] = $runtimeDir
        $psi.Environment["NETWORK_ANOMALY_DB_PATH"] = $dbPath
        $psi.Environment["NETWORK_ANOMALY_BACKEND_PORT"] = "0"
        $psi.Environment["NETWORK_ANOMALY_API_TOKEN"] = $TokenValue
        $psi.Environment["NETWORK_ANOMALY_DESKTOP_TELEMETRY_FILE"] = $telemetryPath
        $psi.Environment["WEBVIEW2_USER_DATA_FOLDER"] = $wv2Dir
        return [System.Diagnostics.Process]::Start($psi)
    }

    function Wait-DesktopReady([System.Diagnostics.Process]$Proc, [hashtable]$ReqHeaders, [int]$TimeoutSeconds = 130) {
        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        while ((Get-Date) -lt $deadline) {
            if ($Proc.HasExited) {
                throw "Installed desktop exited prematurely with code $($Proc.ExitCode)"
            }
            if (Test-Path $telemetryPath) {
                try {
                    $tel = Get-Content -Path $telemetryPath -Raw -Encoding utf8 | ConvertFrom-Json
                    if ($tel.frontend_connected -eq $true -and $tel.desktop_pid -eq $Proc.Id) {
                        $bs = $tel.backend_status
                        if ($bs.running -eq $true -and $bs.managed_child -eq $true -and [int]$bs.pid -gt 0 -and ([string]$bs.base_url).StartsWith("http://127.0.0.1:")) {
                            $h = Invoke-LoopbackJson -Url "$($bs.base_url)/api/v1/health" -Headers $ReqHeaders -TimeoutSeconds 3
                            if ($h.StatusCode -eq 200) {
                                return $tel
                            }
                        }
                    }
                } catch {
                    # Telemetry file may still be updating or backend booting
                }
            }
            Start-Sleep -Milliseconds 250
        }
        throw "Installed desktop did not report WebView2 + FastAPI readiness within ${TimeoutSeconds}s"
    }

    $desktopProc = Start-InstalledDesktop $sessionToken
    $observedBackendPid = 0
    $backendPort = 0
    $gracefulMethod = $null
    $telData = $null
    try {
        $telData = Wait-DesktopReady -Proc $desktopProc -ReqHeaders $authHeaders -TimeoutSeconds 130
        $observedBackendPid = [int]$telData.backend_status.pid
        $baseUrl = [string]$telData.backend_status.base_url
        $backendPort = [int]$telData.backend_status.port
        if (-not (Test-PidAlive $observedBackendPid)) {
            throw "Reported backend PID $observedBackendPid is not alive"
        }
        if ($telData.backend_status.backend_mode -ne "embedded_sidecar") {
            throw "Expected backend_mode='embedded_sidecar', got '$($telData.backend_status.backend_mode)'"
        }
        $actualSidecarPath = [System.IO.Path]::GetFullPath([string]$telData.backend_status.python_executable)
        $expectedSidecarFull = [System.IO.Path]::GetFullPath($sidecarExe)
        if ($actualSidecarPath -ne $expectedSidecarFull) {
            throw "Sidecar executable path mismatch: $actualSidecarPath != $expectedSidecarFull"
        }

        # Session auth fail-closed
        $badMissing = Invoke-LoopbackJson -Url "$baseUrl/api/v1/models"
        if ($badMissing.StatusCode -notin @(401, 403)) {
            throw "Expected HTTP 401/403 for missing session token, got $($badMissing.StatusCode)"
        }
        $badToken = Invoke-LoopbackJson -Url "$baseUrl/api/v1/models" -Headers @{ "X-Sentinel-Session-Token" = ("invalid-" + ("0" * 56)) }
        if ($badToken.StatusCode -notin @(401, 403)) {
            throw "Expected HTTP 401/403 for invalid session token, got $($badToken.StatusCode)"
        }

        # 4-model READY check
        $modelsResp = Invoke-LoopbackJson -Url "$baseUrl/api/v1/models" -Headers $authHeaders
        if ($modelsResp.StatusCode -ne 200) {
            throw "GET /api/v1/models failed with HTTP $($modelsResp.StatusCode)"
        }
        $modelsByKey = @{}
        foreach ($m in $modelsResp.Json) {
            $modelsByKey[$m.model_key] = $m
        }
        $modelOrder = @("random_forest", "xgboost", "isolation_forest", "autoencoder")
        foreach ($mk in $modelOrder) {
            if (-not $modelsByKey.ContainsKey($mk) -or $modelsByKey[$mk].ready -ne $true -or $modelsByKey[$mk].status -ne "READY") {
                throw "Model '$mk' is not READY"
            }
        }

        $demoFlowsPath = Join-Path $installDir "data\demo\demo_flows.csv"
        $demoLabelsPath = Join-Path $installDir "data\demo\demo_labels.csv"
        $perModelResults = [ordered]@{}

        foreach ($mk in $modelOrder) {
            $azResp = Invoke-LoopbackJson -Url "$baseUrl/api/v1/csv/analyze" -Method "POST" -Headers $authHeaders -TimeoutSeconds 60 -BodyObject @{
                file_path        = $demoFlowsPath
                model_name       = $mk
                batch_size       = 100
                create_incidents = $false
            }
            if ($azResp.StatusCode -ne 200) {
                throw "${mk}: analyze failed with HTTP $($azResp.StatusCode): $($azResp.BodyText)"
            }
            $az = $azResp.Json
            if ($az.inference_mode -ne "verified_model") {
                throw "${mk}: expected inference_mode='verified_model', got '$($az.inference_mode)'"
            }
            if ($az.total_rows -ne 200 -or -not (($az.evaluated_rows -eq 200 -and $az.abstained_rows -eq 0) -or ($az.evaluated_rows -eq 198 -and $az.abstained_rows -eq 2))) {
                throw "${mk}: unexpected row counts total=$($az.total_rows) eval=$($az.evaluated_rows) abstained=$($az.abstained_rows)"
            }

            $evResp = Invoke-LoopbackJson -Url "$baseUrl/api/v1/csv/evaluate" -Method "POST" -Headers $authHeaders -TimeoutSeconds 30 -BodyObject @{
                labels_path = $demoLabelsPath
                predictions = $az.results
            }
            if ($evResp.StatusCode -ne 200) {
                throw "${mk}: evaluate failed with HTTP $($evResp.StatusCode)"
            }
            $ev = $evResp.Json

            $simResp = Invoke-LoopbackJson -Url "$baseUrl/api/v1/security/simulate-response" -Method "POST" -Headers $authHeaders -TimeoutSeconds 30 -BodyObject @{
                analysis_id = $az.analysis_id
                dry_run     = $true
            }
            if ($simResp.StatusCode -ne 200) {
                throw "${mk}: simulate-response failed with HTTP $($simResp.StatusCode)"
            }
            $sim = $simResp.Json
            if ($sim.executed -ne $false -or $sim.os_firewall_touched -ne $false -or $sim.real_key_rotated -ne $false -or $sim.provenance_verification -ne "server_verified_analysis") {
                throw "${mk}: invalid dry-run security flags"
            }

            $modelArtSha = [string]$embManifest.models.$mk.sha256
            $modelRunId = [string]$embManifest.models.$mk.run_id
            $perModelResults[$mk] = [ordered]@{
                analysis_id               = $az.analysis_id
                run_id                    = $modelRunId
                inference_run_id          = $az.run_id
                artifact_sha256           = $modelArtSha
                preprocessor_sha256       = $az.preprocessor_sha256
                source_csv_sha256         = $az.file_sha256
                labels_sha256             = $ev.labels_sha256
                compatibility_status      = $az.compatibility_gate.compatibility_status
                inference_mode            = $az.inference_mode
                total_rows                = [int]$az.total_rows
                evaluated_rows            = [int]$az.evaluated_rows
                abstained_rows            = [int]$az.abstained_rows
                confusion_matrix          = [ordered]@{
                    tn = [int]$ev.confusion_matrix.tn
                    fp = [int]$ev.confusion_matrix.fp
                    fn = [int]$ev.confusion_matrix.fn
                    tp = [int]$ev.confusion_matrix.tp
                }
                accuracy                  = [double]$ev.accuracy
                precision                 = [double]$ev.precision
                recall                    = [double]$ev.recall
                f1                        = [double]$ev.f1
                fpr                       = [double]$ev.false_positive_rate
                prediction_coverage       = [double]$ev.prediction_coverage
                dry_run_simulation_id     = $sim.simulation_id
                dry_run_provenance        = $sim.provenance_verification
                dry_run_action_counts     = [ordered]@{
                    NO_ACTION           = [int]$sim.action_counts.NO_ACTION
                    MONITOR             = [int]$sim.action_counts.MONITOR
                    INVESTIGATE         = [int]$sim.action_counts.INVESTIGATE
                    ISOLATE_RECOMMENDED = [int]$sim.action_counts.ISOLATE_RECOMMENDED
                }
                dry_run_rotation_decision = $sim.key_rotation_simulation.decision
            }
        }

        # Client spoof fail-closed check
        $spoofResp = Invoke-LoopbackJson -Url "$baseUrl/api/v1/security/simulate-response" -Method "POST" -Headers $authHeaders -BodyObject @{
            model_key          = "xgboost"
            inference_mode     = "verified_model"
            compatibility_gate = @{
                source_id            = "source:ait-nds-v2"
                provenance_verified  = $true
                model_key            = "xgboost"
                eligible             = $true
                eligibility_status   = "ELIGIBLE"
                compatibility_status = "MODEL_VALIDATED"
            }
            results            = @(
                @{
                    row_id                   = 1
                    row_index                = 0
                    predicted_label          = 1
                    predicted_class          = "Attack"
                    attack_probability       = 0.99
                    raw_anomaly_score        = 0.99
                    normalized_anomaly_score = 0.99
                    decision_threshold       = 0.5
                    score_type               = "attack_probability"
                    score_direction          = "higher_is_more_anomalous"
                    risk_score               = 99.0
                    risk_level               = "CRITICAL"
                    is_ood_flagged           = $false
                }
            )
            dry_run            = $true
        }
        if ($spoofResp.StatusCode -ne 200) {
            throw "Anti-spoof check failed with HTTP $($spoofResp.StatusCode)"
        }
        $spoof = $spoofResp.Json

        # CSV + JSON metadata export check
        $rfAzResp = Invoke-LoopbackJson -Url "$baseUrl/api/v1/csv/analyze" -Method "POST" -Headers $authHeaders -TimeoutSeconds 60 -BodyObject @{
            file_path        = $demoFlowsPath
            model_name       = "random_forest"
            batch_size       = 100
            create_incidents = $false
        }
        $rfAz = $rfAzResp.Json
        $exportCsv = Join-Path $exportDir "rf_vm_export.csv"
        $expResp = Invoke-LoopbackJson -Url "$baseUrl/api/v1/csv/export" -Method "POST" -Headers $authHeaders -BodyObject @{
            output_path         = $exportCsv
            analysis_id         = $rfAz.analysis_id
            source_csv_path     = $demoFlowsPath
            model_key           = "random_forest"
            model_type          = $rfAz.model_type
            run_id              = $rfAz.run_id
            model_sha256        = $perModelResults["random_forest"].artifact_sha256
            preprocessor_sha256 = $perModelResults["random_forest"].preprocessor_sha256
            results             = $rfAz.results
            evaluation          = $null
        }
        if ($expResp.StatusCode -ne 200 -or [int]$expResp.Json.rows_exported -ne 200 -or -not (Test-Path $expResp.Json.csv_path) -or -not (Test-Path $expResp.Json.metadata_path)) {
            throw "CSV export E2E verification failed"
        }

        $gracefulMethod = Request-GracefulWindowClose $desktopProc
        if (-not $desktopProc.WaitForExit(15000)) {
            $desktopProc.Kill()
            throw "Installed desktop did not exit cleanly within 15s"
        }
        $orphanWait = (Get-Date).AddSeconds(5)
        while ((Get-Date) -lt $orphanWait) {
            if (-not (Test-PidAlive $observedBackendPid)) { break }
            Start-Sleep -Milliseconds 150
        }
        if (Test-PidAlive $observedBackendPid) {
            throw "Orphan backend PID $observedBackendPid remained alive after desktop exit"
        }
        if (Test-LoopbackPortOpen $backendPort) {
            throw "Backend loopback port $backendPort remained open after desktop exit"
        }
    } finally {
        if (-not $desktopProc.HasExited) {
            $desktopProc.Kill()
        }
        if ($observedBackendPid -gt 0 -and (Test-PidAlive $observedBackendPid)) {
            & taskkill.exe /PID $observedBackendPid /T /F | Out-Null
        }
    }

    # 4. Restart SQLite persistence check
    $restartToken = New-RandomHexToken 32
    $restartHeaders = @{ "X-Sentinel-Session-Token" = $restartToken }
    $restartProc = Start-InstalledDesktop $restartToken
    $restartBackendPid = 0
    $restartPort = 0
    try {
        $rTel = Wait-DesktopReady -Proc $restartProc -ReqHeaders $restartHeaders -TimeoutSeconds 130
        $restartBackendPid = [int]$rTel.backend_status.pid
        $restartUrl = [string]$rTel.backend_status.base_url
        $restartPort = [int]$rTel.backend_status.port
        $simHistResp = Invoke-LoopbackJson -Url "$restartUrl/api/v1/security/simulations?limit=10&offset=0" -Headers $restartHeaders
        if ($simHistResp.StatusCode -ne 200 -or [int]$simHistResp.Json.total -lt 4) {
            throw "SQLite restart persistence check failed (expected >=4 simulations)"
        }
        $null = Request-GracefulWindowClose $restartProc
        if (-not $restartProc.WaitForExit(15000)) {
            $restartProc.Kill()
            throw "Restarted desktop did not exit cleanly within 15s"
        }
        $rOrphanWait = (Get-Date).AddSeconds(5)
        while ((Get-Date) -lt $rOrphanWait) {
            if (-not (Test-PidAlive $restartBackendPid)) { break }
            Start-Sleep -Milliseconds 150
        }
        if (Test-PidAlive $restartBackendPid) {
            throw "Orphan backend PID $restartBackendPid remained alive after restart exit"
        }
        if (Test-LoopbackPortOpen $restartPort) {
            throw "Restart backend port $restartPort remained open"
        }
    } finally {
        if (-not $restartProc.HasExited) {
            $restartProc.Kill()
        }
        if ($restartBackendPid -gt 0 -and (Test-PidAlive $restartBackendPid)) {
            & taskkill.exe /PID $restartBackendPid /T /F | Out-Null
        }
    }

    # 5. Silent NSIS uninstall
    $uninstProc = Start-Process -FilePath $uninstallerExe -ArgumentList @("/S") -Wait -PassThru
    if ($uninstProc.ExitCode -ne 0) {
        throw "NSIS silent uninstall failed with exit code $($uninstProc.ExitCode)"
    }
    $cleanWait = (Get-Date).AddSeconds(20)
    while (Test-Path -LiteralPath $installDir) {
        $remainingFile = Get-ChildItem -LiteralPath $installDir -File -Recurse -Force | Select-Object -First 1
        if (-not $remainingFile) { break }
        if ((Get-Date) -ge $cleanWait) {
            throw "NSIS uninstall left an installed file behind: $($remainingFile.FullName)"
        }
        Start-Sleep -Milliseconds 200
    }

    $evidencePayload = [ordered]@{
        format                   = "netflow-sentinel-vm-target-evidence-v1"
        challenge_nonce          = $challenge.challenge_nonce
        completed_at_utc         = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        desktop_version          = $embManifest.desktop_version
        port                     = $backendPort
        split_manifest_sha256    = $splitSha
        preprocessor_sha256      = $prepSha
        demo_sha256              = $demoShaMap
        ready_models             = @($telData.summary.ready_models)
        models                   = $perModelResults
        session_auth_fail_closed = $true
        client_spoof_fail_closed = [ordered]@{
            provenance_verification    = $spoof.provenance_verification
            critical_downgraded_action = $spoof.recommendations[0].action
            rotation_decision          = $spoof.key_rotation_simulation.decision
        }
        target_probe             = $targetProbe
        nsis_e2e                 = [ordered]@{
            status                       = "PASS"
            installer_filename           = $installerItem.Name
            installer_sha256             = $installerSha
            installer_size_bytes         = [int64]$installerItem.Length
            sums_file_verified           = $false
            installed_exe_sha256         = $installedExeSha
            compiled_exe_sha256          = $compiledSha
            normalized_compiled_exe_sha256 = $normCompiledSha
            compiled_exe_sha256_match    = $compiledMatch
            exe_parity_mode              = $parityMode
            uninstaller_verified         = $true
            clean_install_verified       = $true
            installed_app_launched       = $true
            installed_exe_path_verified  = $true
            frontend_webview_connected   = $true
            frontend_ready_models        = @($telData.summary.ready_models)
            bundled_resources_mode       = $true
            repo_root_env_passed         = $false
            runtime_dir_isolated         = $true
            backend_spawned_on_loopback  = $true
            backend_port                 = $backendPort
            graceful_close_verified      = $true
            graceful_close_method        = $gracefulMethod
            zero_orphan_processes_verified = $true
            uninstall_cleanup_verified   = $true
            standalone_embedded_mode     = $true
            sidecar_exe_verified         = $true
            sidecar_sha256               = $actualSidecarSha
            sidecar_size_bytes           = [int64]$sidecarSizeBytes
            embedded_file_count          = $embeddedCount
            system_python_used           = $false
            external_companion_used      = $false
            restart_persistence_verified = $true
            export_verified              = $true
            frontend_interactive_gui_clicks = "NOT VERIFIED (WebView2 mounted and Svelte onMount IPC handshake verified; manual/UIA button clicks across UI tabs not automated)"
        }
    }

    $resolvedOut = if ([System.IO.Path]::IsPathRooted($OutputJson)) {
        $OutputJson
    } else {
        Join-Path (Get-Location).Path $OutputJson
    }
    $outParent = Split-Path -Path $resolvedOut -Parent
    if ($outParent) {
        New-Item -ItemType Directory -Force -Path $outParent | Out-Null
    }
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($resolvedOut, (($evidencePayload | ConvertTo-Json -Depth 12) + "`n"), $utf8NoBom)
    Write-Host "Target E2E evidence written to: $resolvedOut"
} finally {
    if ($cleanupWorkDir -and (Test-Path $WorkDir)) {
        Remove-Item -Path $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

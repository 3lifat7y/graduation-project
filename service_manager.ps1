<#
.SYNOPSIS
    DDoS-Guard: Windows Service & Driver Management Script
.DESCRIPTION
    Safely installs, configures, queries, starts, stops, and removes the
    DDoS-Guard Network Sniffer Windows Service.
    Enforces UAC elevation check and respects Windows Security policies.
    Engine operates strictly in monitor-only mode (WinDivert Flag.SNIFF).
.PARAMETER Action
    Install, Start, Stop, Restart, Status, Uninstall, TestIPC
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet("Install", "Start", "Stop", "Restart", "Status", "Uninstall", "TestIPC")]
    [string]$Action
)

$ServiceName = "DDoSGuardSnifferService"
$DisplayName = "DDoS-Guard Network Sniffer Service"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ServiceScript = Join-Path $ScriptDir "ddos_guard_service.py"

# Dynamically resolve Python executable with intelligent fallback
$CandidatePythons = @(
    (Join-Path $ScriptDir ".venv\Scripts\python.exe"),
    "C:\Users\alifa\AppData\Local\Python\pythoncore-3.15-64\python.exe",
    (Join-Path $env:LOCALAPPDATA "Programs\Python\Python311\python.exe"),
    (Join-Path $env:LOCALAPPDATA "Programs\Python\Python312\python.exe"),
    (Get-Command python -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -ErrorAction SilentlyContinue)
)

$PythonExe = $null
foreach ($cand in $CandidatePythons) {
    if ($cand -and (Test-Path -LiteralPath $cand)) {
        # Verify scapy can be imported with this python
        $testPy = & $cand -c "import scapy; print('ok')" 2>$null
        if ($testPy -match "ok") {
            $PythonExe = $cand
            break
        }
    }
}

if (-not $PythonExe) {
    # Fallback to first existing python executable
    foreach ($cand in $CandidatePythons) {
        if ($cand -and (Test-Path -LiteralPath $cand)) {
            $PythonExe = $cand
            break
        }
    }
}

function Check-Administrator {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Show-UACWarning {
    Write-Warning "This operation requires Windows Administrator privileges."
    Write-Warning "Please right-click PowerShell, select 'Run as administrator', and retry:"
    Write-Warning "  powershell -ExecutionPolicy Bypass -File .\service_manager.ps1 $Action"
}

switch ($Action) {
    "Install" {
        if (-not (Check-Administrator)) {
            Show-UACWarning
            exit 1
        }

        Write-Host "=== Registering DDoS-Guard Windows Service ===" -ForegroundColor Cyan
        Write-Host "  • Service Name       : $ServiceName"
        Write-Host "  • Display Name       : $DisplayName"
        Write-Host "  • Python Executable  : $PythonExe"
        Write-Host "  • Service Script     : $ServiceScript"

        # Validate file paths exist
        if (-not $PythonExe -or -not (Test-Path -LiteralPath $PythonExe)) {
            Write-Error "Python executable could not be resolved. Please verify Python installation."
            exit 1
        }
        if (-not (Test-Path -LiteralPath $ServiceScript)) {
            Write-Error "Service script does not exist at '$ServiceScript'. Please verify project files."
            exit 1
        }

        # Check if already installed
        $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($existing) {
            Write-Host "Service '$ServiceName' is already installed. Current status: $($existing.Status)" -ForegroundColor Yellow
            Write-Host "To reinstall, first run: .\service_manager.ps1 Uninstall" -ForegroundColor Gray
            exit 0
        }

        # Safe dependency resolution: Stage python311.dll, pywintypes311.dll, and servicemanager.pyd
        Write-Host "`nVerifying and staging Python runtime dependencies for SCM..." -ForegroundColor Cyan
        $stagePy = @"
import sys, pathlib, shutil
try:
    bp = pathlib.Path(sys.base_prefix)
    venv_dir = pathlib.Path(sys.prefix)
    dll_name = f'python{sys.version_info.major}{sys.version_info.minor}.dll'
    base_py_dll = bp / dll_name
    if base_py_dll.exists():
        shutil.copy2(base_py_dll, venv_dir / dll_name)
        print(f'  ✓ Staged {dll_name} into {venv_dir}')
    
    # Locate pywintypes DLL
    import win32api
    h = win32api.GetModuleHandle(f'pywintypes{sys.version_info.major}{sys.version_info.minor}.dll')
    if h:
        pywin_path = pathlib.Path(win32api.GetModuleFileName(h))
        if pywin_path.exists():
            shutil.copy2(pywin_path, venv_dir / pywin_path.name)
            print(f'  ✓ Staged {pywin_path.name} into {venv_dir}')

    # Locate and stage servicemanager.pyd next to pythonservice.exe
    import servicemanager
    sm_path = pathlib.Path(servicemanager.__file__)
    if sm_path.exists():
        shutil.copy2(sm_path, venv_dir / sm_path.name)
        print(f'  ✓ Staged {sm_path.name} into {venv_dir}')

    print('  ✓ Runtime dependencies verified.')
except Exception as e:
    print(f'  ! Warning during DLL staging: {e}')
"@
        & $PythonExe -c "$stagePy"

        # Primary Registration: Use native pywin32 HandleCommandLine
        Write-Host "`nRegistering service via pywin32 service framework..." -ForegroundColor Cyan
        $pyOutput = & $PythonExe $ServiceScript --startup auto install 2>&1
        $pyExit = $LASTEXITCODE

        if ($pyExit -eq 0 -or (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
            Write-Host "✅ Service registered successfully via pywin32!" -ForegroundColor Green
            # Update description
            $descText = "DDoS-Guard kernel packet capture engine running Scapy + Npcap in monitor-only mode."
            $null = & sc.exe description $ServiceName $descText 2>&1

            # Configure SCM Environment block (PYTHONPATH and PYTHONHOME) for LocalSystem host
            $pyHome = (& $PythonExe -c "import sys; print(sys.base_prefix)").Trim()
            $venvDir = (& $PythonExe -c "import sys; print(sys.prefix)").Trim()
            $pyPath = "$venvDir\Lib\site-packages;$venvDir\Lib\site-packages\win32;$venvDir\Lib\site-packages\win32\lib;$ScriptDir"
            $envStrings = @(
                "PYTHONPATH=$pyPath",
                "PYTHONHOME=$pyHome",
                "VIRTUAL_ENV=$venvDir",
                "PATH=$venvDir\Scripts;$venvDir\Lib\site-packages\win32;$pyHome;$pyHome\Scripts;$env:PATH"
            )
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -Name "Environment" -Value $envStrings -Type MultiString
            Write-Host "  + Configured SCM service Environment (PYTHONPATH and PYTHONHOME)." -ForegroundColor Green
            Write-Host "✅ Successfully registered $ServiceName!" -ForegroundColor Green
            Write-Host "To start the service now, run: .\service_manager.ps1 Start" -ForegroundColor Gray
        } else {
            Write-Error "pywin32 registration failed: $pyOutput"
            exit 1
        }
    }

    "Start" {
        if (-not (Check-Administrator)) {
            Show-UACWarning
            exit 1
        }

        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if (-not $svc) {
            Write-Error "Service '$ServiceName' is NOT installed. Run '.\service_manager.ps1 Install' first."
            exit 1
        }

        if ($svc.Status -eq 'Running') {
            Write-Host "✅ Service '$ServiceName' is ALREADY running." -ForegroundColor Green
            exit 0
        }

        # Ensure SCM Environment is verified and configured before starting
        $svcKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
        $existingEnv = (Get-ItemProperty -Path $svcKey -ErrorAction SilentlyContinue).Environment
        $pyHome = (& $PythonExe -c "import sys; print(sys.base_prefix)").Trim()
        $venvDir = (& $PythonExe -c "import sys; print(sys.prefix)").Trim()
        $pyPath = "$venvDir\Lib\site-packages;$venvDir\Lib\site-packages\win32;$venvDir\Lib\site-packages\win32\lib;$ScriptDir"
        if (-not $existingEnv -or (($existingEnv -join "`n") -notmatch [regex]::Escape($pyPath))) {
            $envStrings = @(
                "PYTHONPATH=$pyPath",
                "PYTHONHOME=$pyHome",
                "VIRTUAL_ENV=$venvDir",
                "PATH=$venvDir\Scripts;$venvDir\Lib\site-packages\win32;$pyHome;$pyHome\Scripts;$env:PATH"
            )
            Set-ItemProperty -Path $svcKey -Name "Environment" -Value $envStrings -Type MultiString
            Write-Host "  + Updated SCM Environment registry settings for $ServiceName." -ForegroundColor Gray
        }

        Write-Host "Starting $ServiceName..." -ForegroundColor Cyan
        try {
            Start-Service -Name $ServiceName -ErrorAction Stop
            # Wait up to 5 seconds for service to enter Running state
            $started = $false
            for ($i = 0; $i -lt 10; $i++) {
                Start-Sleep -Milliseconds 500
                $svc = Get-Service -Name $ServiceName
                if ($svc.Status -eq 'Running') {
                    $started = $true
                    break
                }
            }

            if ($started) {
                Write-Host "✅ Service '$ServiceName' started successfully (State: Running)." -ForegroundColor Green
            } else {
                Write-Warning "Service status is: $($svc.Status)"
            }
        } catch {
            Write-Error "Failed to start service '$ServiceName': $($_.Exception.Message)"
            
            # Diagnostic inspection: check service log file
            $logPath = Join-Path $ScriptDir "ddos_guard_service.log"
            if (Test-Path -LiteralPath $logPath) {
                Write-Host "`n--- Recent Service Log Output ($logPath) ---" -ForegroundColor Yellow
                Get-Content $logPath -Tail 15 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
            }

            # Check Event Viewer for Python Service events
            $ev = Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='Python Service'} -MaxEvents 3 -ErrorAction SilentlyContinue
            if ($ev) {
                Write-Host "`n--- Recent Windows Event Log Entries (Python Service) ---" -ForegroundColor Red
                foreach ($e in $ev) {
                    Write-Host "  Event ID $($e.Id) ($($e.TimeCreated)): $($e.Properties.Value)" -ForegroundColor Yellow
                }
            }
            exit 1
        }
    }

    "Stop" {
        if (-not (Check-Administrator)) {
            Show-UACWarning
            exit 1
        }

        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if (-not $svc) {
            Write-Warning "Service '$ServiceName' is not installed."
            exit 0
        }

        if ($svc.Status -eq 'Stopped') {
            Write-Host "Service '$ServiceName' is already stopped." -ForegroundColor Yellow
            exit 0
        }

        Write-Host "Stopping $ServiceName..." -ForegroundColor Yellow
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        $svc = Get-Service -Name $ServiceName
        Write-Host "✅ Service status: $($svc.Status)" -ForegroundColor Green
    }

    "Restart" {
        if (-not (Check-Administrator)) {
            Show-UACWarning
            exit 1
        }
        Write-Host "Restarting $ServiceName..." -ForegroundColor Cyan
        Restart-Service -Name $ServiceName -Force
        Start-Sleep -Seconds 1
        $svc = Get-Service -Name $ServiceName
        Write-Host "✅ Service status: $($svc.Status)" -ForegroundColor Green
    }

    "Status" {
        Write-Host "=== DDoS-Guard Service Status ===" -ForegroundColor Cyan
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($svc) {
            Write-Host "  • Service Name    : $($svc.Name)"
            Write-Host "  • Display Name    : $($svc.DisplayName)"
            Write-Host "  • State           : $($svc.Status)"
            Write-Host "  • Startup Type    : $($svc.StartType)"
        } else {
            Write-Host "  • Service '$ServiceName' is NOT installed in Service Control Manager." -ForegroundColor Yellow
        }

        # Check service log
        $logPath = Join-Path $ScriptDir "ddos_guard_service.log"
        if (Test-Path -LiteralPath $logPath) {
            Write-Host "`n=== Recent Service Log Entries ===" -ForegroundColor Cyan
            Get-Content $logPath -Tail 5 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
        }

        Write-Host "`n=== Testing IPC Probe on 127.0.0.1:50505 ===" -ForegroundColor Cyan
        if ($PythonExe) {
            & $PythonExe -c "import sys; sys.path.insert(0, '$ScriptDir'); from ipc_client import DDoSGuardIPCClient; c = DDoSGuardIPCClient(); print('  • IPC Ping:', c.ping())"
        } else {
            Write-Warning "Python executable not available to run IPC test."
        }
    }

    "TestIPC" {
        Write-Host "Probing IPC server on 127.0.0.1:50505..." -ForegroundColor Cyan
        if ($PythonExe) {
            & $PythonExe -c "import sys; sys.path.insert(0, '$ScriptDir'); from ipc_client import DDoSGuardIPCClient; c = DDoSGuardIPCClient(); print(c.ping())"
        }
    }

    "Uninstall" {
        if (-not (Check-Administrator)) {
            Show-UACWarning
            exit 1
        }
        Write-Host "Uninstalling $ServiceName..." -ForegroundColor Yellow
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue

        # Try pywin32 remove first
        $remOut = & $PythonExe $ServiceScript remove 2>&1
        $svcCheck = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($svcCheck) {
            $delOutput = & sc.exe delete $ServiceName 2>&1
        }
        Write-Host "✅ Service $ServiceName has been uninstalled." -ForegroundColor Green
    }
}

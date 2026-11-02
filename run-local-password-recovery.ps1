param(
    [string]$GmailSender
)

$ErrorActionPreference = 'Stop'

$serviceRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent (Split-Path -Parent $serviceRoot)
$springRoot = Join-Path $projectRoot 'ms_security-main'

if ([string]::IsNullOrWhiteSpace($GmailSender)) {
    $GmailSender = $env:GMAIL_SENDER
}
if ([string]::IsNullOrWhiteSpace($GmailSender)) {
    $GmailSender = Read-Host 'Authorized Gmail sender address'
}
if ($GmailSender -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
    throw 'GmailSender must be a valid email address.'
}
if (-not (Test-Path -LiteralPath (Join-Path $springRoot 'mvnw.cmd'))) {
    throw 'The sibling Spring Boot project or its Maven wrapper was not found.'
}
if (-not (Test-Path -LiteralPath (Join-Path $serviceRoot 'credentials\credentials.json')) -and
    -not (Test-Path -LiteralPath (Join-Path $serviceRoot 'credentials\token.pickle'))) {
    throw 'Gmail OAuth is not configured. Provide credentials\credentials.json and authorize the Gmail send scope.'
}

$pythonCandidates = @(
    (Join-Path $serviceRoot '.venv\Scripts\python.exe'),
    (Join-Path (Split-Path -Parent $serviceRoot) 'emails_google\.venv\Scripts\python.exe')
)
$pythonExe = $pythonCandidates |
    Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
    Select-Object -First 1
if (-not $pythonExe) {
    $pythonCommand = Get-Command python.exe -ErrorAction SilentlyContinue
    if (-not $pythonCommand) {
        throw 'Python was not found. Install Python and the FastAPI requirements first.'
    }
    $pythonExe = $pythonCommand.Source
}

& $pythonExe -c 'import fastapi, googleapiclient, google_auth_oauthlib, uvicorn' *> $null
if ($LASTEXITCODE -ne 0) {
    throw 'The selected Python environment is missing FastAPI or Gmail API dependencies. Install requirements.txt in that environment.'
}

$portsInUse = @(
    foreach ($port in @(8000, 8181)) {
        Get-NetTCPConnection `
            -LocalPort $port `
            -State Listen `
            -ErrorAction SilentlyContinue
    }
)
if ($portsInUse.Count -gt 0) {
    throw 'Ports 8000 or 8181 are already in use. Stop the existing services first.'
}

$previousServiceToken = [Environment]::GetEnvironmentVariable(
    'SERVICE_TOKEN',
    'Process'
)
$previousNotificationToken = [Environment]::GetEnvironmentVariable(
    'NOTIFICATION_SERVICE_TOKEN',
    'Process'
)
$previousSender = [Environment]::GetEnvironmentVariable(
    'GMAIL_SENDER',
    'Process'
)
$fastApiProcess = $null
try {
    # Both services read the same ignored file; don't let stale environment
    # variables override it in the locally launched processes.
    [Environment]::SetEnvironmentVariable('SERVICE_TOKEN', $null, 'Process')
    [Environment]::SetEnvironmentVariable(
        'NOTIFICATION_SERVICE_TOKEN',
        $null,
        'Process'
    )
    $env:GMAIL_SENDER = $GmailSender

    Write-Host 'Starting FastAPI; its startup creates the shared token if needed.'
    $fastApiProcess = Start-Process -FilePath $pythonExe `
        -WorkingDirectory $serviceRoot `
        -ArgumentList @(
            '-m',
            'uvicorn',
            'main:app',
            '--host',
            '127.0.0.1',
            '--port',
            '8000'
        ) `
        -PassThru

    $fastApiReady = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        if ($fastApiProcess.HasExited) {
            throw 'FastAPI stopped before its health endpoint became available.'
        }
        try {
            $null = Invoke-RestMethod `
                -Uri 'http://127.0.0.1:8000/health' `
                -TimeoutSec 2
            $fastApiReady = $true
            break
        } catch {
            Start-Sleep -Seconds 1
        }
    }
    if (-not $fastApiReady) {
        Stop-Process -Id $fastApiProcess.Id
        throw 'FastAPI did not become ready on port 8000.'
    }

    Write-Host 'FastAPI is ready. Starting Spring Boot.'
    Start-Process -FilePath 'powershell.exe' `
        -WorkingDirectory $springRoot `
        -ArgumentList @(
            '-NoExit',
            '-ExecutionPolicy',
            'Bypass',
            '-Command',
            '& .\mvnw.cmd spring-boot:run'
        )
    Write-Host 'Both services use the same local token file; its contents are not displayed.'
} finally {
    [Environment]::SetEnvironmentVariable(
        'SERVICE_TOKEN',
        $previousServiceToken,
        'Process'
    )
    [Environment]::SetEnvironmentVariable(
        'NOTIFICATION_SERVICE_TOKEN',
        $previousNotificationToken,
        'Process'
    )
    [Environment]::SetEnvironmentVariable(
        'GMAIL_SENDER',
        $previousSender,
        'Process'
    )
}
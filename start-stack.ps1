Set-StrictMode -Version Latest
$cwd = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $cwd
try {
    Write-Host 'Starting Docker Desktop...'
    Start-Process -FilePath 'C:\Program Files\Docker\Docker\Docker Desktop.exe' -ErrorAction SilentlyContinue

    $timeout = 120
    $elapsed = 0
    $dockerReady = $false
    while ($elapsed -lt $timeout) {
        $result = & docker version --format '{{.Server.Version}}' 2>$null
        if ($LASTEXITCODE -eq 0) {
            $dockerReady = $true
            break
        }
        Write-Host "Waiting for Docker daemon... ($elapsed/$timeout)"
        Start-Sleep -Seconds 5
        $elapsed += 5
    }

    if (-not $dockerReady) {
        throw 'Docker did not become available within 120 seconds. Please open Docker Desktop and ensure the daemon is running.'
    }

    Write-Host 'Docker is available. Starting the compose stack...'
    docker compose up -d
    Write-Host 'Docker stack started successfully.'
} finally {
    Pop-Location
}

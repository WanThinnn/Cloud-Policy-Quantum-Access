$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path -LiteralPath "$PSScriptRoot\..").Path
$OutputDirectory = Join-Path $ProjectRoot "build\crypto"
docker build --platform linux/amd64 --target crypto-artifacts `
    -f "$ProjectRoot\docker\Dockerfile" `
    --output "type=local,dest=$OutputDirectory" $ProjectRoot
if ($LASTEXITCODE -ne 0) { throw "Crypto build failed (exit $LASTEXITCODE)" }
Write-Host "Crypto artifacts: $OutputDirectory (lib/, plugin/, source.env)"

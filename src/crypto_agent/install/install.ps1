$ErrorActionPreference = 'Stop'
$hostName = 'com.cpqa.crypto_agent'
$root = Join-Path $env:LOCALAPPDATA 'CPQA\Crypto Agent'
$destination = Join-Path $root ([guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $destination -Force | Out-Null
Copy-Item -Path (Join-Path $PSScriptRoot 'runtime\*') -Destination $destination -Recurse
$manifest = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'native-host.json') | ConvertFrom-Json
$manifest.path = Join-Path $destination 'cpqa-crypto-agent.exe'
$manifestPath = Join-Path $destination 'native-host.json'
[IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 4))
foreach ($vendor in 'Google\Chrome', 'Microsoft\Edge') {
    $key = "HKCU:\Software\$vendor\NativeMessagingHosts\$hostName"
    New-Item -Path $key -Force | Out-Null
    Set-Item -Path $key -Value $manifestPath
}
Write-Host 'Crypto Agent installed. Return to CPQA and check again.'

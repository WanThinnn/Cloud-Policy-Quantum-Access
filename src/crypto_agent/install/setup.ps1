$ErrorActionPreference = 'Stop'
$hostName = 'com.cpqa.crypto_agent'
$root = Join-Path $env:LOCALAPPDATA 'CPQA\Crypto Agent'
$extension = Join-Path $root 'extension'

foreach ($file in 'runtime\cpqa-crypto-agent.exe', 'native-host.json', 'extension\manifest.json',
                  'extension\background.js', 'extension\deployment.js') {
    if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot $file) -PathType Leaf)) {
        throw 'Extract the entire Crypto Agent ZIP, then run setup again.'
    }
}
New-Item -ItemType Directory -Path $root -Force | Out-Null
$destination = Join-Path $root ([guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $destination | Out-Null
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'runtime') -Destination $destination -Recurse
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'extension') -Destination $destination -Recurse

# Keep the extension path stable for browser profiles that already loaded it.
$stagedExtension = Join-Path $destination 'extension'
$backup = Join-Path $destination 'previous-extension'
$previous = Get-Item -LiteralPath $extension -Force -ErrorAction SilentlyContinue
if ($previous) {
    if (-not $previous.PSIsContainer -or ($previous.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'The Crypto Agent extension path must be a local directory.'
    }
    Move-Item -LiteralPath $extension -Destination $backup
}
try {
    Move-Item -LiteralPath $stagedExtension -Destination $extension
} catch {
    if ($previous -and -not (Test-Path -LiteralPath $extension)) {
        Move-Item -LiteralPath $backup -Destination $extension
    }
    throw
}

$manifest = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'native-host.json') | ConvertFrom-Json
$manifest.path = Join-Path $destination 'runtime\cpqa-crypto-agent.exe'
$manifestPath = Join-Path $destination 'native-host.json'
[IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 4))
foreach ($vendor in 'Google\Chrome', 'Microsoft\Edge', 'BraveSoftware\Brave-Browser', 'Chromium') {
    $key = "HKCU:\Software\$vendor\NativeMessagingHosts\$hostName"
    New-Item -Path $key -Force | Out-Null
    Set-Item -LiteralPath $key -Value $manifestPath
}
Write-Host 'Crypto Agent installed for this Windows account.'
Write-Host 'Open the extensions page in your browser, enable Developer mode, and choose Load unpacked.'
Write-Host "Select this folder: $extension"
Write-Host 'Return to CPQA > Security Keys and choose Check Crypto Agent.'

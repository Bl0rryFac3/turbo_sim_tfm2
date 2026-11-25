#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $GameDirectory,

    [ValidateSet('x86_64-pc-windows-msvc', 'x86_64-pc-windows-gnu')]
    [string] $Target = 'x86_64-pc-windows-msvc'
)

$ErrorActionPreference = 'Stop'
$game = Get-Item -LiteralPath $GameDirectory
if ($game -isnot [IO.DirectoryInfo]) {
    throw 'Choose the game folder from Steam > Manage > Browse local files.'
}

$exe = Join-Path $game.FullName 'TeamfightManager2.exe'
$expected = 'c74955e11f4845f93dcb73f90c5cdd442615ac72f40ed642a1fdeb5f41def01e'
if ((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash -ine $expected) {
    throw 'This source targets the Windows 0.7.4 executable used to build Turbo Sim.'
}

$cargo = Get-Command cargo -CommandType Application -ErrorAction Stop | Select-Object -First 1
$gameSdk = Join-Path $game.FullName 'mod-sdk-stable/mod-api-stable'
$localSdk = Join-Path $PSScriptRoot 'mod-api-stable'
$sdkManifest = Join-Path $gameSdk 'Cargo.toml'
$sdkLibrary = Join-Path $gameSdk 'src/lib.rs'
if (!(Test-Path -LiteralPath $sdkManifest -PathType Leaf) -or
    !(Test-Path -LiteralPath $sdkLibrary -PathType Leaf)) {
    throw 'The stable SDK was not found. Check your Steam installation for mod-sdk-stable/mod-api-stable.'
}

if (!(Test-Path -LiteralPath $localSdk)) {
    $stagingSdk = Join-Path $PSScriptRoot ('.sdk-' + [Guid]::NewGuid().ToString('N'))
    try {
        Copy-Item -LiteralPath $gameSdk -Destination $stagingSdk -Recurse
        Move-Item -LiteralPath $stagingSdk -Destination $localSdk
    }
    finally {
        if (Test-Path -LiteralPath $stagingSdk) {
            Remove-Item -LiteralPath $stagingSdk -Recurse
        }
    }
}
$localSdkLibrary = Join-Path $localSdk 'src/lib.rs'
$sdkSource = Get-Content -LiteralPath $localSdkLibrary -Raw
if (($sdkSource -notmatch 'pub const ABI_LEVEL: u32\s*=\s*(\d+);') -or ([int]$Matches[1] -lt 10)) {
    throw 'The local mod-api-stable folder must contain Stable Mod SDK ABI 10 or later.'
}

$manifest = Join-Path $PSScriptRoot 'source/Cargo.toml'
$targetDirectory = Join-Path $PSScriptRoot 'source/target'
& $cargo.Source build --offline --locked --release --target $Target --manifest-path $manifest --target-dir $targetDirectory
if ($LASTEXITCODE -ne 0) {
    throw "Cargo build failed with exit code $LASTEXITCODE."
}
$dll = Join-Path $targetDirectory "$Target/release/turbo_sim.dll"
$builtMod = Join-Path $PSScriptRoot 'mod/Turbo_Sim'
Copy-Item -LiteralPath $dll -Destination (Join-Path $builtMod 'Turbo_Sim.dll') -Force
Write-Host "Built mod folder $builtMod"

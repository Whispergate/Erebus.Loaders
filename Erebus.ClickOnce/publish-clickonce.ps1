# Publishes Erebus.ClickOnce as a ClickOnce app and generates the .application manifest
param(
    [string]$Configuration = "Release"
)

$ErrorActionPreference = 'Stop'

function Get-MSBuildPath {
    $candidates = @(
        "$Env:ProgramFiles(x86)\Microsoft Visual Studio\2026\BuildTools\MSBuild\Current\Bin\MSBuild.exe",
        "F:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe",
        "$Env:ProgramFiles(x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe",
        "$Env:ProgramFiles\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe",
        "$Env:ProgramFiles(x86)\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe",
        "$Env:ProgramFiles\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe",
        "$Env:ProgramFiles(x86)\Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin\MSBuild.exe",
        "$Env:ProgramFiles(x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe"
    )
    foreach ($p in $candidates) {
        if (Test-Path $p) { return $p }
    }
    return $null
}

$msbuild = Get-MSBuildPath
if (-not $msbuild) {
    Write-Error "MSBuild.exe (full .NET Framework) not found. Install 'Visual Studio Build Tools 2022' with MSBuild and .NET desktop build tools. https://aka.ms/vsbuildtools"
}

$proj = Join-Path $PSScriptRoot 'Erebus.ClickOnce.csproj'
$pubProfile = 'Properties\\PublishProfiles\\ClickOnce.pubxml'

$msbuildArgs = @(
    $proj,
    '/nologo',
    '/m',
    '/t:Restore,Publish',
    "/p:PublishProfile=$pubProfile",
    "/p:Configuration=$Configuration",
    '/p:TargetFramework=net8.0-windows',
    '/v:m'
)

& $msbuild @msbuildArgs

$publishDir = Join-Path $PSScriptRoot 'bin\\ClickOnce'
if (Test-Path $publishDir) {
    Write-Host "Publish complete → $publishDir"
    Get-ChildItem $publishDir -Recurse -Filter '*.application' | ForEach-Object { Write-Host "Created: " $_.FullName }
} else {
    Write-Warning "Publish directory not found: $publishDir"
}

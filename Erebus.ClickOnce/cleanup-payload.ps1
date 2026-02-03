# Cleanup script to minimize ClickOnce payload per SpecterOps methodology
# Removes unnecessary files, keeping only the loader executable

param(
    [string]$PublishDir = "bin\Release\net7.0-windows\win-x64\publish"
)

$ErrorActionPreference = 'Stop'

$publishPath = Join-Path $PSScriptRoot $PublishDir

if (-not (Test-Path $publishPath)) {
    Write-Error "Publish directory not found: $publishPath"
}

Write-Host "[*] Cleaning payload directory: $publishPath" -ForegroundColor Cyan

# Files to keep (the main executable only)
$keepPatterns = @(
    '*.exe'
)

# Files to remove
$removeExtensions = @('.pdb', '.deps.json', '.runtimeconfig.json', '.xml', '.dll', '.json')

Write-Host "`n[*] Cleaning publish directory..." -ForegroundColor Yellow
Get-ChildItem $publishPath -File | ForEach-Object {
    $keep = $false
    
    # Check if it's the main exe
    foreach ($pattern in $keepPatterns) {
        if ($_.Name -like $pattern -and $_.Extension -eq '.exe') {
            $keep = $true
            break
        }
    }
    
    # Remove files with unnecessary extensions
    if ($removeExtensions -contains $_.Extension) {
        $keep = $false
    }
    
    if (-not $keep) {
        Write-Host "  [-] Removing: $($_.Name)" -ForegroundColor Red
        Remove-Item $_.FullName -Force
    } else {
        Write-Host "  [+] Keeping: $($_.Name)" -ForegroundColor Green
    }
}

Write-Host "`n[+] Cleanup complete!" -ForegroundColor Green
Write-Host "`n[*] Final payload:" -ForegroundColor Cyan
Get-ChildItem $publishPath -File | ForEach-Object {
    $size = "{0:N2} MB" -f ($_.Length / 1MB)
    Write-Host "  [FILE] $($_.Name) ($size)" -ForegroundColor White
}

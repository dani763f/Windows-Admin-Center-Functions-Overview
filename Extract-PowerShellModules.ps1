# Script to get all modules, and required files for the site from a normal Windows Admin Center install.

$rootPath = Read-Host "Enter the path to the Windows Admin Center modules folder (leave blank for default)"
if ([string]::IsNullOrWhiteSpace($rootPath)) {
    $rootPath = "C:\\ProgramData\\WindowsAdminCenter\\UX\\modules"
}

if (-not (Test-Path -Path $rootPath -PathType Container)) {
    Write-Error "Path not found or not a folder: $rootPath"
    exit 1
}

$outputRoot = Join-Path $PSScriptRoot "_wac-modules-for-site"
New-Item -Path $outputRoot -ItemType Directory -Force | Out-Null

Get-ChildItem -Path $rootPath -Directory | ForEach-Object {
    $moduleName = $_.Name
    $modulePath = $_.FullName
    $psModulePath = Join-Path $modulePath "powershell-module"
    $assetsPath = Join-Path $modulePath "assets"

    $destPath = Join-Path $outputRoot $moduleName
    New-Item -Path $destPath -ItemType Directory -Force | Out-Null

    if (Test-Path -Path $psModulePath -PathType Container) {
        $psm1Files = Get-ChildItem -Path $psModulePath -Filter *.psm1 -File -Recurse -ErrorAction SilentlyContinue
        foreach ($file in $psm1Files) {
            $relative = $file.FullName.Substring($modulePath.Length + 1)
            $target = Join-Path $destPath $relative
            $targetDir = Split-Path -Path $target -Parent
            New-Item -Path $targetDir -ItemType Directory -Force | Out-Null
            Copy-Item -Path $file.FullName -Destination $target -Force
        }
    } else {
        Write-Warning "Skipping '$moduleName' (no powershell-module folder)"
    }

    if (Test-Path -Path $assetsPath -PathType Container) {
        $svgFiles = Get-ChildItem -Path $assetsPath -Filter *.svg -File -Recurse -ErrorAction SilentlyContinue
        foreach ($file in $svgFiles) {
            $relative = $file.FullName.Substring($modulePath.Length + 1)
            $target = Join-Path $destPath $relative
            $targetDir = Split-Path -Path $target -Parent
            New-Item -Path $targetDir -ItemType Directory -Force | Out-Null
            Copy-Item -Path $file.FullName -Destination $target -Force
        }
    }

    $rootSvgs = Get-ChildItem -Path $modulePath -Filter *.svg -File -ErrorAction SilentlyContinue
    if ($rootSvgs.Count -gt 0) {
        Copy-Item -Path $rootSvgs.FullName -Destination $destPath -Force
    }
}

Write-Host "Done. Extracted modules are in: $outputRoot"

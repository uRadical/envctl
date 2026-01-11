# envctl installer for Windows
# Usage: irm https://raw.githubusercontent.com/uradical/envctl/main/install.ps1 | iex

$ErrorActionPreference = "Stop"

$repo = "uradical/envctl"
$installDir = "$env:LOCALAPPDATA\envctl"

# Detect architecture
$arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }

# Windows ARM64 not supported
if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") {
    Write-Error "Windows ARM64 is not supported"
    exit 1
}

# Get latest version
Write-Host "Fetching latest version..."
$release = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest"
$version = $release.tag_name
$versionNum = $version.TrimStart("v")

Write-Host "Installing envctl $version for windows/$arch..."

# Download
$filename = "envctl_${versionNum}_windows_${arch}.zip"
$url = "https://github.com/$repo/releases/download/$version/$filename"
$tempDir = New-Item -ItemType Directory -Path "$env:TEMP\envctl-install-$(Get-Random)"
$zipPath = "$tempDir\$filename"

Write-Host "Downloading $url..."
Invoke-WebRequest -Uri $url -OutFile $zipPath

# Extract
Expand-Archive -Path $zipPath -DestinationPath $tempDir -Force

# Create install directory
if (!(Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
}

# Install
Move-Item -Path "$tempDir\envctl.exe" -Destination "$installDir\envctl.exe" -Force

# Cleanup
Remove-Item -Path $tempDir -Recurse -Force

# Add to PATH if not already there
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$installDir*") {
    Write-Host "Adding $installDir to PATH..."
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$installDir", "User")
    $env:Path = "$env:Path;$installDir"
}

Write-Host ""
Write-Host "Successfully installed envctl $version to $installDir\envctl.exe" -ForegroundColor Green
Write-Host ""
Write-Host "Restart your terminal, then run 'envctl version' to verify the installation."

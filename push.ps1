# Quick push script - run with your token as argument
param([string]$TOKEN)

if (!$TOKEN) {
    Write-Host "Usage: .\push.ps1 YOUR_TOKEN_HERE" -ForegroundColor Red
    exit 1
}

$REPO = "GoodyOG/SSHCustom-Magisk"
$VERSION = "v2.5.0"

Write-Host "Committing..." -ForegroundColor Green
git add -A
git commit -m "Release v2.5.0: Fix no internet + transparent proxy

- Fixed no internet tag on all carriers
- Fixed slow Google/YouTube (removed port 80 bypass)
- Fixed module version display in KSU
- Cleaned up repo and documentation"

Write-Host "Pushing to GitHub..." -ForegroundColor Green
git push -f "https://$TOKEN@github.com/$REPO.git" main

Write-Host "Creating release..." -ForegroundColor Green
$headers = @{
    "Authorization" = "token $TOKEN"
    "Accept" = "application/vnd.github.v3+json"
}

$body = @{
    tag_name = $VERSION
    target_commitish = "main"
    name = "SSHCustom-Magisk $VERSION"
    body = @"
# SSHCustom-Magisk v2.5.0

## Fixed
- No Internet tag on all carriers (bug-host + zero-bug-host)
- Slow Google/YouTube through transparent proxy (port 80 issue)
- Module version display in KSU/Magisk managers
- Universal captive portal compatibility

## Download
[SSHCustom-Magisk-v2.5.0.zip](https://github.com/GoodyOG/SSHCustom-Magisk/releases/download/v2.5.0/SSHCustom-Magisk-v2.5.0.zip)

Tested on HyperOS 3, Android 16, MTN Nigeria
"@
    draft = $false
    prerelease = $false
} | ConvertTo-Json -Depth 10

$release = Invoke-RestMethod -Method Post -Uri "https://api.github.com/repos/$REPO/releases" -Headers $headers -Body $body -ContentType "application/json"

Write-Host "Uploading ZIP..." -ForegroundColor Green
$uploadUrl = $release.upload_url -replace '\{\?.*\}', "?name=SSHCustom-Magisk-v2.5.0.zip"
$zipBytes = [System.IO.File]::ReadAllBytes((Resolve-Path "dist\SSHCustom-Magisk-v2.5.0.zip").Path)
$headers["Content-Type"] = "application/zip"
Invoke-RestMethod -Method Post -Uri $uploadUrl -Headers $headers -Body $zipBytes | Out-Null

Write-Host "`nDONE! Delete your token now!" -ForegroundColor Cyan
Write-Host $release.html_url -ForegroundColor Green

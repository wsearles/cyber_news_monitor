# Builds a release cybernewsmonitor.exe: stripped debug info, no CGO
# (all deps are pure Go), targeting windows/amd64. Run from anywhere;
# output always lands in .\dist next to this script.

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$env:CGO_ENABLED = "0"
$env:GOOS = "windows"
$env:GOARCH = "amd64"

New-Item -ItemType Directory -Force -Path dist | Out-Null

go build -trimpath -ldflags="-s -w" -o dist\cybernewsmonitor.exe .\cmd\cybernewsmonitor

$size = (Get-Item dist\cybernewsmonitor.exe).Length / 1MB
Write-Host ("Built dist\cybernewsmonitor.exe ({0:N1} MB)" -f $size)

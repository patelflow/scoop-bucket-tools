$ErrorActionPreference = "Stop"

$manifestUrl = "https://cnb.cool/jian23/php-spawner/-/git/raw/main/manifest.json"
$bucketFile = Join-Path $PSScriptRoot "..\bucket\phpspawner.json"

# 获取 CNB 最新版本信息
$remote = Invoke-RestMethod -Uri $manifestUrl

$version = [string]$remote.latestVersion
$downloadUrl = [string]$remote.downloadUrl
$hash = [string]$remote.sha256

# 检查数据完整性
if ([string]::IsNullOrWhiteSpace($version) -or
    [string]::IsNullOrWhiteSpace($downloadUrl) -or
    $hash -notmatch '^[a-fA-F0-9]{64}$') {
    throw "CNB manifest.json 缺少有效的版本号、下载地址或 SHA256"
}

if ($downloadUrl -notmatch '^https://') {
    throw "下载地址不是 HTTPS URL"
}

# 读取现有 Scoop manifest，保留其他配置
$path = (Resolve-Path $bucketFile).Path
$app = Get-Content $path -Raw | ConvertFrom-Json

# url/hash 位于 64bit 架构节点下；属性名以数字开头，需用引号
$arch64 = $app.architecture.'64bit'

if ($app.version -eq $version -and
    $arch64.url -eq $downloadUrl -and
    $arch64.hash -eq $hash) {
    Write-Host "phpspawner 已是最新版本：$version"
    exit 0
}

# 同步版本、下载地址和 SHA256
$app.version = $version
$arch64.url = $downloadUrl
$arch64.hash = $hash

$json = $app | ConvertTo-Json -Depth 100
[System.IO.File]::WriteAllText(
    $path,
    $json + [Environment]::NewLine,
    [System.Text.UTF8Encoding]::new($false)
)

Write-Host "已更新 phpspawner"
Write-Host "版本：$version"
Write-Host "下载地址：$downloadUrl"
Write-Host "SHA256：$hash"

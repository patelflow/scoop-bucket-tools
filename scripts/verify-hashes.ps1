<#
.SYNOPSIS
    安全地复核 bucket 中各 manifest 的下载哈希，并在确认“文件被偷换”时刷新哈希。

.DESCRIPTION
    为什么不直接使用 Scoop 自带的 bin/checkhashes.ps1 -Update 做无人值守更新：
      1. 当 URL 返回 404 时它会直接 throw，整轮中止，后续包全部跳过；
      2. 当 URL 返回“200 + HTML 错误页”（镜像 / CDN 软失败）时，它会把错误页的
         哈希当成正确值写入 manifest，造成“自愈变自残”；
      3. 即使哈希本来就正确，它也会整体重写 JSON（重排键顺序、改写行尾），产生脏 diff。

    本脚本采用 fail-closed（不确定就不写）策略，仅在同时满足以下条件时才更新哈希：
      下载成功 + 文件头魔数与扩展名匹配 + 不是 HTML 错误页 + 实际哈希确实变化。
    更新方式为等长字符串替换，只改动哈希值本身，完整保留原文件的键顺序、缩进、
    行尾与末尾空行。任何下载失败、类型未知、内容可疑、哈希出现歧义的情况一律跳过。

    脚本可被 dot-source：此时仅加载函数与常量、不执行复核，便于 Pester 单元测试。

.PARAMETER App
    要复核的包名（不含 .json）。支持通配符，默认复核全部。

.PARAMETER BucketDir
    manifest 目录，默认为脚本上级目录的 bucket。一般无需指定，仅供本地测试覆盖。

.EXAMPLE
    ./scripts/verify-hashes.ps1 -App elyterminal
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [SupportsWildcards()]
    [string]$App = '*',

    [string]$BucketDir
)

# 各受支持归档 / 可执行格式在偏移 0 处的文件头魔数。
# 新增文件类型时在此登记；未登记的扩展名将被保守跳过，而不是贸然写入哈希。
$script:MagicNumbers = [ordered]@{
    '.zip'  = @(0x50, 0x4B, 0x03, 0x04) # PK\x03\x04
    '.xpi'  = @(0x50, 0x4B, 0x03, 0x04)
    '.vsix' = @(0x50, 0x4B, 0x03, 0x04)
    '.jar'  = @(0x50, 0x4B, 0x03, 0x04)
    '.gz'   = @(0x1F, 0x8B)             # gzip（.tar.gz 外层即 gzip）
    '.tgz'  = @(0x1F, 0x8B)
    '.bz2'  = @(0x42, 0x5A, 0x68)
    '.xz'   = @(0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00)
    '.7z'   = @(0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C)
    '.exe'  = @(0x4D, 0x5A)             # MZ
    '.msi'  = @(0xD0, 0xCF, 0x11, 0xE0) # OLE 复合文档
    '.msm'  = @(0xD0, 0xCF, 0x11, 0xE0)
    '.msp'  = @(0xD0, 0xCF, 0x11, 0xE0)
}

function Get-UrlExtension {
    param([Parameter(Mandatory = $true)][string]$Url)
    # 去掉 query / fragment 后取扩展名；.tar.gz 取最后一段 .gz 即可命中 gzip。
    $path = ([Uri]$Url).AbsolutePath
    return [IO.Path]::GetExtension($path).ToLowerInvariant()
}

function Read-LeadingBytes {
    param([Parameter(Mandatory = $true)][string]$Path, [int]$Count = 8)
    $stream = [IO.File]::OpenRead($Path)
    try {
        $length = [Math]::Min($Count, [int]$stream.Length)
        $buffer = New-Object byte[] $length
        [void]$stream.Read($buffer, 0, $length)
        return ,$buffer
    } finally {
        $stream.Dispose()
    }
}

function Test-MagicNumber {
    param([Parameter(Mandatory = $true)][string]$Path, [string]$Extension)
    # 返回 $true / $false；未登记的扩展名返回 $null，表示“无法判断”。
    if (-not $script:MagicNumbers.Contains($Extension)) { return $null }
    $expected = $script:MagicNumbers[$Extension]
    $actual = Read-LeadingBytes -Path $Path -Count $expected.Count
    if ($actual.Count -lt $expected.Count) { return $false }
    for ($i = 0; $i -lt $expected.Count; $i++) {
        if ($actual[$i] -ne $expected[$i]) { return $false }
    }
    return $true
}

function Test-HtmlErrorPage {
    # 镜像 / 对象存储在文件被删除或鉴权失败时，常返回 200 + HTML 提示页。
    param([Parameter(Mandatory = $true)][string]$Path)
    $length = [Math]::Min(1024, [int](Get-Item -LiteralPath $Path).Length)
    if ($length -le 0) { return $false }
    $stream = [IO.File]::OpenRead($Path)
    try {
        $buffer = New-Object byte[] $length
        [void]$stream.Read($buffer, 0, $length)
    } finally {
        $stream.Dispose()
    }
    $head = [Text.Encoding]::ASCII.GetString($buffer).TrimStart()
    if ($head.Length -eq 0 -or $head[0] -ne [char]0x3C) { return $false } # 非 '<' 开头
    return ($head -match '(?is)^(<!doctype|<html|<head|<\?xml)')
}

function Get-ManifestTargets {
    # 汇总 manifest 中所有 (url, hash) 组合，覆盖顶层 url/hash 与多架构两种写法。
    param([Parameter(Mandatory = $true)]$Manifest)
    $targets = @()
    if ($Manifest.url) {
        $urls = @($Manifest.url)
        $hashes = @($Manifest.hash)
        for ($i = 0; $i -lt $urls.Count; $i++) {
            $targets += [pscustomobject]@{ Url = [string]$urls[$i]; HashToken = [string]$hashes[$i] }
        }
    } elseif ($Manifest.architecture) {
        foreach ($arch in @('64bit', '32bit', 'arm64')) {
            $node = $Manifest.architecture.$arch
            if ($null -ne $node -and $node.url) {
                $urls = @($node.url)
                $hashes = @($node.hash)
                for ($i = 0; $i -lt $urls.Count; $i++) {
                    $targets += [pscustomobject]@{
                        Arch      = $arch
                        Url       = [string]$urls[$i]
                        HashToken = [string]$hashes[$i]
                    }
                }
            }
        }
    }
    return $targets
}

function Resolve-HashToken {
    # 拆出算法与十六进制值；支持 "<algo>:<hex>" 形式与按长度推断的裸哈希。
    # 允许空串：manifest 漏填 hash 时应返回 $null（无法判定），而不是抛参数绑定异常。
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Token)
    if ($Token -match '^([A-Za-z0-9]+):([0-9a-fA-F]+)$') {
        return [pscustomobject]@{ Algorithm = $Matches[1].ToUpperInvariant(); Hex = $Matches[2].ToLowerInvariant() }
    }
    $hex = $Token.Trim().ToLowerInvariant()
    $algorithm = switch ($hex.Length) {
        32 { 'MD5' }
        40 { 'SHA1' }
        64 { 'SHA256' }
        128 { 'SHA512' }
        default { $null }
    }
    if ($null -eq $algorithm -or $hex -notmatch '^[0-9a-f]+$') { return $null }
    return [pscustomobject]@{ Algorithm = $algorithm; Hex = $hex }
}

function Save-RemoteFile {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][string]$OutPath
    )
    Invoke-WebRequest -Uri $Url -OutFile $OutPath -UseBasicParsing -MaximumRedirection 10 -TimeoutSec 600 `
        -Headers @{ 'User-Agent' = 'scoop-bucket-verify/1.0' } | Out-Null
}

function Invoke-HashVerification {
    [CmdletBinding()]
    param(
        [SupportsWildcards()]
        [string]$App = '*',

        [string]$BucketDir
    )

    # 执行期偏好放在函数内部：本文件被 dot-source（单元测试）时不污染调用方环境。
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'

    if (-not $BucketDir) {
        $BucketDir = (Resolve-Path (Join-Path $PSScriptRoot '..' 'bucket')).Path
    }

    $tempDir = Join-Path $env:TEMP ("verify-hashes-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tempDir | Out-Null

    try {
        $manifests = Get-ChildItem -LiteralPath $BucketDir -Filter '*.json' -File |
            Where-Object { $_.BaseName -like $App } |
            Sort-Object BaseName

        foreach ($file in $manifests) {
            $app = $file.BaseName
            $originalText = [IO.File]::ReadAllText($file.FullName)

            try {
                $manifest = $originalText | ConvertFrom-Json
            } catch {
                Write-Host "::warning file=bucket/$app.json::$app skipped: invalid JSON manifest"
                continue
            }

            $targets = Get-ManifestTargets -Manifest $manifest
            if ($targets.Count -eq 0) {
                Write-Host "::warning file=bucket/$app.json::$app skipped: no downloadable url found"
                continue
            }

            $text = $originalText
            $updated = $false
            $skipReason = $null

            foreach ($target in $targets) {
                if ([string]::IsNullOrWhiteSpace($target.HashToken)) {
                    $skipReason = 'hash is missing or empty for the url'
                    break
                }
                $parsed = Resolve-HashToken -Token $target.HashToken
                if ($null -eq $parsed) {
                    $skipReason = "unsupported hash token '$($target.HashToken)'"
                    break
                }

                $extension = Get-UrlExtension -Url $target.Url
                $tempFile = Join-Path $tempDir (([Guid]::NewGuid().ToString('N')) + $extension)
                try {
                    Save-RemoteFile -Url $target.Url -OutPath $tempFile
                } catch {
                    $skipReason = "download failed ($extension): $($_.Exception.Message)"
                    break
                }

                $magicOk = Test-MagicNumber -Path $tempFile -Extension $extension
                if ($null -eq $magicOk) {
                    if (Test-HtmlErrorPage -Path $tempFile) {
                        $skipReason = "unsupported type '$extension' and content is an HTML error page"
                    } else {
                        $skipReason = "unsupported file type '$extension' (add its magic number to the script)"
                    }
                    break
                }
                if (-not $magicOk) {
                    if (Test-HtmlErrorPage -Path $tempFile) {
                        $skipReason = 'downloaded content is an HTML error page, not the declared archive'
                    } else {
                        $skipReason = "file header does not match '$extension'"
                    }
                    break
                }

                $actual = (Get-FileHash -LiteralPath $tempFile -Algorithm $parsed.Algorithm).Hash.ToLowerInvariant()
                if ($actual -eq $parsed.Hex) {
                    continue
                }

                # 旧哈希在文件中必须恰好出现一次，避免同一哈希值被多处引用时误替换。
                $occurrences = [regex]::Matches($text, [regex]::Escape($parsed.Hex)).Count
                if ($occurrences -ne 1) {
                    $skipReason = "expected hash is ambiguous ($occurrences occurrences); refusing to edit"
                    break
                }
                $text = $text.Replace($parsed.Hex, $actual)
                $updated = $true
                Write-Host ("{0}: {1} -> {2}" -f $app, $parsed.Hex, $actual)
            }

            if ($skipReason) {
                Write-Host "::warning file=bucket/$app.json::$app skipped: $skipReason"
                continue
            }
            if (-not $updated) {
                Write-Host "$app : OK"
                continue
            }

            # 无 BOM UTF-8 写回；等长十六进制替换不会触碰键顺序、缩进、行尾与末尾空行。
            $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
            [IO.File]::WriteAllText($file.FullName, $text, $utf8NoBom)
            Write-Host "$app : UPDATED"
        }
    } finally {
        Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# 被直接运行（含 pwsh -File、& 脚本路径）时执行复核；被 dot-source（单元测试）时仅加载定义。
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-HashVerification @PSBoundParameters
}

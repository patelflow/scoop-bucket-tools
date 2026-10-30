#Requires -Version 5.1
# verify-hashes.ps1 的单元测试（Pester 5/6，全程离线：用本地固件 + 替换下载器驱动主流程）

BeforeAll {
    $sut = Join-Path $PSScriptRoot '..' 'scripts' 'verify-hashes.ps1'
    # 双保险：即便 dot-source 守卫误判而执行，-App '__none__' 也匹配不到任何包，不联网、不碰真实 bucket
    . $sut -App '__none__'

    # ---- 构造本地“下载固件” ----
    $script:fixtureDir = Join-Path ([IO.Path]::GetTempPath()) ("vh-fixtures-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:fixtureDir | Out-Null

    function New-Fixture {
        param([string]$Name, [byte[]]$Bytes)
        $path = Join-Path $script:fixtureDir $Name
        [IO.File]::WriteAllBytes($path, $Bytes)
        return $path
    }

    $script:zipFile  = New-Fixture 'good.zip' ([byte[]]((0x50, 0x4B, 0x03, 0x04) + (1..200 | ForEach-Object { $_ % 256 })))
    $script:gzFile   = New-Fixture 'good.gz'  ([byte[]]((0x1F, 0x8B, 0x08) + (1..100 | ForEach-Object { $_ % 256 })))
    $script:exeFile  = New-Fixture 'good.exe' ([byte[]]((0x4D, 0x5A)        + (1..100 | ForEach-Object { $_ % 256 })))
    $script:htmlFile = New-Fixture 'error.html' ([Text.Encoding]::UTF8.GetBytes('<!doctype html><html><body>404 Not Found</body></html>'))
    $script:tinyZip  = New-Fixture 'tiny.zip' ([byte[]](0x50, 0x4B)) # 合法 zip 头被截断

    $script:zipHash = (Get-FileHash $script:zipFile -Algorithm SHA256).Hash.ToLowerInvariant()
    $script:gzHash  = (Get-FileHash $script:gzFile  -Algorithm SHA256).Hash.ToLowerInvariant()

    # ---- 用本地固件替换真实下载器（与被测函数同处脚本作用域，调用时命中此覆盖）----
    $script:downloads = @{}
    $script:failingUrls = @()
    function Save-RemoteFile {
        param([string]$Url, [string]$OutPath)
        if ($script:failingUrls -contains $Url) {
            throw "simulated transport failure: $Url"
        }
        $source = $script:downloads[$Url]
        if (-not $source) { throw "simulated 404: no fixture mapped for $Url" }
        Copy-Item -LiteralPath $source -Destination $OutPath
    }

    # ---- 测试辅助：写入 LF / 无 BOM 的 manifest ----
    function New-TestManifest {
        param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Object)
        $json = ($Object | ConvertTo-Json -Depth 8) -replace "`r`n", "`n"
        [IO.File]::WriteAllText($Path, $json, (New-Object Text.UTF8Encoding($false)))
        return [IO.File]::ReadAllText($Path)
    }

    function New-TestBucket {
        param([hashtable]$Manifest, [string]$AppName = 'demo')
        $dir = Join-Path $TestDrive ('bucket-' + [Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $dir | Out-Null
        $path = Join-Path $dir "$AppName.json"
        $original = New-TestManifest -Path $path -Object $Manifest
        return [pscustomobject]@{ Dir = $dir; Path = $path; App = $AppName; Original = $original }
    }
}

AfterAll {
    if ($script:fixtureDir -and (Test-Path $script:fixtureDir)) {
        Remove-Item $script:fixtureDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Get-UrlExtension' {
    It '正确取扩展名 <Url> -> <Expected>' -ForEach @(
        @{ Url = 'https://host/prog-1.zip'; Expected = '.zip' }
        @{ Url = 'https://host/prog-1.tar.gz'; Expected = '.gz' }
        @{ Url = 'https://host/Markpad_2.9.1_x64.exe?token=abc&x=1'; Expected = '.exe' }
        @{ Url = 'https://host/prog.MSI#section'; Expected = '.msi' }
        @{ Url = 'https://host/download/'; Expected = '' }
        @{ Url = 'https://host/plain'; Expected = '' }
    ) {
        Get-UrlExtension -Url $Url | Should -BeExactly $Expected
    }
}

Describe 'Resolve-HashToken' {
    It '按长度识别裸哈希 <Desc>' -ForEach @(
        @{ Desc = 'MD5(32)'; Token = ('a' * 32); Algorithm = 'MD5' }
        @{ Desc = 'SHA1(40)'; Token = ('b' * 40); Algorithm = 'SHA1' }
        @{ Desc = 'SHA256(64)'; Token = ('c' * 64); Algorithm = 'SHA256' }
        @{ Desc = 'SHA512(128)'; Token = ('d' * 128); Algorithm = 'SHA512' }
    ) {
        $r = Resolve-HashToken -Token $Token
        $r.Algorithm | Should -BeExactly $Algorithm
        $r.Hex | Should -BeExactly $Token
    }

    It '支持 "algo:hex" 前缀并归一化大小写' {
        $r = Resolve-HashToken -Token ('SHA256:' + ('AB' * 32))
        $r.Algorithm | Should -BeExactly 'SHA256'
        $r.Hex | Should -BeExactly ('ab' * 32)
    }

    It '非法输入返回 $null: <Desc>' -ForEach @(
        @{ Desc = '长度不合法'; Token = 'abc' }
        @{ Desc = '长度为 64 但含非十六进制字符'; Token = ('z' * 64) }
        @{ Desc = '空字符串'; Token = '' }
    ) {
        Resolve-HashToken -Token $Token | Should -BeNullOrEmpty
    }
}

Describe 'Read-LeadingBytes' {
    It '读取文件前 N 字节' {
        $bytes = Read-LeadingBytes -Path $script:zipFile -Count 4
        $bytes | Should -HaveCount 4
        $bytes[0] | Should -Be 0x50
        $bytes[3] | Should -Be 0x04
    }

    It '文件短于请求长度时返回实际长度' {
        $bytes = Read-LeadingBytes -Path $script:tinyZip -Count 8
        $bytes | Should -HaveCount 2
    }
}

Describe 'Test-MagicNumber' {
    It '<Desc> 应返回 <Expected>' -ForEach @(
        @{ Desc = 'zip 头 + .zip'; FileKey = 'zipFile'; Ext = '.zip'; Expected = $true }
        @{ Desc = 'gzip 头 + .gz'; FileKey = 'gzFile'; Ext = '.gz'; Expected = $true }
        @{ Desc = 'MZ 头 + .exe'; FileKey = 'exeFile'; Ext = '.exe'; Expected = $true }
        @{ Desc = 'HTML 内容伪装成 .zip'; FileKey = 'htmlFile'; Ext = '.zip'; Expected = $false }
        @{ Desc = '被截断的 zip 头'; FileKey = 'tinyZip'; Ext = '.zip'; Expected = $false }
    ) {
        $r = Test-MagicNumber -Path (Get-Variable -Name $FileKey -ValueOnly -Scope Script) -Extension $Ext
        if ($Expected) { $r | Should -BeTrue } else { $r | Should -BeFalse }
    }

    It '未登记的扩展名返回 $null（无法判断）' {
        Test-MagicNumber -Path $script:zipFile -Extension '.appimage' | Should -BeNullOrEmpty
    }
}

Describe 'Test-HtmlErrorPage' {
    It '识别 HTML 错误页: <Desc>' -ForEach @(
        @{ Desc = 'doctype'; Content = '<!doctype html><html></html>' }
        @{ Desc = '大写 DOCTYPE 且有前导空白'; Content = "   `n<!DOCTYPE html>" }
        @{ Desc = 'html 标签'; Content = '<html><body>x</body>' }
        @{ Desc = 'xml 声明'; Content = '<?xml version="1.0"?><Error/>' }
    ) {
        $path = Join-Path $TestDrive 'probe.bin'
        [IO.File]::WriteAllBytes($path, [Text.Encoding]::UTF8.GetBytes($Content))
        Test-HtmlErrorPage -Path $path | Should -BeTrue
    }

    It '排除非 HTML 内容: <Desc>' -ForEach @(
        @{ Desc = 'zip 二进制'; FileKey = 'zipFile' }
        @{ Desc = 'gzip 二进制'; FileKey = 'gzFile' }
        @{ Desc = '非尖括号开头文本'; Content = 'Not Found, please login' }
        @{ Desc = '尖括号开头但非白名单标签'; Content = '<note>hello</note>' }
    ) {
        if ($FileKey) {
            $path = Get-Variable -Name $FileKey -ValueOnly -Scope Script
        } else {
            $path = Join-Path $TestDrive 'probe2.bin'
            [IO.File]::WriteAllBytes($path, [Text.Encoding]::UTF8.GetBytes($Content))
        }
        Test-HtmlErrorPage -Path $path | Should -BeFalse
    }
}

Describe 'Get-ManifestTargets' {
    It '枚举顶层标量 url/hash' {
        $m = [pscustomobject]@{ url = 'https://h/a.zip'; hash = ('a' * 64) }
        $t = Get-ManifestTargets -Manifest $m
        $t | Should -HaveCount 1
        $t[0].Url | Should -BeExactly 'https://h/a.zip'
    }

    It '枚举顶层数组 url/hash 并保持顺序' {
        $m = [pscustomobject]@{ url = @('https://h/1', 'https://h/2'); hash = @('h1', 'h2') }
        $t = Get-ManifestTargets -Manifest $m
        $t | Should -HaveCount 2
        $t[0].Url | Should -BeExactly 'https://h/1'
        $t[0].HashToken | Should -BeExactly 'h1'
    }

    It '多架构按 64bit -> 32bit -> arm64 排序' {
        $m = [pscustomobject]@{
            architecture = [pscustomobject]@{
                '32bit' = [pscustomobject]@{ url = 'u32'; hash = 'h32' }
                arm64  = [pscustomobject]@{ url = 'uarm'; hash = 'harm' }
                '64bit' = [pscustomobject]@{ url = 'u64'; hash = 'h64' }
            }
        }
        $t = Get-ManifestTargets -Manifest $m
        $t | Should -HaveCount 3
        ($t | ForEach-Object Arch) -join ',' | Should -BeExactly '64bit,32bit,arm64'
    }

    It '没有任何可下载 url 时返回空集合' {
        Get-ManifestTargets -Manifest ([pscustomobject]@{ version = '1.0' }) | Should -HaveCount 0
    }
}

Describe 'Invoke-HashVerification 端到端（离线）' {
    BeforeEach {
        # 每个用例独立配置“服务器”上有哪些文件、哪些 URL 失败
        $script:downloads = @{}
        $script:failingUrls = @()
        $script:wrongHash = 'f' * 64
    }

    It '哈希漂移：精确等长替换，其余字节（含键序 / LF）完全不变' {
        $bucket = New-TestBucket -Manifest ([ordered]@{
                version     = '0.2.0'
                description = '保留 中文 与键序'
                homepage    = 'https://example.com'
                license     = 'MIT'
                architecture = [ordered]@{
                    '64bit' = [ordered]@{
                        url  = 'https://host/prog.zip'
                        hash = $script:wrongHash
                    }
                }
                bin = 'prog.exe'
            })
        $script:downloads['https://host/prog.zip'] = $script:zipFile

        Invoke-HashVerification -App $bucket.App -BucketDir $bucket.Dir

        $result = [IO.File]::ReadAllText($bucket.Path)
        $result | Should -BeExactly ($bucket.Original.Replace($script:wrongHash, $script:zipHash))
        $result.Contains($script:zipHash) | Should -BeTrue
        $result.Contains($script:wrongHash) | Should -BeFalse
    }

    It '哈希本就正确：文件逐字节不变' {
        $bucket = New-TestBucket -Manifest ([ordered]@{
                version = '1.0'; license = 'MIT'
                architecture = [ordered]@{ '64bit' = [ordered]@{ url = 'https://host/ok.zip'; hash = $script:zipHash } }
            })
        $script:downloads['https://host/ok.zip'] = $script:zipFile

        Invoke-HashVerification -App $bucket.App -BucketDir $bucket.Dir

        [IO.File]::ReadAllText($bucket.Path) | Should -BeExactly $bucket.Original
    }

    It '下载失败（模拟 404 / 传输错误）：fail-closed，文件不变' {
        $bucket = New-TestBucket -Manifest ([ordered]@{
                version = '1.0'; license = 'MIT'
                architecture = [ordered]@{ '64bit' = [ordered]@{ url = 'https://host/missing.zip'; hash = $script:wrongHash } }
            })
        $script:failingUrls = @('https://host/missing.zip')

        Invoke-HashVerification -App $bucket.App -BucketDir $bucket.Dir

        [IO.File]::ReadAllText($bucket.Path) | Should -BeExactly $bucket.Original
    }

    It '200 + HTML 错误页伪装成 zip：拒绝写入，文件不变' {
        $bucket = New-TestBucket -Manifest ([ordered]@{
                version = '1.0'; license = 'MIT'
                architecture = [ordered]@{ '64bit' = [ordered]@{ url = 'https://host/trap.zip'; hash = $script:wrongHash } }
            })
        $script:downloads['https://host/trap.zip'] = $script:htmlFile

        Invoke-HashVerification -App $bucket.App -BucketDir $bucket.Dir

        [IO.File]::ReadAllText($bucket.Path) | Should -BeExactly $bucket.Original
    }

    It '未登记扩展名（.AppImage）且非 HTML：保守跳过，文件不变' {
        $bucket = New-TestBucket -Manifest ([ordered]@{
                version = '1.0'; license = 'MIT'
                architecture = [ordered]@{ '64bit' = [ordered]@{ url = 'https://host/prog.AppImage'; hash = $script:wrongHash } }
            })
        # 内容其实是 zip，但扩展名未登记 -> 不应据其魔数写哈希
        $script:downloads['https://host/prog.AppImage'] = $script:zipFile

        Invoke-HashVerification -App $bucket.App -BucketDir $bucket.Dir

        [IO.File]::ReadAllText($bucket.Path) | Should -BeExactly $bucket.Original
    }

    It '旧哈希在文件中出现多次（歧义）：拒绝编辑，文件不变' {
        $bucket = New-TestBucket -Manifest ([ordered]@{
                version = '1.0'; license = 'MIT'
                description = $script:wrongHash   # 与 hash 字段相同 -> 出现 2 次
                architecture = [ordered]@{ '64bit' = [ordered]@{ url = 'https://host/prog.zip'; hash = $script:wrongHash } }
            })
        $script:downloads['https://host/prog.zip'] = $script:zipFile

        Invoke-HashVerification -App $bucket.App -BucketDir $bucket.Dir

        [IO.File]::ReadAllText($bucket.Path) | Should -BeExactly $bucket.Original
    }

    It '支持 .tar.gz（gzip 外层魔数）哈希漂移自愈' {
        $bucket = New-TestBucket -Manifest ([ordered]@{
                version = '1.0'; license = 'MIT'
                architecture = [ordered]@{ '64bit' = [ordered]@{ url = 'https://host/prog.tar.gz'; hash = $script:wrongHash } }
            })
        $script:downloads['https://host/prog.tar.gz'] = $script:gzFile

        Invoke-HashVerification -App $bucket.App -BucketDir $bucket.Dir

        $result = [IO.File]::ReadAllText($bucket.Path)
        $result.Contains($script:gzHash) | Should -BeTrue
        $result.Contains($script:wrongHash) | Should -BeFalse
    }

    It '支持顶层 url/hash（非 architecture）形式的自愈' {
        $bucket = New-TestBucket -Manifest ([ordered]@{
                version = '1.0'; license = 'MIT'
                url = 'https://host/top.zip'
                hash = $script:wrongHash
            })
        $script:downloads['https://host/top.zip'] = $script:zipFile

        Invoke-HashVerification -App $bucket.App -BucketDir $bucket.Dir

        $result = [IO.File]::ReadAllText($bucket.Path)
        $result.Contains($script:zipHash) | Should -BeTrue
    }

    It 'url 存在但 hash 缺失：跳过且不抛异常、文件不变' {
        $bucket = New-TestBucket -Manifest ([ordered]@{
                version = '1.0'; license = 'MIT'
                url = 'https://host/nohash.zip'
            })
        $script:downloads['https://host/nohash.zip'] = $script:zipFile

        { Invoke-HashVerification -App $bucket.App -BucketDir $bucket.Dir } | Should -Not -Throw
        [IO.File]::ReadAllText($bucket.Path) | Should -BeExactly $bucket.Original
    }

    It 'manifest 缺少可下载 url：跳过且不修改文件' {
        $bucket = New-TestBucket -Manifest ([ordered]@{ version = '1.0'; license = 'MIT' })

        Invoke-HashVerification -App $bucket.App -BucketDir $bucket.Dir

        [IO.File]::ReadAllText($bucket.Path) | Should -BeExactly $bucket.Original
    }
}

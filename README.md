# scoop-bucket-tools

个人 [Scoop](https://scoop.sh) 软件仓库（bucket）。

## 添加 bucket

```powershell
scoop bucket add patelflow_scoop-bucket-tools https://github.com/patelflow/scoop-bucket-tools
```

## 更新软件版本号

`.\bin\checkver.ps1 phpspawner` 验证版本是否有更新，`-u` 自动更新`bucket`中`phpspawner.json`版本

```
.\bin\checkver.ps1 phpspawner -u
```

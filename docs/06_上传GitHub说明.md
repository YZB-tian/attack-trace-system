# 如何把这套骨架放入现有 GitHub 仓库

你的仓库如果现在只有 `README.md`：

## 方法 A：本地 Git（推荐）

1. Clone 你的仓库。
2. 把本压缩包中 `attack-trace-system-starter` **里面的所有文件**复制到 clone 下来的仓库根目录。
3. 允许替换原来的 README。
4. 打开终端执行：

```bash
git add .
git commit -m "chore: initialize unified project skeleton"
git push origin main
```

## 方法 B：GitHub 网页

解压后，把文件/文件夹上传到仓库根目录。

注意：不要把 `attack-trace-system-starter.zip` 作为一个压缩包直接存进仓库；GitHub 里应该能直接看到：
`AGENTS.md`、`common/`、`schemas/`、`collectors/` 等目录。

上传完成后先不要让大家同时大改公共文件。

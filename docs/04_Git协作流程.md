# Git 协作流程

## 第一次

```bash
git clone <仓库地址>
cd attack-trace-system
```

建议组长创建 `dev` 分支。

成员开发：

```bash
git checkout dev
git pull
git checkout -b feature/windows-log
```

开发完成：

```bash
python scripts/validate_contracts.py
pytest -q

git add .
git commit -m "feat: implement windows log parser"
git push -u origin feature/windows-log
```

然后发 Pull Request，不直接把未测试代码推入 `main`。

## 每天开始前

```bash
git checkout dev
git pull
```

再将最新 `dev` 合入自己的功能分支。

## 公共接口变化

若有人认为 Schema 不够用：
1. 不直接改；
2. 建 Issue/群里说明；
3. 组长确认；
4. 统一修改公共契约；
5. 所有人同步；
6. 再继续开发。

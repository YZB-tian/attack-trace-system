# 协作规则

## 分支

建议：
- `main`：只放可演示版本
- `dev`：日常集成
- `feature/<模块名>`：个人开发

示例：

```bash
git checkout -b feature/windows-log
```

## 提交前

```bash
git pull
python scripts/validate_contracts.py
pytest -q
```

## PR 合并条件

- [ ] 没有私改公共 Schema
- [ ] 没有创建重复模型
- [ ] Mock 数据可运行
- [ ] 契约测试通过
- [ ] 与至少一个上下游模块完成联调
- [ ] README/运行方式已写明

公共接口需要变化时，由组长统一修改并通知所有成员重新 `git pull`。

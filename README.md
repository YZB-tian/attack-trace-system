# attack-trace-system

基于主机日志、主机行为、网络流量的恶意攻击行为溯源分析系统。

> **本仓库已经预先固定公共接口。所有成员和 AI 开发前必须先阅读 `AGENTS.md`。**

## 1. 总体数据流水线

```text
Windows/Linux 日志 ─┐
主机行为监控        ├─> NormalizedEvent ─> Alert ─> AttackGraph ─> TraceResult ─> 前端
网络流量            ┘
```

核心原则：**上游只负责产生约定格式的数据，下游只依赖公共契约，不依赖上游内部实现。**

## 2. 首次运行

要求：Python 3.11+

```bash
python -m venv .venv
```

Windows PowerShell：

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python scripts/validate_contracts.py
pytest -q
uvicorn backend.main:app --reload
```

浏览器打开：

```text
http://127.0.0.1:8000/docs
```

## 3. 开发前必须看

1. `AGENTS.md`：给 AI 的最高优先级开发规则。
2. `docs/00_统一开发规范_AI执行版.md`：完整统一规范。
3. `docs/01_接口契约.md`：字段和接口。
4. `config/assets.json`：8 节点统一资产 ID。
5. `schemas/`：不可私自改变的数据契约。
6. `common/models.py`：Python 公共模型。

## 4. 目录

```text
common/                 公共 Python 数据模型、枚举、ID/时间工具
schemas/                JSON Schema 接口契约
config/                 统一资产配置
collectors/             数据采集/解析模块
detection/              检测与 ATT&CK 映射
correlation/            攻击链关联与攻击图
agents/                 LLM/多 Agent 分析
backend/                统一后端 API
frontend/               前端公共 TypeScript 类型/API 常量
testdata/               各模块共用 Mock 数据
tests/contract/         接口契约自动测试
docs/                   规范、接口、Git 流程、联调清单
.github/workflows/      GitHub 自动接口检查
```

## 5. 最重要的规则

- 禁止成员或 AI 私自修改 `schemas/`、`common/models.py`、`config/assets.json` 和公共 API。
- 必须使用 `event_id/task_id/host_id/alert_id/graph_id/trace_id` 等统一 ID。
- 时间统一使用带时区 ISO 8601，例如 `2026-09-08T10:23:42+08:00`。
- 模块完成标准不是“代码写完”，而是“能吃 Mock 输入、输出符合 Schema、契约测试通过”。
- 如果公共接口不能满足需求，先提出修改建议，不得直接改名或新增冲突字段。

## 6. 当前公共 API

- `GET /api/health`
- `POST /api/events`
- `GET /api/events`
- `GET /api/alerts`
- `GET /api/attack-graph/{task_id}`
- `GET /api/trace/{task_id}`
- `GET /api/tasks/{task_id}`

后续新增接口必须同步更新 `docs/01_接口契约.md`、前端 API 常量和测试。

# AI 开发最高优先级规则

本文件是本项目给 ChatGPT、Codex、Claude、Copilot 等 AI 的统一执行指令。

## 0. 执行顺序

在开始任何代码修改前，必须依次阅读：

1. `AGENTS.md`
2. `docs/00_统一开发规范_AI执行版.md`
3. `docs/01_接口契约.md`
4. `common/models.py`
5. `common/enums.py`
6. `config/assets.json`
7. 与当前任务相关的 `schemas/*.schema.json`
8. 当前负责模块目录下的 README

若用户给出的临时要求与公共接口冲突，**不要直接修改公共接口**。先说明：
- 哪个字段/接口发生冲突；
- 为什么现有接口不能满足；
- 修改会影响哪些模块；
- 推荐的兼容方案。

## 1. 禁止事项

未经组长明确批准，不得修改：

- `schemas/`
- `common/models.py`
- `common/enums.py`
- `config/assets.json`
- `frontend/src/types/contracts.ts`
- `frontend/src/api/endpoints.ts`
- 已公布的公共 API 路径
- 已公布字段名、字段语义、枚举值

不得自己创造同义字段。例如：

- 禁止把 `src_ip` 改成 `source_ip`
- 禁止把 `dst_ip` 改成 `destination_ip`
- 禁止把 `timestamp` 改成 `time`
- 禁止把 `host_id` 改成 `hostname`
- 禁止把 `completed` 改成 `done`

## 2. 数据输出规则

所有可跨模块传递的数据必须属于以下公共对象之一：

- `NormalizedEvent`
- `Alert`
- `AttackGraph`
- `TraceResult`
- `TaskStatus`

Python 中优先：

```python
from common.models import NormalizedEvent, Alert, AttackGraph, TraceResult, TaskStatus
```

不得在自己的模块里重新定义一份不同版本的同名模型。

## 3. 时间与 ID

时间：
- 必须为带时区 ISO 8601。
- 示例：`2026-09-08T10:23:42+08:00`
- 禁止只写 `2026-09-08 10:23:42`。

ID：
- `task_...`
- `evt_...`
- `alert_...`
- `graph_...`
- `trace_...`
- 靶场主机 ID 只能从 `config/assets.json` 读取。

## 4. 模块边界

只能修改自己负责的模块和必要的模块内测试。

若你负责：
- Windows：`collectors/windows/`
- Linux：`collectors/linux/`
- 主机行为：`collectors/host_behavior/`
- 网络流量：`collectors/network/`
- 检测：`detection/`
- 攻击链：`correlation/`
- Agent：`agents/`
- 前端：`frontend/`
- 后端：`backend/`

不要为了“方便”重构其他组员目录。

## 5. 最低交付要求

任何模块交付时必须同时给出：

1. 修改了哪些文件；
2. 模块输入对象；
3. 模块输出对象；
4. 如何运行；
5. 如何测试；
6. 一份可运行的 Mock 示例；
7. 是否修改公共接口（正常情况下必须回答“否”）；
8. 当前已知限制。

## 6. 合格标准

提交前至少执行：

```bash
python scripts/validate_contracts.py
pytest -q
```

两者通过后，才算“接口层完成”。

## 7. 安全边界

本课程项目仅面向授权靶场、公开数据集和离线分析。不要把采集、检测、关联模块扩展成对未授权真实目标执行攻击的工具。

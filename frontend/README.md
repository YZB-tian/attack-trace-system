# Frontend

React + Vite + TypeScript 前端，用于展示任务、事件、告警、攻击图和溯源结果。

## 启动

先在仓库根目录启动后端：

```bash
python -m uvicorn backend.main:app --reload
```

再启动前端：

```bash
cd frontend
npm install
npm run dev
```

浏览器访问 `http://127.0.0.1:5173`。Vite 将 `/api` 代理到 `http://127.0.0.1:8000`。

当前仓库 Mock 联调任务为 `task_demo_001`。

## 构建检查

```bash
npm run build
```

公共字段和 API 路径来自：

- `src/types/contracts.ts`
- `src/api/endpoints.ts`

不得在前端重命名公共字段或 API。

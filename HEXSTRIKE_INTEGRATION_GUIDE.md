# HexStrike RAG 知识库 — 集成指南

> 将五周 HexStrike RAG 成果集成到 `ollama_mcp` 基准项目中

---

## 一、集成架构

```
┌─────────────────────────────────────────────────┐
│  ollmcp 客户端                                    │
│  Ollama LLM (qwen3 / gpt-oss 等)                  │
└────────────────┬────────────────────────────────┘
                 │ stdio 传输 (MCP 协议)
                 ▼
┌─────────────────────────────────────────────────┐
│  hexstrike_rag_mcp_server.py  ← 新建             │
│  MCP Server (兼容 ollmcp 的 stdio 传输)            │
│                                                  │
│  工具 1: search_security_knowledge                │
│          检索渗透测试安全知识库                     │
│  工具 2: get_knowledge_base_stats                 │
│          获取知识库统计信息                         │
│  工具 3: verify_payload_safety                    │
│          验证 payload 安全等级                     │
└────────────────┬────────────────────────────────┘
                 │
       ┌─────────┴─────────┐
       ▼                   ▼
  ┌─────────┐        ┌─────────────┐
  │ 阶段一   │  →    │  阶段二      │
  │ Mock模式 │        │ 真实管线     │
  │ (当前)   │        │ (下周)       │
  └─────────┘        └──────┬──────┘
                            │
                  ┌─────────┼─────────┐
                  ▼         ▼         ▼
              BM25+Qdrant  Cross-   缓存层
              向量检索     Encoder   Redis
                           重排器
```

## 二、文件结构

```
ollama_mcp/
├── hexstrike_rag_mcp_server.py       ← 新建! MCP 服务器 (stdio 传输)
├── hexstrike_rag_config.json         ← 新建! 服务器配置
├── HEXSTRIKE_INTEGRATION_GUIDE.md    ← 本指南
│
├── hexstrike_rag/                    ← 五周 RAG 代码 (阶段二使用)
│   ├── retrieval_pipeline.py         ← 四步检索链路
│   ├── bm25_retriever.py
│   ├── vector_retriever.py
│   ├── reranker.py
│   ├── rrf_fusion.py
│   ├── qdrant_store.py
│   ├── cache_layer_v2.py
│   ├── query_expansion.py
│   ├── metadata_schema.py
│   ├── deduplication.py
│   └── ... (共 18 个文件)
│
├── rag_mcp_server.py                 ← 原版 (保留)
├── rag_knowledge_base/               ← 原版 ChromaDB (保留)
└── rag_mcp_config.json               ← 原版配置 (保留)
```

## 三、快速启动（阶段一 · Mock 模式）

**不需要 Qdrant / Redis / 大模型**，直接运行即可。

### 3.1 启动 ollmcp

```bash
cd <PROJECT_ROOT>

ollmcp -j hexstrike_rag_config.json
```

### 3.2 在 ollmcp 中启用 HexStrike 工具

启动后，在 ollmcp 交互界面输入：

```
tools
```

你会看到类似输出：

```
服务器: hexstrike-rag (MCP)
  1. search_security_knowledge  - 检索渗透测试安全知识库
  2. get_knowledge_base_stats   - 获取知识库统计信息
  3. verify_payload_safety      - 验证 payload 安全等级
```

输入 `a` 启用所有工具，然后输入 `s` 保存返回聊天。

### 3.3 测试对话

**测试 1：安全知识检索**
```
你: SQL 注入有哪些类型和防御方法？
```
→ ollmcp 自动调用 `search_security_knowledge` 工具  
→ 返回模拟的安全知识文档（包含漏洞类型、严重程度、来源等）

**测试 2：Payload 安全验证**
```
你: 帮我验证这个 payload: ' OR 1=1 --
```
→ ollmcp 自动调用 `verify_payload_safety` 工具  
→ 返回风险等级和安全建议

**测试 3：知识库状态查询**
```
你: 知识库现在有多少文档？状态正常吗？
```
→ ollmcp 自动调用 `get_knowledge_base_stats` 工具  
→ 返回文档数量、漏洞分布等统计信息

### 3.4 同时使用原版 RAG + HexStrike

`hexstrike_rag_config.json` 中同时配置了两个 MCP 服务器：
- `hexstrike-rag` → 新版 (HexStrike 五周成果)
- `rag-knowledge-base` → 原版 (ChromaDB)

ollmcp 会同时连接两个服务器，模型可以自由选择使用哪个工具。

---

## 四、阶段二：切换到真实管线（下周）

### 前置条件

| 依赖 | 安装方式 |
|------|---------|
| Qdrant | `docker run -d -p 6333:6333 --name qdrant qdrant/qdrant` |
| Redis | `docker run -d -p 6379:6379 --name redis redis:7` |
| bge-m3 | 下载模型到服务器 |
| bge-reranker | 下载模型到服务器 |
| Python 依赖 | `pip install qdrant-client redis sentence-transformers` |

### 4.1 修改配置

编辑 `hexstrike_rag_config.json`，将 `HEXSTRIKE_USE_MOCK` 改为 `false`：

```json
{
  "mcpServers": {
    "hexstrike-rag": {
      "command": "python3",
      "args": ["<PROJECT_ROOT>/hexstrike_rag_mcp_server.py"],
      "env": {
        "PYTHONPATH": "<PROJECT_ROOT>",
        "HEXSTRIKE_USE_MOCK": "false"
      }
    }
  }
}
```

### 4.2 导入数据

```bash
cd <PROJECT_ROOT>
python3 hexstrike_rag/data_loader_100k.py --source all --limit 100000
```

### 4.3 重启 ollmcp

```bash
ollmcp -j hexstrike_rag_config.json
```

启动日志确认：
```
[HexStrike] MCP 服务器启动 — 🟢 真实管线模式
[HexStrike] ✅ 真实管线已加载
```

---

## 五、五周成果关键指标

| 里程碑 | 指标 | 目标值 | 实际值 | 状态 |
|--------|------|--------|--------|------|
| M1 数据层 | 知识库规模 | 10万+ | 100,000 | ✅ |
| M2 检索层 | Recall@10 | ≥85% | 88% | ✅ |
| M2 检索层 | nDCG@10 | ≥0.75 | 0.76 | ✅ |
| M2 检索层 | P95 延迟 | <500ms | 185ms | ✅ |
| M3 服务层 | MCP 工具数 | ≥3 | 3 | ✅ |
| M3 服务层 | 测试用例通过 | 全部 | 15/15 | ✅ |
| **代码总量** | | | **6,390 行** | ✅ |

---

## 六、阶段切换说明

| | 阶段一（当前） | 阶段二（下周） |
|--|---------------|---------------|
| 数据 | Mock 模拟数据 | 真实 Qdrant 10万+文档 |
| 检索 | 直接返回模拟结果 | BM25+向量+RRF+Cross-Encoder |
| 缓存 | 无 | Redis 标签缓存 |
| 查询扩展 | 无 | 同义词+实体改写 |
| 启动要求 | 仅需 ollmcp | Qdrant + Redis + ML 模型 |
| 切换方式 | `HEXSTRIKE_USE_MOCK=true` | `HEXSTRIKE_USE_MOCK=false` |

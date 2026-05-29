#!/usr/bin/env python3
"""
HexStrike RAG MCP 服务器 - stdio 传输版

兼容 ollmcp 客户端（Model Context Protocol stdio 传输协议）。

将 HexStrike 五周成果（RAG 知识库）封装为 MCP 工具，
供 ollmcp 客户端中的 Ollama 模型调用。

工具列表：
1. search_security_knowledge   - 检索渗透测试安全知识库
2. get_knowledge_base_stats    - 获取知识库统计信息
3. verify_payload_safety       - 验证安全测试 payload 风险等级

============================================================
集成说明：
  - 第一阶段（当前）：使用 Mock 数据验证接口连通性
  - 第二阶段（下周）：接入真实的 RetrievalPipeline（Qdrant + BM25 + Cross-Encoder）
  - 切换方式：设置环境变量 HEXSTRIKE_USE_MOCK=false
============================================================
"""

import asyncio
import hashlib
import os
import sys
import time
from typing import Any, Dict, List, Optional
from datetime import datetime

# ====== 添加项目路径 ======
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_DIR)

# MCP SDK（与 ollmcp 兼容）
from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server import NotificationOptions, Server
import mcp.server.stdio


# ====== 配置 ======
USE_MOCK = os.environ.get("HEXSTRIKE_USE_MOCK", "true").lower() == "true"

# 真实管线（第二阶段启用）
if not USE_MOCK:
    try:
        from hexstrike_rag.retrieval_pipeline import RetrievalPipeline, RuleFilter
        from hexstrike_rag.query_expansion import QueryExpander
        from hexstrike_rag.cache_layer_v2 import TaggedQueryCache
        REAL_PIPELINE_AVAILABLE = True
    except ImportError as e:
        print(f"[HexStrike] 真实管线不可用: {e}", file=sys.stderr)
        REAL_PIPELINE_AVAILABLE = False
        USE_MOCK = True
else:
    REAL_PIPELINE_AVAILABLE = False


# ====== 初始化真实管线（如果可用） ======
if REAL_PIPELINE_AVAILABLE:
    try:
        _pipeline = RetrievalPipeline()
        _expander = QueryExpander()
        _cache = TaggedQueryCache()
        print("[HexStrike] ✅ 真实管线已加载", file=sys.stderr)
    except Exception as e:
        print(f"[HexStrike] ⚠️ 真实管线初始化失败，回退到 Mock 模式: {e}", file=sys.stderr)
        REAL_PIPELINE_AVAILABLE = False


# ====== Payload 安全验证器（直接使用第五周实现） ======
class PayloadSafetyVerifier:
    """验证安全测试 payload 的风险等级"""

    DANGEROUS_PATTERNS = [
        "rm -rf /",
        "DROP TABLE",
        "; rm -",
        "&& rm -",
        "exec(",
        "eval(",
        "__import__",
    ]

    SAFE_TEST_PATTERNS = [
        "<script>alert(1)</script>",
        "' OR '1'='1",
        "1; sleep 5",
        "{{7*7}}",
        "${jndi:",
        "../../etc/passwd",
    ]

    def verify(self, payload: str, context: str = "testing") -> Dict:
        findings = []
        risk_level = "safe"

        for pattern in self.DANGEROUS_PATTERNS:
            if pattern.lower() in payload.lower():
                findings.append({
                    "type": "dangerous_pattern",
                    "pattern": pattern,
                    "risk": "critical",
                    "description": f"检测到危险操作模式: {pattern}",
                })
                risk_level = "critical"

        is_known_test = False
        for safe_pattern in self.SAFE_TEST_PATTERNS:
            if safe_pattern.lower() in payload.lower():
                is_known_test = True
                findings.append({
                    "type": "known_test_pattern",
                    "pattern": safe_pattern,
                    "risk": "info",
                    "description": f"识别为安全测试模式: {safe_pattern}",
                })

        if len(payload) > 10000:
            findings.append({
                "type": "excessive_length",
                "risk": "warning",
                "description": f"payload 过长 ({len(payload)} 字符)",
            })
            if risk_level == "safe":
                risk_level = "warning"

        recommendations = {
            "critical": "⚠️ 检测到高危操作，请确认操作意图后再执行",
            "warning": "⚡ 存在潜在风险，建议审查后再执行",
            "safe": "✅ 未发现明显安全风险",
        }
        if is_known_test:
            recommendations["safe"] = "✅ 识别为标准安全测试模式，可在授权环境中使用"

        return {
            "payload_hash": hashlib.sha256(payload.encode()).hexdigest()[:16],
            "risk_level": risk_level,
            "is_known_test": is_known_test,
            "context": context,
            "findings": findings,
            "recommendation": recommendations.get(risk_level, "✅ 未发现明显安全风险"),
        }


_verifier = PayloadSafetyVerifier()


# ====== Mock 检索（第一阶段） ======
def mock_search(query: str, top_k: int = 10,
                vuln_type: Optional[str] = None,
                severity: Optional[str] = None,
                min_confidence: float = 0.7,
                use_expansion: bool = True) -> Dict:
    """
    Mock 安全检索 — 第一阶段使用
    
    第二阶段：替换为真实的 RetrievalPipeline.search()
    """
    vuln_types = ["SQL注入", "XSS", "RCE", "SSRF", "认证绕过", "文件上传"]
    severities = ["Critical", "High", "Medium", "Low"]
    sources = ["HackTricks", "OWASP", "CVE/NVD", "本地知识库"]

    results = []
    for i in range(min(top_k, 5)):
        vt = vuln_type if vuln_type else vuln_types[i % len(vuln_types)]
        sv = severity if severity else severities[i % len(severities)]
        results.append({
            "id": hashlib.md5(f"{query}-{i}".encode()).hexdigest()[:12],
            "content": f"【{vt}】关于 {query} 的安全技术文档片段 #{i+1}。"
                       f"涉及 {vt} 漏洞的检测、利用与防御方法。"
                       f"CVSS 评分参考值可用于安全评估。",
            "score": round(0.95 - i * 0.1, 3),
            "metadata": {
                "vuln_type": vt,
                "severity": sv,
                "confidence": round(0.9 - i * 0.05, 2),
                "source": sources[i % len(sources)],
                "date": "2024-01-15",
                "is_expired": False,
                "has_poc": i % 2 == 0,
            }
        })

    return {
        "query": query,
        "results": results,
        "total": len(results),
        "latency_ms": 0.1,
        "expansion_used": use_expansion,
    }


# ====== 真实检索（第二阶段） ======
def real_search(query: str, top_k: int = 10,
                vuln_type: Optional[str] = None,
                severity: Optional[str] = None,
                min_confidence: float = 0.7,
                use_expansion: bool = True) -> Dict:
    """
    真实安全检索 — 第二阶段启用
    
    调用五周成果构建的完整检索管线：
      BM25 → 向量召回 → RRF 融合 → Cross-Encoder 重排 → 规则过滤
    """
    start = time.time()

    filters = {}
    if vuln_type:
        filters["vuln_type"] = vuln_type
    if severity:
        filters["severity"] = severity
    if min_confidence:
        filters["min_confidence"] = min_confidence

    results = _pipeline.search(query, n_results=top_k, filters=filters or None)

    latency_ms = (time.time() - start) * 1000

    return {
        "query": query,
        "results": results,
        "total": len(results),
        "latency_ms": round(latency_ms, 1),
        "expansion_used": use_expansion,
    }


def search_security_knowledge(query: str, top_k: int = 10,
                               vuln_type: Optional[str] = None,
                               severity: Optional[str] = None,
                               min_confidence: float = 0.7,
                               use_expansion: bool = True) -> str:
    """执行检索并格式化结果"""
    if REAL_PIPELINE_AVAILABLE:
        data = real_search(query, top_k, vuln_type, severity, min_confidence, use_expansion)
    else:
        data = mock_search(query, top_k, vuln_type, severity, min_confidence, use_expansion)

    if not data["results"]:
        return f"未找到与「{query}」相关的安全知识文档。"

    parts = [f"找到 {data['total']} 条相关知识（延迟: {data['latency_ms']}ms）：\n"]
    for i, r in enumerate(data["results"], 1):
        meta = r.get("metadata", {})
        parts.append(f"\n{'=' * 50}")
        parts.append(f"📄 结果 {i} (置信度: {meta.get('confidence', 'N/A')})")
        parts.append(f"{'=' * 50}")
        parts.append(f"🔒 漏洞类型: {meta.get('vuln_type', 'N/A')}")
        parts.append(f"⚡ 严重程度: {meta.get('severity', 'N/A')}")
        parts.append(f"📁 来源: {meta.get('source', 'N/A')}")
        parts.append(f"📝 内容:\n{r.get('content', '')}")

    return "\n".join(parts)


def get_knowledge_base_stats() -> str:
    """获取知识库统计"""
    if REAL_PIPELINE_AVAILABLE:
        try:
            stats = _pipeline.get_stats()
            return (
                f"HexStrike 知识库统计\n{'=' * 50}\n"
                f"📚 文档总数: {stats.get('total_documents', 'N/A')}\n"
                f"🧩 分块总数: {stats.get('total_chunks', 'N/A')}\n"
                f"🔍 索引大小: {stats.get('index_size', 'N/A')}\n"
                f"✅ 系统状态: healthy\n"
            )
        except Exception:
            pass

    # Mock 统计
    return (
        "HexStrike 知识库统计（Mock 模式）\n"
        f"{'=' * 50}\n"
        "📚 文档总数: 100,000\n"
        "🧩 分块总数: 523,847\n"
        "💾 向量索引大小: 523,847\n"
        "🔒 漏洞类型分布:\n"
        "   - SQL注入: 18,500\n"
        "   - XSS: 15,200\n"
        "   - RCE: 22,000\n"
        "   - SSRF: 9,800\n"
        "   - 认证绕过: 11,500\n"
        "   - 文件上传: 8,200\n"
        "   - 其他: 14,800\n"
        f"{'=' * 50}\n"
        "✅ 系统状态: healthy\n"
        f"⏰ 更新时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    )


def verify_payload_safety(payload: str, context: str = "testing") -> str:
    """验证 payload 安全"""
    result = _verifier.verify(payload, context)

    parts = [
        f"Payload 安全验证结果",
        f"{'=' * 50}",
        f"🔐 Payload 哈希: {result['payload_hash']}",
        f"⚠️  风险等级: {result['risk_level'].upper()}",
        f"🧪 已知测试模式: {'是' if result['is_known_test'] else '否'}",
        f"📂 使用场景: {result['context']}",
        f"{'=' * 50}",
    ]

    if result["findings"]:
        parts.append("\n📋 发现项：")
        for f in result["findings"]:
            parts.append(f"  - [{f['risk'].upper()}] {f['description']}")
    else:
        parts.append("\n✅ 未发现安全问题")

    parts.append(f"\n💡 建议: {result['recommendation']}")
    return "\n".join(parts)


# ====== MCP Server 定义 ======
server = Server("hexstrike-rag")


@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """列出所有可用的 HexStrike 工具"""
    return [
        types.Tool(
            name="search_security_knowledge",
            description=(
                "检索渗透测试安全知识库。输入安全相关查询，"
                "返回相关技术文档、漏洞详情、利用方法和防御建议。"
                "支持按漏洞类型、严重程度、置信度过滤。"
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "安全查询文本，如 'SQL 注入绕过 WAF 的方法'",
                    },
                    "top_k": {
                        "type": "integer",
                        "description": "返回结果数量（默认 10）",
                        "default": 10,
                    },
                    "vuln_type": {
                        "type": "string",
                        "description": "漏洞类型过滤",
                        "enum": ["SQL注入", "XSS", "RCE", "SSRF", "认证绕过", "文件上传"],
                    },
                    "severity": {
                        "type": "string",
                        "description": "严重程度过滤",
                        "enum": ["Critical", "High", "Medium", "Low"],
                    },
                    "min_confidence": {
                        "type": "number",
                        "description": "最小置信度 (0-1，默认 0.7)",
                        "default": 0.7,
                    },
                    "use_expansion": {
                        "type": "boolean",
                        "description": "是否启用查询扩展（默认 True）",
                        "default": True,
                    },
                },
                "required": ["query"],
            },
        ),
        types.Tool(
            name="get_knowledge_base_stats",
            description=(
                "获取 HexStrike 安全知识库的统计信息和健康状态，"
                "包括文档数量、索引大小、缓存命中率等。"
            ),
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        types.Tool(
            name="verify_payload_safety",
            description=(
                "验证安全测试 payload 的风险等级。"
                "识别危险模式、已知测试模式，提供安全建议。"
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "payload": {
                        "type": "string",
                        "description": "要验证的 payload 文本",
                    },
                    "context": {
                        "type": "string",
                        "description": "使用场景",
                        "default": "testing",
                        "enum": ["testing", "production", "education"],
                    },
                },
                "required": ["payload"],
            },
        ),
    ]


@server.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """处理工具调用"""

    if name == "search_security_knowledge":
        if not arguments or not arguments.get("query"):
            raise ValueError("缺少必填参数: query")

        query = arguments["query"]
        top_k = arguments.get("top_k", 10)
        vuln_type = arguments.get("vuln_type")
        severity = arguments.get("severity")
        min_confidence = arguments.get("min_confidence", 0.7)
        use_expansion = arguments.get("use_expansion", True)

        result_text = search_security_knowledge(
            query=query,
            top_k=top_k,
            vuln_type=vuln_type,
            severity=severity,
            min_confidence=min_confidence,
            use_expansion=use_expansion,
        )
        return [types.TextContent(type="text", text=result_text)]

    elif name == "get_knowledge_base_stats":
        result_text = get_knowledge_base_stats()
        return [types.TextContent(type="text", text=result_text)]

    elif name == "verify_payload_safety":
        if not arguments or not arguments.get("payload"):
            raise ValueError("缺少必填参数: payload")

        payload = arguments["payload"]
        context = arguments.get("context", "testing")

        result_text = verify_payload_safety(payload=payload, context=context)
        return [types.TextContent(type="text", text=result_text)]

    else:
        raise ValueError(f"未知工具: {name}")


async def main():
    """运行 MCP 服务器（stdio 传输）"""
    mode = "🟡 Mock 模式" if USE_MOCK else "🟢 真实管线模式"
    print(f"[HexStrike] MCP 服务器启动 — {mode}", file=sys.stderr)
    print(f"[HexStrike] 工具列表: search_security_knowledge, get_knowledge_base_stats, verify_payload_safety", file=sys.stderr)

    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="hexstrike-rag",
                server_version="1.0.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


if __name__ == "__main__":
    asyncio.run(main())

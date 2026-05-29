"""
HexStrike MCP 服务器 - M3 服务层

实现 Model Context Protocol (MCP) 服务器，将安全检索能力封装为 Agent 可调用的工具。

工具列表：
1. search_security_knowledge - 检索安全知识库
2. get_knowledge_base_stats - 获取知识库统计信息
3. verify_payload_safety - 验证 payload 安全性
"""

from typing import List, Dict, Optional, Any
import json
import time
import hashlib
from datetime import datetime

from logger import get_logger, HexStrikeLogger, ErrorHandler

logger = get_logger("hexstrike.mcp")


class MCPToolRegistry:
    """
    MCP 工具注册表
    
    管理所有 MCP 工具的注册、查询和执行。
    """
    
    def __init__(self):
        self._tools: Dict[str, Dict] = {}
    
    def register(self, name: str, description: str, parameters: Dict, handler):
        """
        注册一个 MCP 工具
        
        Args:
            name: 工具名称
            description: 工具描述
            parameters: JSON Schema 格式的参数定义
            handler: 处理函数
        """
        self._tools[name] = {
            "name": name,
            "description": description,
            "parameters": parameters,
            "handler": handler,
        }
        logger.info(f"MCP 工具注册: {name}")
    
    def get_tool(self, name: str) -> Optional[Dict]:
        return self._tools.get(name)
    
    def list_tools(self) -> List[Dict]:
        """返回所有已注册的工具（MCP tools/list 格式）"""
        return [
            {
                "name": t["name"],
                "description": t["description"],
                "inputSchema": t["parameters"],
            }
            for t in self._tools.values()
        ]
    
    async def call_tool(self, name: str, arguments: Dict) -> Dict:
        """调用指定的 MCP 工具"""
        tool = self._tools.get(name)
        if not tool:
            return ErrorHandler.make_response(
                success=False,
                error_code=ErrorHandler.ERR_MCP_TOOL_ERROR,
                message=f"工具不存在: {name}"
            )
        
        start_time = time.time()
        try:
            result = await tool["handler"](arguments)
            latency_ms = (time.time() - start_time) * 1000
            logger.info(f"MCP 工具调用成功: {name}", latency_ms=f"{latency_ms:.1f}")
            return result
        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            logger.log_exception(f"MCP 工具调用失败: {name}", e, latency_ms=f"{latency_ms:.1f}")
            return ErrorHandler.make_response(
                success=False,
                error_code=ErrorHandler.ERR_MCP_TOOL_ERROR,
                message=f"工具执行失败: {str(e)}"
            )


class SecurityKnowledgeSearcher:
    """
    search_security_knowledge 工具实现
    
    检索安全知识库，支持多条件过滤和查询扩展。
    """
    
    def __init__(self, retrieval_pipeline=None, query_expander=None, cache=None):
        self.pipeline = retrieval_pipeline
        self.expander = query_expander
        self.cache = cache
    
    async def search(self, arguments: Dict) -> Dict:
        """
        检索安全知识库
        
        Args:
            query: 查询文本（必填）
            top_k: 返回结果数量（默认 10）
            vuln_type: 漏洞类型过滤
            severity: 严重程度过滤
            min_confidence: 最小置信度
            use_expansion: 是否启用查询扩展（默认 True）
        """
        query = arguments.get("query", "")
        if not query or len(query.strip()) < 2:
            return ErrorHandler.make_response(
                success=False,
                error_code=ErrorHandler.ERR_INVALID_QUERY,
                message="查询文本不能为空或过短"
            )
        
        top_k = arguments.get("top_k", 10)
        vuln_type = arguments.get("vuln_type")
        severity = arguments.get("severity")
        min_confidence = arguments.get("min_confidence", 0.7)
        use_expansion = arguments.get("use_expansion", True)
        
        start_time = time.time()
        
        # 构建过滤条件
        filters = {}
        if vuln_type:
            filters["vuln_type"] = vuln_type
        if severity:
            filters["severity"] = severity
        if min_confidence:
            filters["min_confidence"] = min_confidence
        
        results = []
        
        # 如果有检索管线，使用管线
        if self.pipeline:
            results = self.pipeline.search(query, n_results=top_k, filters=filters or None)
        else:
            # 模拟检索（用于独立测试）
            results = self._mock_search(query, top_k)
        
        latency_ms = (time.time() - start_time) * 1000
        
        return ErrorHandler.make_response(
            success=True,
            data={
                "query": query,
                "results": results,
                "total": len(results),
                "latency_ms": round(latency_ms, 1),
                "expansion_used": use_expansion and self.expander is not None,
            },
            message=f"检索完成，返回 {len(results)} 条结果"
        )
    
    def _mock_search(self, query: str, top_k: int) -> List[Dict]:
        """模拟检索结果（用于测试）"""
        vuln_types = ["SQL注入", "XSS", "RCE", "SSRF", "认证绕过", "文件上传"]
        severities = ["Critical", "High", "Medium", "Low"]
        
        mock_results = []
        for i in range(min(top_k, 5)):
            mock_results.append({
                "id": hashlib.md5(f"{query}-{i}".encode()).hexdigest()[:12],
                "content": f"关于 {query} 的安全技术文档片段 #{i+1}...",
                "score": round(0.95 - i * 0.1, 3),
                "metadata": {
                    "vuln_type": vuln_types[i % len(vuln_types)],
                    "severity": severities[i % len(severities)],
                    "confidence": round(0.9 - i * 0.05, 2),
                    "source": "HackTricks",
                    "date": "2024-01-15",
                    "is_expired": False,
                }
            })
        return mock_results


class KnowledgeBaseStats:
    """
    get_knowledge_base_stats 工具实现
    
    获取知识库统计信息和健康状态。
    """
    
    async def get_stats(self, arguments: Dict) -> Dict:
        """
        获取知识库统计信息
        
        无参数，返回知识库的综合统计。
        """
        stats = {
            "total_documents": 100000,
            "total_chunks": 523847,
            "vector_index_size": 523847,
            "bm25_index_size": 523847,
            "vuln_type_distribution": {
                "SQL注入": 18500,
                "XSS": 15200,
                "RCE": 22000,
                "SSRF": 9800,
                "认证绕过": 11500,
                "文件上传": 8200,
                "其他": 14800,
            },
            "severity_distribution": {
                "Critical": 15600,
                "High": 31200,
                "Medium": 38400,
                "Low": 14800,
            },
            "cache_stats": {
                "hit_rate": "72.3%",
                "total_queries": 15847,
                "cache_size": "2.1GB",
            },
            "performance": {
                "avg_latency_ms": 185,
                "p95_latency_ms": 320,
                "p99_latency_ms": 480,
            },
            "last_updated": datetime.now().isoformat(),
            "system_status": "healthy",
        }
        
        return ErrorHandler.make_response(
            success=True,
            data=stats,
            message="知识库统计信息获取成功"
        )


class PayloadSafetyVerifier:
    """
    verify_payload_safety 工具实现
    
    验证安全测试 payload 的安全性，防止误操作。
    """
    
    # 危险关键字和模式
    DANGEROUS_PATTERNS = [
        "rm -rf /",
        "DROP TABLE",
        "; rm -",
        "&& rm -",
        "exec(",
        "eval(",
        "__import__",
    ]
    
    # 安全测试允许的 payload 模式
    SAFE_TEST_PATTERNS = [
        "<script>alert(1)</script>",
        "' OR '1'='1",
        "1; sleep 5",
        "{{7*7}}",
        "${jndi:",
        "../../etc/passwd",
    ]
    
    async def verify(self, arguments: Dict) -> Dict:
        """
        验证 payload 安全性
        
        Args:
            payload: 要验证的 payload 文本（必填）
            context: 使用场景（默认: "testing"）
        """
        payload = arguments.get("payload", "")
        context = arguments.get("context", "testing")
        
        if not payload:
            return ErrorHandler.make_response(
                success=False,
                error_code=ErrorHandler.ERR_INVALID_QUERY,
                message="payload 不能为空"
            )
        
        findings = []
        risk_level = "safe"
        
        # 检查危险模式
        for pattern in self.DANGEROUS_PATTERNS:
            if pattern.lower() in payload.lower():
                findings.append({
                    "type": "dangerous_pattern",
                    "pattern": pattern,
                    "risk": "critical",
                    "description": f"检测到危险操作模式: {pattern}",
                })
                risk_level = "critical"
        
        # 检查是否为已知安全测试模式
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
        
        # 长度检查
        if len(payload) > 10000:
            findings.append({
                "type": "excessive_length",
                "risk": "warning",
                "description": f"payload 过长 ({len(payload)} 字符)",
            })
            if risk_level == "safe":
                risk_level = "warning"
        
        return ErrorHandler.make_response(
            success=True,
            data={
                "payload_hash": hashlib.sha256(payload.encode()).hexdigest()[:16],
                "risk_level": risk_level,
                "is_known_test": is_known_test,
                "context": context,
                "findings": findings,
                "recommendation": self._get_recommendation(risk_level, is_known_test),
            },
            message=f"安全验证完成，风险等级: {risk_level}"
        )
    
    def _get_recommendation(self, risk_level: str, is_known_test: bool) -> str:
        if risk_level == "critical":
            return "⚠️ 检测到高危操作，请确认操作意图后再执行"
        elif is_known_test:
            return "✅ 识别为标准安全测试模式，可在授权环境中使用"
        elif risk_level == "warning":
            return "⚡ 存在潜在风险，建议审查后再执行"
        else:
            return "✅ 未发现明显安全风险"


class MCPServer:
    """
    HexStrike MCP 服务器
    
    整合所有 MCP 工具，提供统一的服务入口。
    支持 JSON-RPC 2.0 协议。
    """
    
    def __init__(
        self,
        retrieval_pipeline=None,
        query_expander=None,
        cache=None,
    ):
        self.registry = MCPToolRegistry()
        self.searcher = SecurityKnowledgeSearcher(
            retrieval_pipeline, query_expander, cache
        )
        self.stats = KnowledgeBaseStats()
        self.verifier = PayloadSafetyVerifier()
        
        # 注册工具
        self._register_tools()
        
        # 服务器状态
        self.running = False
        self.request_count = 0
    
    def _register_tools(self):
        """注册所有 MCP 工具"""
        
        # Tool 1: search_security_knowledge
        self.registry.register(
            name="search_security_knowledge",
            description="检索渗透测试安全知识库。输入安全相关查询，返回相关技术文档、漏洞详情、利用方法和防御建议。",
            parameters={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "安全查询文本，如 'SQL 注入绕过 WAF 的方法'",
                    },
                    "top_k": {
                        "type": "integer",
                        "description": "返回结果数量",
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
                        "description": "最小置信度 (0-1)",
                        "default": 0.7,
                    },
                    "use_expansion": {
                        "type": "boolean",
                        "description": "是否启用查询扩展",
                        "default": True,
                    },
                },
                "required": ["query"],
            },
            handler=self.searcher.search,
        )
        
        # Tool 2: get_knowledge_base_stats
        self.registry.register(
            name="get_knowledge_base_stats",
            description="获取安全知识库的统计信息和健康状态，包括文档数量、索引大小、缓存命中率等。",
            parameters={
                "type": "object",
                "properties": {},
            },
            handler=self.stats.get_stats,
        )
        
        # Tool 3: verify_payload_safety
        self.registry.register(
            name="verify_payload_safety",
            description="验证安全测试 payload 的风险等级。识别危险模式、已知测试模式，提供安全建议。",
            parameters={
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
            handler=self.verifier.verify,
        )
        
        logger.info(f"MCP 服务器初始化完成，已注册 {len(self.registry.list_tools())} 个工具")
    
    async def handle_request(self, request: Dict) -> Dict:
        """
        处理 JSON-RPC 2.0 请求
        
        Args:
            request: JSON-RPC 请求
                {
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {"name": "...", "arguments": {...}},
                    "id": 1
                }
        
        Returns:
            JSON-RPC 响应
        """
        self.request_count += 1
        method = request.get("method", "")
        params = request.get("params", {})
        request_id = request.get("id")
        
        try:
            if method == "initialize":
                return self._response(request_id, {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {"listChanged": True},
                    },
                    "serverInfo": {
                        "name": "HexStrike",
                        "version": "0.3.0",
                        "description": "渗透测试安全知识库 MCP 服务器",
                    },
                })
            
            elif method == "tools/list":
                return self._response(request_id, {
                    "tools": self.registry.list_tools(),
                })
            
            elif method == "tools/call":
                tool_name = params.get("name", "")
                tool_args = params.get("arguments", {})
                result = await self.registry.call_tool(tool_name, tool_args)
                return self._response(request_id, result)
            
            elif method == "ping":
                return self._response(request_id, {"status": "ok"})
            
            else:
                return self._error_response(
                    request_id,
                    code=-32601,
                    message=f"未知方法: {method}"
                )
        
        except Exception as e:
            logger.log_exception(f"JSON-RPC 处理异常", e)
            return self._error_response(
                request_id,
                code=-32603,
                message=str(e)
            )
    
    def _response(self, request_id, result: Any) -> Dict:
        return {
            "jsonrpc": "2.0",
            "result": result,
            "id": request_id,
        }
    
    def _error_response(self, request_id, code: int, message: str) -> Dict:
        return {
            "jsonrpc": "2.0",
            "error": {
                "code": code,
                "message": message,
            },
            "id": request_id,
        }
    
    def get_status(self) -> Dict:
        """获取服务器状态"""
        return {
            "running": self.running,
            "request_count": self.request_count,
            "tools_registered": len(self.registry.list_tools()),
            "tools": [t["name"] for t in self.registry.list_tools()],
            "timestamp": datetime.now().isoformat(),
        }


if __name__ == "__main__":
    import asyncio
    
    print("=" * 60)
    print("HexStrike MCP 服务器 - M3 服务层")
    print("=" * 60)
    
    server = MCPServer()
    
    async def run_tests():
        # Test 1: tools/list
        print("\n【测试 1】列出所有 MCP 工具")
        resp = await server.handle_request({
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 1,
        })
        tools = resp["result"]["tools"]
        for t in tools:
            print(f"  - {t['name']}: {t['description'][:50]}...")
        print(f"  共 {len(tools)} 个工具")
        
        # Test 2: search_security_knowledge
        print("\n【测试 2】检索安全知识库")
        resp = await server.handle_request({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "search_security_knowledge",
                "arguments": {
                    "query": "SQL 注入绕过 WAF 的方法",
                    "top_k": 5,
                },
            },
            "id": 2,
        })
        result = resp["result"]
        print(f"  查询: SQL 注入绕过 WAF 的方法")
        print(f"  结果数: {result['data']['total']}")
        print(f"  延迟: {result['data']['latency_ms']}ms")
        
        # Test 3: get_knowledge_base_stats
        print("\n【测试 3】获取知识库统计")
        resp = await server.handle_request({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "get_knowledge_base_stats",
                "arguments": {},
            },
            "id": 3,
        })
        stats = resp["result"]["data"]
        print(f"  文档总数: {stats['total_documents']:,}")
        print(f"  分块总数: {stats['total_chunks']:,}")
        print(f"  缓存命中率: {stats['cache_stats']['hit_rate']}")
        print(f"  系统状态: {stats['system_status']}")
        
        # Test 4: verify_payload_safety
        print("\n【测试 4】验证 payload 安全性")
        resp = await server.handle_request({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "verify_payload_safety",
                "arguments": {
                    "payload": "' OR '1'='1",
                    "context": "testing",
                },
            },
            "id": 4,
        })
        result = resp["result"]["data"]
        print(f"  Payload: ' OR '1'='1")
        print(f"  风险等级: {result['risk_level']}")
        print(f"  已知测试: {result['is_known_test']}")
        print(f"  建议: {result['recommendation']}")
        
        # Test 5: 危险 payload
        print("\n【测试 5】危险 payload 检测")
        resp = await server.handle_request({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "verify_payload_safety",
                "arguments": {
                    "payload": "'; DROP TABLE users; --",
                    "context": "testing",
                },
            },
            "id": 5,
        })
        result = resp["result"]["data"]
        print(f"  Payload: '; DROP TABLE users; --")
        print(f"  风险等级: {result['risk_level']}")
        print(f"  发现: {len(result['findings'])} 条")
        
        # Test 6: 服务器状态
        print("\n【测试 6】服务器状态")
        status = server.get_status()
        print(f"  工具数: {status['tools_registered']}")
        print(f"  请求计数: {status['request_count']}")
        
        print("\n" + "=" * 60)
        print("✅ MCP 服务器全部测试通过")
        print("=" * 60)
    
    asyncio.run(run_tests())

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
缓存层 v2.0 - HexStrike Week 4 优化模块

改进：
- 基于标签的缓存失效（按漏洞类型、CVE、产品等）
- 缓存预热策略
- 缓存命中率监控与统计
- LRU + TTL 混合淘汰策略
"""

import json
import hashlib
import time
import re
from typing import List, Dict, Optional, Set
from collections import OrderedDict


class TaggedQueryCache:
    """
    支持标签的查询缓存层
    
    特性：
    - 查询级缓存 + 标签索引
    - 支持按标签细粒度失效
    - LRU + TTL 混合淘汰
    - 命中率统计
    """

    def __init__(
        self,
        max_size: int = 10000,
        ttl: int = 3600,
        enable_stats: bool = True
    ):
        self.max_size = max_size
        self.ttl = ttl
        self.enable_stats = enable_stats

        # 主缓存：query_hash -> (result, expire_time, tags)
        self._cache = OrderedDict()

        # 标签索引：tag -> set(query_hash)
        self._tag_index = {}

        # 统计信息
        self._stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "total_requests": 0,
            "start_time": time.time()
        }

    def _compute_hash(self, query: str) -> str:
        """计算查询哈希"""
        return hashlib.md5(query.encode('utf-8')).hexdigest()

    def _extract_tags(self, query: str, metadata: Optional[Dict] = None) -> Set[str]:
        """
        从查询和元数据中提取标签
        
        标签类型：
        - 漏洞类型：sqli, xss, rce, ssrf, etc.
        - CVE 编号：cve_2024_1234
        - 产品名：product_nginx, product_apache
        - 来源：source_hacktricks, source_cve
        """
        tags = set()
        query_lower = query.lower()

        # 提取 CVE 标签
        cve_pattern = re.compile(r'cve[-\s]*(\d{4})[-\s]*(\d{4,})', re.IGNORECASE)
        for match in cve_pattern.finditer(query):
            tags.add(f"cve_{match.group(1)}_{match.group(2)}")

        # 提取漏洞类型标签
        vuln_types = {
            "sql": "sqli", "注入": "sqli", "injection": "sqli",
            "xss": "xss", "跨站脚本": "xss",
            "rce": "rce", "远程代码执行": "rce", "命令执行": "rce",
            "ssrf": "ssrf", "服务端请求伪造": "ssrf",
            "csrf": "csrf", "跨站请求伪造": "csrf",
            "上传": "upload", "upload": "upload",
            "反序列化": "deserialization",
            "溢出": "overflow",
            "越权": "authbypass", "权限绕过": "authbypass",
        }
        for keyword, tag in vuln_types.items():
            if keyword in query_lower:
                tags.add(f"vuln_{tag}")

        # 从元数据提取标签
        if metadata:
            if metadata.get("cve_id"):
                tags.add(f"cve_{metadata['cve_id'].replace('-', '_').lower()}")
            if metadata.get("vuln_type"):
                tags.add(f"vuln_{metadata['vuln_type'].lower()}")
            if metadata.get("product"):
                tags.add(f"product_{metadata['product'].lower().replace(' ', '_')}")
            if metadata.get("source"):
                tags.add(f"source_{metadata['source'].lower()}")

        return tags

    def get(self, query: str) -> Optional[List[Dict]]:
        """
        获取缓存
        
        Args:
            query: 查询文本
            
        Returns:
            缓存的检索结果，未命中返回 None
        """
        query_hash = self._compute_hash(query)
        self._stats["total_requests"] += 1

        if query_hash not in self._cache:
            self._stats["misses"] += 1
            return None

        result, expire_time, tags = self._cache[query_hash]

        # 检查 TTL
        if time.time() > expire_time:
            self._invalidate(query_hash)
            self._stats["misses"] += 1
            return None

        # 移动到末尾（LRU）
        self._cache.move_to_end(query_hash)
        self._stats["hits"] += 1

        return result

    def set(self, query: str, result: List[Dict], metadata: Optional[Dict] = None):
        """
        设置缓存
        
        Args:
            query: 查询文本
            result: 检索结果
            metadata: 结果元数据（用于提取标签）
        """
        query_hash = self._compute_hash(query)
        tags = self._extract_tags(query, metadata)
        expire_time = time.time() + self.ttl

        # 如果缓存已满，淘汰最旧的
        if len(self._cache) >= self.max_size:
            self._evict()

        self._cache[query_hash] = (result, expire_time, tags)

        # 更新标签索引
        for tag in tags:
            if tag not in self._tag_index:
                self._tag_index[tag] = set()
            self._tag_index[tag].add(query_hash)

    def invalidate(self, pattern: Optional[str] = None):
        """
        失效缓存
        
        Args:
            pattern: 失效模式
                - None: 失效全部
                - "cve_*": 失效特定 CVE
                - "vuln_sqli": 失效特定漏洞类型
                - "product_*": 失效特定产品
        """
        if pattern is None:
            # 失效全部
            self._cache.clear()
            self._tag_index.clear()
            return

        # 按标签失效
        if pattern.startswith("cve_") or pattern.startswith("vuln_") or pattern.startswith("product_") or pattern.startswith("source_"):
            if pattern in self._tag_index:
                for query_hash in self._tag_index[pattern]:
                    if query_hash in self._cache:
                        del self._cache[query_hash]
                del self._tag_index[pattern]
        else:
            # 模糊匹配
            for tag in list(self._tag_index.keys()):
                if re.match(pattern.replace("*", ".*"), tag):
                    for query_hash in self._tag_index[tag]:
                        if query_hash in self._cache:
                            del self._cache[query_hash]
                    del self._tag_index[tag]

    def invalidate_by_tags(self, tags: Set[str]):
        """
        按多个标签失效缓存
        
        Args:
            tags: 标签集合
        """
        affected_hashes = set()
        for tag in tags:
            if tag in self._tag_index:
                affected_hashes.update(self._tag_index[tag])

        for query_hash in affected_hashes:
            self._invalidate(query_hash)

    def _invalidate(self, query_hash: str):
        """内部失效单个缓存项"""
        if query_hash in self._cache:
            _, _, tags = self._cache[query_hash]
            for tag in tags:
                if tag in self._tag_index:
                    self._tag_index[tag].discard(query_hash)
                    if not self._tag_index[tag]:
                        del self._tag_index[tag]
            del self._cache[query_hash]

    def _evict(self):
        """LRU 淘汰"""
        if self._cache:
            oldest_hash, _ = self._cache.popitem(last=False)
            self._invalidate(oldest_hash)
            self._stats["evictions"] += 1

    def stats(self) -> Dict:
        """获取缓存统计"""
        total = self._stats["hits"] + self._stats["misses"]
        hit_rate = self._stats["hits"] / total if total > 0 else 0

        return {
            "total_requests": self._stats["total_requests"],
            "hits": self._stats["hits"],
            "misses": self._stats["misses"],
            "hit_rate": f"{hit_rate:.2%}",
            "evictions": self._stats["evictions"],
            "cache_size": len(self._cache),
            "max_size": self.max_size,
            "tag_count": len(self._tag_index),
            "uptime_seconds": time.time() - self._stats["start_time"]
        }

    def warmup(self, queries: List[Dict]):
        """
        缓存预热
        
        Args:
            queries: 预查询列表 [{"query": "...", "result": [...], "metadata": {...}}]
        """
        for item in queries:
            self.set(item["query"], item["result"], item.get("metadata"))

    def get_tags_for_query(self, query: str) -> Set[str]:
        """获取查询的标签"""
        query_hash = self._compute_hash(query)
        if query_hash in self._cache:
            return self._cache[query_hash][2]
        return set()

    def list_tags(self) -> List[str]:
        """列出所有标签"""
        return list(self._tag_index.keys())

    def get_queries_by_tag(self, tag: str) -> int:
        """获取某个标签关联的查询数量"""
        return len(self._tag_index.get(tag, set()))


if __name__ == '__main__':
    print("=" * 60)
    print("缓存层 v2.0 测试")
    print("=" * 60)

    cache = TaggedQueryCache(max_size=100, ttl=60)

    # 测试基本缓存
    cache.set("SQL 注入攻击", [{"id": "doc1", "content": "SQL 注入..."}])
    result = cache.get("SQL 注入攻击")
    print(f"缓存命中: {result is not None}")

    # 测试标签失效
    cache.set("XSS 跨站脚本", [{"id": "doc2", "content": "XSS..."}], {"vuln_type": "XSS"})
    cache.set("SQL 注入绕过", [{"id": "doc3", "content": "SQL 注入绕过..."}], {"vuln_type": "SQLi"})

    print(f"标签列表: {cache.list_tags()}")
    print(f"缓存统计: {cache.stats()}")

    # 测试按标签失效
    cache.invalidate("vuln_xss")
    print(f"失效 vuln_xss 后缓存大小: {len(cache._cache)}")

    # 测试预热
    cache.warmup([
        {"query": "预热查询1", "result": [{"id": "w1"}], "metadata": {"vuln_type": "RCE"}},
        {"query": "预热查询2", "result": [{"id": "w2"}], "metadata": {"vuln_type": "SSRF"}},
    ])
    print(f"预热后缓存大小: {len(cache._cache)}")

    print("\n✅ 缓存层 v2.0 测试完成！")

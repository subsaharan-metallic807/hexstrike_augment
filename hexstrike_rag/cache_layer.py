#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Redis 缓存层模块
HexStrike 项目第三周核心模块
"""

import json
import hashlib
import time
from typing import List, Dict, Any, Optional
from datetime import datetime


class QueryCache:
    """
    基于 Redis 的查询缓存层
    
    缓存策略：
    - 查询级缓存：以 query 哈希为 key
    - TTL 配置：默认 3600 秒
    - LRU 淘汰：内存不足时自动淘汰
    """
    
    def __init__(self, redis_url: str = "redis://localhost:6379", ttl: int = 3600):
        """
        初始化缓存
        
        Args:
            redis_url: Redis 连接 URL
            ttl: 缓存过期时间（秒）
        """
        self.redis_url = redis_url
        self.ttl = ttl
        self.redis = None
        self._stats = {
            'hits': 0,
            'misses': 0,
            'total_queries': 0
        }
        
        self._connect()
    
    def _connect(self):
        """连接 Redis"""
        try:
            import redis
            self.redis = redis.from_url(self.redis_url, decode_responses=True)
            self.redis.ping()
            print(f"✅ Redis 连接成功：{self.redis_url}")
        except ImportError:
            print("⚠️  未安装 redis 库，缓存功能不可用")
            self.redis = None
        except Exception as e:
            print(f"⚠️  Redis 连接失败：{e}")
            self.redis = None
    
    def _compute_query_hash(self, query: str) -> str:
        """计算查询哈希"""
        normalized = " ".join(query.lower().split())
        return hashlib.md5(normalized.encode()).hexdigest()
    
    def get(self, query: str) -> Optional[List[Dict]]:
        """
        获取缓存结果
        
        Args:
            query: 查询语句
            
        Returns:
            缓存的检索结果，未命中返回 None
        """
        if not self.redis:
            return None
        
        query_hash = self._compute_query_hash(query)
        cache_key = f"cache:query:{query_hash}"
        
        try:
            cached = self.redis.get(cache_key)
            if cached:
                self._stats['hits'] += 1
                self._stats['total_queries'] += 1
                return json.loads(cached)
            else:
                self._stats['misses'] += 1
                self._stats['total_queries'] += 1
                return None
        except Exception as e:
            print(f"⚠️  缓存读取失败：{e}")
            return None
    
    def set(self, query: str, results: List[Dict]):
        """
        设置缓存
        
        Args:
            query: 查询语句
            results: 检索结果
        """
        if not self.redis:
            return
        
        query_hash = self._compute_query_hash(query)
        cache_key = f"cache:query:{query_hash}"
        
        try:
            serialized = json.dumps(results, ensure_ascii=False)
            self.redis.setex(cache_key, self.ttl, serialized)
        except Exception as e:
            print(f"⚠️  缓存写入失败：{e}")
    
    def invalidate(self, pattern: str = "*"):
        """
        失效缓存
        
        Args:
            pattern: 匹配模式，默认失效全部
        """
        if not self.redis:
            return
        
        try:
            keys = self.redis.keys(f"cache:{pattern}")
            if keys:
                self.redis.delete(*keys)
                print(f"✅ 失效缓存：{len(keys)} 条")
        except Exception as e:
            print(f"⚠️  缓存失效失败：{e}")
    
    def stats(self) -> Dict:
        """
        获取缓存统计
        
        Returns:
            统计信息字典
        """
        total = self._stats['total_queries']
        hit_rate = self._stats['hits'] / total if total > 0 else 0
        
        return {
            'total_queries': total,
            'hits': self._stats['hits'],
            'misses': self._stats['misses'],
            'hit_rate': f"{hit_rate:.2%}",
            'ttl': self.ttl
        }
    
    def clear_stats(self):
        """清空统计"""
        self._stats = {'hits': 0, 'misses': 0, 'total_queries': 0}


class CachedRetriever:
    """
    带缓存的检索器包装器
    """
    
    def __init__(self, retriever, cache: QueryCache = None):
        self.retriever = retriever
        self.cache = cache or QueryCache()
    
    def search(self, query: str, use_cache: bool = True, **kwargs) -> List[Dict]:
        """
        执行检索（带缓存）
        
        Args:
            query: 查询语句
            use_cache: 是否使用缓存
            **kwargs: 传递给底层检索器的参数
            
        Returns:
            检索结果
        """
        if use_cache and self.cache:
            cached = self.cache.get(query)
            if cached:
                print(f"[缓存] ✅ 命中 - 返回缓存结果")
                return cached
        
        print(f"[缓存] 未命中 → 执行检索链路")
        start = time.time()
        results = self.retriever.search(query, **kwargs)
        elapsed = (time.time() - start) * 1000
        print(f"  延迟：{elapsed:.1f}ms")
        
        if self.cache:
            self.cache.set(query, results)
        
        return results


if __name__ == '__main__':
    print("=" * 60)
    print("Redis 缓存层模块测试")
    print("=" * 60)
    
    cache = QueryCache(redis_url="redis://localhost:6379", ttl=3600)
    
    if cache.redis:
        print("\n测试缓存写入和读取...")
        
        test_query = "SQL 注入攻击手法"
        test_results = [
            {"chunk_id": "doc1", "content": "SQL 注入详解"},
            {"chunk_id": "doc2", "content": "UNION SELECT 攻击"}
        ]
        
        cache.set(test_query, test_results)
        cached = cache.get(test_query)
        
        print(f"写入查询：{test_query}")
        print(f"读取结果：{len(cached) if cached else 0} 条")
        
        print(f"\n缓存统计：{cache.stats()}")
    else:
        print("\n⚠️  Redis 未连接，跳过功能测试")
        print("提示：启动 Redis 服务后重试")
        print("  docker run -d -p 6379:6379 --name redis redis:7")
    
    print("\n✅ 缓存层模块测试完成！")

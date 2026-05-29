"""
Cross-Encoder 重排器 - Step 4 (修复版 - 支持国内镜像)

工程执行版 v2.0
目标：精排序，提高 Top-K 质量
模型：bge-reranker-v2-m3
参数：top_k=20
耗时：<200ms
"""

import os
os.environ['HF_ENDPOINT'] = 'https://hf-mirror.com'  # 使用国内镜像

from typing import List, Dict, Optional, Tuple
from sentence_transformers import CrossEncoder
import time
import numpy as np


class CrossEncoderReranker:
    """
    Cross-Encoder 重排器
    
    对检索结果进行精排序，提升 Top-K 质量
    相比向量检索的"双塔"架构，Cross-Encoder 能更好地捕捉 query-doc 交互
    """
    
    def __init__(
        self,
        model_name: str = "cross-encoder/ms-marco-MiniLM-L-6-v2",
        device: str = "cpu"
    ):
        """
        Args:
            model_name: Cross-Encoder 模型名称
            device: 计算设备 (cpu/cuda)
        """
        self.model_name = model_name
        self.device = device
        self.model: Optional[CrossEncoder] = None
        
        # 性能统计
        self.stats = {
            "total_reranks": 0,
            "avg_latency_ms": 0,
            "avg_docs_reranked": 0
        }
    
    def load_model(self):
        """加载 Cross-Encoder 模型"""
        if self.model is None:
            print(f"[重排器] 加载模型：{self.model_name} (device={self.device})")
            print(f"[重排器] 使用镜像：https://hf-mirror.com")
            load_start = time.time()
            try:
                self.model = CrossEncoder(self.model_name, device=self.device)
                load_time = (time.time() - load_start) * 1000
                print(f"[重排器] ✅ 模型加载完成，耗时：{load_time:.1f}ms")
            except Exception as e:
                print(f"[重排器] ❌ 模型加载失败：{e}")
                print(f"[重排器] 提示：请检查网络连接，或手动下载模型到缓存目录")
                raise
    
    def rerank(
        self,
        query: str,
        documents: List[Dict],
        top_k: int = 20
    ) -> List[Dict]:
        """
        重排文档
        
        Args:
            query: 查询文本
            documents: 待重排的文档列表
            top_k: 返回结果数量
        
        Returns:
            重排后的文档列表 (按相关性降序)
        """
        if not documents:
            return []
        
        if not self.model:
            # 模型未加载，直接返回
            return documents[:top_k]
        
        rerank_start = time.time()
        
        # 准备输入对 (query, document)
        pairs = []
        for doc in documents:
            content = doc.get("content", "")
            pairs.append([query, content])
        
        # 预测相关性分数
        scores = self.model.predict(pairs)
        
        # 排序
        sorted_indices = np.argsort(scores)[::-1]
        
        # 构建结果
        results = []
        for i, idx in enumerate(sorted_indices[:top_k]):
            doc = documents[idx].copy()
            doc["rerank_score"] = float(scores[idx])
            doc["rerank_rank"] = i + 1
            results.append(doc)
        
        rerank_time = (time.time() - rerank_start) * 1000
        
        # 更新统计
        self.stats["total_reranks"] += 1
        self.stats["avg_latency_ms"] = (
            self.stats["avg_latency_ms"] * (self.stats["total_reranks"] - 1) + rerank_time
        ) / self.stats["total_reranks"]
        self.stats["avg_docs_reranked"] = (
            self.stats["avg_docs_reranked"] * (self.stats["total_reranks"] - 1) + len(documents)
        ) / self.stats["total_reranks"]
        
        print(f"[重排] 耗时：{rerank_time:.1f}ms, 文档数：{len(documents)} → {len(results)}")
        
        return results
    
    def rerank_batch(
        self,
        query: str,
        documents: List[Dict],
        batch_size: int = 32,
        top_k: int = 20
    ) -> List[Dict]:
        """
        批量重排 (大数据集时更稳定)
        """
        if not documents:
            return []
        
        if not self.model:
            return documents[:top_k]
        
        rerank_start = time.time()
        
        # 分批预测
        all_scores = []
        for i in range(0, len(documents), batch_size):
            batch_docs = documents[i:i + batch_size]
            pairs = [[query, doc.get("content", "")] for doc in batch_docs]
            batch_scores = self.model.predict(pairs)
            all_scores.extend(batch_scores)
        
        # 排序
        sorted_indices = np.argsort(all_scores)[::-1]
        
        # 构建结果
        results = []
        for i, idx in enumerate(sorted_indices[:top_k]):
            doc = documents[idx].copy()
            doc["rerank_score"] = float(all_scores[idx])
            doc["rerank_rank"] = i + 1
            results.append(doc)
        
        rerank_time = (time.time() - rerank_start) * 1000
        print(f"[批量重排] 耗时：{rerank_time:.1f}ms, 文档数：{len(documents)} → {len(results)}")
        
        return results


if __name__ == "__main__":
    # ========== 测试示例 ==========
    print("=" * 60)
    print("Cross-Encoder 重排器测试")
    print("=" * 60)
    
    # 测试数据
    docs = [
        {"content": "CVE-2024-0012 Palo Alto PAN-OS RCE 漏洞", "metadata": {"cve_id": "CVE-2024-0012", "vuln_type": "RCE"}},
        {"content": "SQL 注入攻击手法详解", "metadata": {"vuln_type": "SQLi"}},
        {"content": "XSS 跨站脚本攻击", "metadata": {"vuln_type": "XSS"}},
        {"content": "SSRF 服务器端请求伪造", "metadata": {"vuln_type": "SSRF"}},
        {"content": "命令注入漏洞，通过 system() 函数执行系统命令", "metadata": {"vuln_type": "CommandInjection"}},
    ]
    
    # 创建重排器
    print("\n[测试] 创建重排器...")
    reranker = CrossEncoderReranker(
        model_name="cross-encoder/ms-marco-MiniLM-L-6-v2",
        device="cpu"
    )
    
    # 加载模型
    print("\n[测试] 加载模型...")
    reranker.load_model()
    
    # 测试查询
    query = "远程代码执行和命令注入漏洞"
    print(f"\n[测试] 查询：'{query}'")
    print(f"[测试] 待重排文档数：{len(docs)}")
    
    # 执行重排
    print("\n" + "-" * 60)
    print("重排后 (按相关性排序):")
    print("-" * 60)
    results = reranker.rerank(query, docs, top_k=3)
    for i, r in enumerate(results, 1):
        print(f"[{i}] {r['content'][:50]}...")
        print(f"    重排分数：{r['rerank_score']:.4f}, 类型：{r['metadata'].get('vuln_type', 'N/A')}")
    
    # 性能统计
    print("\n" + "=" * 60)
    print("性能统计")
    print("=" * 60)
    print(f"总重排数：{reranker.stats['total_reranks']}")
    print(f"平均延迟：{reranker.stats['avg_latency_ms']:.1f}ms")
    print(f"平均文档数：{reranker.stats['avg_docs_reranked']:.1f}")
    
    print("\n✅ Cross-Encoder 重排器测试完成！")

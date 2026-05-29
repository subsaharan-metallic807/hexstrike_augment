"""
四步检索链路 - 工程执行版 v2.0

强制顺序:
Step1: 关键词召回 (BM25) - 保精确实体
Step2: 向量召回 (Embedding) - 语义补全
Step3: 交叉重排 (Cross-Encoder) - 精排序
Step4: 规则过滤 - 时效/版本/目标环境匹配
"""

from typing import List, Dict, Optional
import time


class RetrievalPipeline:
    """
    四步检索链路
    
    每步都有明确的耗时要求和验收指标
    """
    
    def __init__(
        self,
        bm25_retriever=None,
        vector_retriever=None,
        reranker=None,
        rule_filter=None
    ):
        """
        Args:
            bm25_retriever: BM25 召回器
            vector_retriever: 向量召回器
            reranker: 重排器
            rule_filter: 规则过滤器
        """
        self.bm25_retriever = bm25_retriever
        self.vector_retriever = vector_retriever
        self.reranker = reranker
        self.rule_filter = rule_filter
        
        # 性能统计
        self.stats = {
            "total_queries": 0,
            "avg_latency_ms": 0
        }
    
    def search(
        self,
        query: str,
        n_results: int = 10,
        filters: Optional[Dict] = None
    ) -> List[Dict]:
        """
        四步检索流程
        
        Args:
            query: 查询文本
            n_results: 返回结果数量
            filters: 过滤条件
        
        Returns:
            检索结果列表
        """
        start_time = time.time()
        
        # ========== Step 1: 关键词召回 (BM25) ==========
        # 目标：保证精确实体召回 (CVE 编号、端口号、产品名)
        # 耗时：<50ms
        step1_start = time.time()
        bm25_results = self.bm25_retriever.search(query, top_k=50) if self.bm25_retriever else []
        step1_time = (time.time() - step1_start) * 1000
        
        # ========== Step 2: 向量召回 (Embedding) ==========
        # 目标：语义补全，召回相关但关键词不匹配的文档
        # 耗时：<100ms
        step2_start = time.time()
        vector_results = self.vector_retriever.search(query, top_k=50, threshold=0.1) if self.vector_retriever else []
        step2_time = (time.time() - step2_start) * 1000
        
        # ========== Step 3: RRF 融合 ==========
        # 目标：融合 BM25 和向量检索结果
        # 耗时：<20ms
        step3_start = time.time()
        fused_results = self._rrf_fusion(bm25_results, vector_results, k=60)
        step3_time = (time.time() - step3_start) * 1000
        
        # ========== Step 4: 交叉重排 ==========
        # 目标：精排序，提高 Top-K 质量
        # 耗时：<200ms
        step4_start = time.time()
        reranked_results = self.reranker.rerank(query, fused_results[:20], top_k=n_results * 2) if self.reranker else fused_results[:n_results * 2]
        step4_time = (time.time() - step4_start) * 1000
        
        # ========== Step 5: 规则过滤 ==========
        # 目标：时效/版本/目标环境匹配
        # 耗时：<20ms
        step5_start = time.time()
        filtered_results = self.rule_filter.filter(reranked_results, filters) if self.rule_filter else reranked_results
        step5_time = (time.time() - step5_start) * 1000
        
        # 取最终结果
        final_results = filtered_results[:n_results]
        
        # 更新统计
        total_time = (time.time() - start_time) * 1000
        self.stats["total_queries"] += 1
        self.stats["avg_latency_ms"] = (
            self.stats["avg_latency_ms"] * (self.stats["total_queries"] - 1) + total_time
        ) / self.stats["total_queries"]
        
        # 性能日志
        print(f"[检索链路] 总耗时：{total_time:.1f}ms")
        print(f"  - Step1 BM25: {step1_time:.1f}ms ({len(bm25_results)}条)")
        print(f"  - Step2 向量：{step2_time:.1f}ms ({len(vector_results)}条)")
        print(f"  - Step3 融合：{step3_time:.1f}ms ({len(fused_results)}条)")
        print(f"  - Step4 重排：{step4_time:.1f}ms ({len(reranked_results)}条)")
        print(f"  - Step5 过滤：{step5_time:.1f}ms ({len(filtered_results)}条)")
        
        return final_results
    
    def _rrf_fusion(self, bm25_results: List, vector_results: List, k: int = 60) -> List:
        """
        Reciprocal Rank Fusion (RRF) 融合算法
        
        公式：RRF 分数 = Σ 1 / (k + rank_i)
        其中 k=60 为平滑常数
        
        Args:
            bm25_results: BM25 检索结果
            vector_results: 向量检索结果
            k: 平滑常数
        
        Returns:
            融合后的结果
        """
        # 如果没有结果，直接返回空列表
        if not bm25_results and not vector_results:
            return []
        
        # 如果只有一路有结果，直接返回
        if not bm25_results:
            return vector_results
        if not vector_results:
            return bm25_results
        
        scores = {}
        doc_map = {}  # 用 content 作为唯一标识
        
        # BM25 结果计分
        for i, doc in enumerate(bm25_results):
            # 使用 content 作为唯一标识（测试数据没有 chunk_hash 或 id）
            doc_id = doc.get("chunk_hash") or doc.get("id") or doc.get("content", str(i))[:100]
            scores[doc_id] = scores.get(doc_id, 0) + 1 / (k + i + 1)
            doc_map[doc_id] = doc
        
        # 向量检索结果计分
        for i, doc in enumerate(vector_results):
            doc_id = doc.get("chunk_hash") or doc.get("id") or doc.get("content", str(i))[:100]
            scores[doc_id] = scores.get(doc_id, 0) + 1 / (k + i + 1)
            if doc_id not in doc_map:
                doc_map[doc_id] = doc
        
        # 按分数排序
        sorted_docs = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        
        # 合并结果
        fused_results = []
        for doc_id, score in sorted_docs:
            if doc_id in doc_map:
                doc = doc_map[doc_id]
                doc["rrf_score"] = score
                fused_results.append(doc)
        
        return fused_results


class RuleFilter:
    """
    规则过滤器
    
    Step 5: 时效/版本/目标环境匹配
    """
    
    def filter(self, documents: List[Dict], filters: Optional[Dict] = None) -> List[Dict]:
        """
        过滤文档
        
        Args:
            documents: 文档列表
            filters: 过滤条件
                - is_expired: 是否包含过期数据
                - min_confidence: 最小置信度
                - vuln_type: 漏洞类型
                - severity: 严重程度
        
        Returns:
            过滤后的文档列表
        """
        if not filters:
            return documents
        
        filtered = []
        for doc in documents:
            metadata = doc.get("metadata", {})
            
            # 时效过滤 (默认排除过期数据)
            if not filters.get("is_expired", False) and metadata.get("is_expired", False):
                continue
            
            # 置信度过滤
            min_confidence = filters.get("min_confidence", 0.7)
            if metadata.get("confidence", 1.0) < min_confidence:
                continue
            
            # 漏洞类型过滤
            if filters.get("vuln_type") and metadata.get("vuln_type") != filters["vuln_type"]:
                continue
            
            # 严重程度过滤
            if filters.get("severity") and metadata.get("severity") != filters["severity"]:
                continue
            
            filtered.append(doc)
        
        return filtered


if __name__ == "__main__":
    # 测试示例
    print("四步检索链路测试")
    print("=" * 60)
    print("注意：需要先实现 BM25、向量检索、重排器才能完整测试")
    print("=" * 60)

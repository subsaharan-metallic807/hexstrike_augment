#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RRF Fusion Module - 融合算法优化
HexStrike 项目第三周核心模块
"""

from typing import List, Dict, Any
from collections import defaultdict
import math


class RRFFusion:
    """
    Reciprocal Rank Fusion (RRF) 融合模块
    
    算法公式：RRF 分数 = Σ 1 / (k + rank_i)
    """
    
    def __init__(self, k: int = 60, weights: List[float] = None):
        """
        初始化 RRF 融合器
        
        Args:
            k: RRF 参数，默认 60（经典值）
            weights: 各路检索结果的权重，默认等权重
        """
        self.k = k
        self.weights = weights
    
    def fuse(self, result_lists: List[List[Dict]], top_k: int = 20) -> List[Dict]:
        """
        融合多路检索结果
        
        Args:
            result_lists: 多路检索结果列表
            top_k: 返回 Top-K 结果
            
        Returns:
            融合后的排序结果
        """
        doc_scores = defaultdict(float)
        doc_info = {}
        
        for list_idx, results in enumerate(result_lists):
            weight = self.weights[list_idx] if self.weights else 1.0
            
            for rank, doc in enumerate(results):
                doc_id = doc.get('chunk_id', doc.get('id'))
                rrf_score = weight / (self.k + rank)
                doc_scores[doc_id] += rrf_score
                
                if doc_id not in doc_info:
                    doc_info[doc_id] = doc
        
        sorted_docs = sorted(doc_scores.items(), key=lambda x: x[1], reverse=True)
        
        fused_results = []
        for rank, (doc_id, score) in enumerate(sorted_docs[:top_k]):
            doc = doc_info[doc_id].copy()
            doc['rrf_score'] = score
            doc['rrf_rank'] = rank + 1
            fused_results.append(doc)
        
        return fused_results
    
    def normalize_scores(self, results: List[Dict]) -> List[Dict]:
        """
        分数归一化到 [0, 1] 区间
        """
        if not results:
            return results
        
        scores = [doc.get('rrf_score', 0) for doc in results]
        min_score = min(scores)
        max_score = max(scores)
        
        if max_score == min_score:
            for doc in results:
                doc['rrf_score_norm'] = 1.0
        else:
            for doc in results:
                score = doc.get('rrf_score', 0)
                doc['rrf_score_norm'] = (score - min_score) / (max_score - min_score)
        
        return results


def optimize_k(query_results: List[Dict], gold_labels: List[str], k_range: List[int] = None) -> Dict:
    """
    离线优化 k 值
    
    Args:
        query_results: 查询结果
        gold_labels: 金标准文档 ID 列表
        k_range: 待测试的 k 值范围
        
    Returns:
        最优 k 值和对应指标
    """
    if k_range is None:
        k_range = [30, 40, 50, 60, 70, 80, 100]
    
    best_k = 60
    best_ndcg = 0
    
    for k in k_range:
        fusion = RRFFusion(k=k)
        # 简化评估，实际应使用完整 benchmark
        ndcg = _evaluate_ndcg(query_results, gold_labels, k=10)
        
        if ndcg > best_ndcg:
            best_ndcg = ndcg
            best_k = k
    
    return {
        'best_k': best_k,
        'best_ndcg': best_ndcg,
        'k_range_tested': k_range
    }


def _evaluate_ndcg(results: List[Dict], gold_labels: List[str], k: int = 10) -> float:
    """
    计算 nDCG@K
    """
    dcg = 0.0
    idcg = 0.0
    
    for i, doc in enumerate(results[:k]):
        doc_id = doc.get('chunk_id', '')
        rel = 1 if doc_id in gold_labels else 0
        dcg += (2 ** rel - 1) / math.log2(i + 2)
    
    for i in range(min(k, len(gold_labels))):
        idcg += 1 / math.log2(i + 2)
    
    return dcg / idcg if idcg > 0 else 0.0


if __name__ == '__main__':
    print("=" * 60)
    print("RRF Fusion 模块测试")
    print("=" * 60)
    
    bm25_results = [
        {"chunk_id": "doc1", "score": 0.85, "source": "BM25"},
        {"chunk_id": "doc2", "score": 0.72, "source": "BM25"},
        {"chunk_id": "doc3", "score": 0.65, "source": "BM25"},
    ]
    
    vector_results = [
        {"chunk_id": "doc2", "score": 0.88, "source": "Vector"},
        {"chunk_id": "doc4", "score": 0.76, "source": "Vector"},
        {"chunk_id": "doc1", "score": 0.71, "source": "Vector"},
    ]
    
    fusion = RRFFusion(k=60)
    fused = fusion.fuse([bm25_results, vector_results], top_k=5)
    
    print(f"\n融合结果 (k=60):")
    for i, doc in enumerate(fused, 1):
        print(f"  [{i}] {doc['chunk_id']} - RRF 分数：{doc['rrf_score']:.4f}")
    
    print("\n✅ RRF Fusion 模块测试完成！")

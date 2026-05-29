#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Benchmark 评估工具 v1.0
HexStrike 项目第三周核心模块
"""

import json
import math
from typing import List, Dict, Any
from datetime import datetime


class BenchmarkEvaluator:
    """
    检索质量评估工具
    
    支持指标：
    - Recall@K
    - nDCG@K
    - Precision@K
    - MRR
    - MAP
    """
    
    def __init__(self, retrieval_pipeline=None):
        self.pipeline = retrieval_pipeline
        self.test_queries = []
        self.gold_standards = {}
    
    def load_test_dataset(self, dataset_path: str):
        """
        加载测试数据集
        
        Args:
            dataset_path: JSON 格式测试数据集路径
        """
        with open(dataset_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        self.test_queries = data.get('queries', [])
        self.gold_standards = {q['query_id']: q['gold_docs'] for q in self.test_queries}
        
        print(f"✅ 加载测试数据集：{len(self.test_queries)} 条查询")
    
    def evaluate(self, top_k: List[int] = None) -> Dict:
        """
        执行完整评估
        
        Returns:
            评估指标字典
        """
        if top_k is None:
            top_k = [5, 10, 20]
        
        results = {
            'recall': {},
            'ndcg': {},
            'precision': {},
            'mrr': 0.0,
            'map': 0.0,
            'query_count': len(self.test_queries)
        }
        
        all_precisions = []
        
        for query_data in self.test_queries:
            query = query_data['query']
            query_id = query_data['query_id']
            gold_docs = set(query_data['gold_docs'])
            
            retrieved = self._retrieve(query, top_k=max(top_k))
            retrieved_ids = [doc.get('chunk_id', doc.get('id')) for doc in retrieved]
            
            for k in top_k:
                recall = self._calc_recall(retrieved_ids[:k], gold_docs)
                ndcg = self._calc_ndcg(retrieved_ids[:k], gold_docs)
                precision = self._calc_precision(retrieved_ids[:k], gold_docs)
                
                results['recall'][f'@{k}'] = results['recall'].get(f'@{k}', []) + [recall]
                results['ndcg'][f'@{k}'] = results['ndcg'].get(f'@{k}', []) + [ndcg]
                results['precision'][f'@{k}'] = results['precision'].get(f'@{k}', []) + [precision]
            
            mrr = self._calc_mrr(retrieved_ids, gold_docs)
            ap = self._calc_ap(retrieved_ids, gold_docs)
            
            results['mrr'] += mrr
            all_precisions.append(ap)
        
        results['mrr'] /= len(self.test_queries)
        results['map'] = sum(all_precisions) / len(all_precisions)
        
        for k in top_k:
            results['recall'][f'@{k}'] = sum(results['recall'][f'@{k}']) / len(self.test_queries)
            results['ndcg'][f'@{k}'] = sum(results['ndcg'][f'@{k}']) / len(self.test_queries)
            results['precision'][f'@{k}'] = sum(results['precision'][f'@{k}']) / len(self.test_queries)
        
        return results
    
    def _retrieve(self, query: str, top_k: int = 20) -> List[Dict]:
        """
        执行检索（Mock 实现，实际应调用检索链路）
        """
        if self.pipeline:
            return self.pipeline.search(query, n_results=top_k)
        else:
            return []
    
    def _calc_recall(self, retrieved: List[str], gold: set) -> float:
        """计算 Recall@K"""
        if not gold:
            return 0.0
        return len(set(retrieved) & gold) / len(gold)
    
    def _calc_precision(self, retrieved: List[str], gold: set) -> float:
        """计算 Precision@K"""
        if not retrieved:
            return 0.0
        return len(set(retrieved) & gold) / len(retrieved)
    
    def _calc_ndcg(self, retrieved: List[str], gold: set, k: int = None) -> float:
        """计算 nDCG@K"""
        if k is None:
            k = len(retrieved)
        
        dcg = 0.0
        idcg = 0.0
        
        for i, doc_id in enumerate(retrieved[:k]):
            rel = 1 if doc_id in gold else 0
            dcg += (2 ** rel - 1) / math.log2(i + 2)
        
        for i in range(min(k, len(gold))):
            idcg += 1 / math.log2(i + 2)
        
        return dcg / idcg if idcg > 0 else 0.0
    
    def _calc_mrr(self, retrieved: List[str], gold: set) -> float:
        """计算 MRR"""
        for i, doc_id in enumerate(retrieved):
            if doc_id in gold:
                return 1.0 / (i + 1)
        return 0.0
    
    def _calc_ap(self, retrieved: List[str], gold: set) -> float:
        """计算 Average Precision"""
        if not gold:
            return 0.0
        
        ap = 0.0
        relevant_count = 0
        
        for i, doc_id in enumerate(retrieved):
            if doc_id in gold:
                relevant_count += 1
                ap += relevant_count / (i + 1)
        
        return ap / len(gold)
    
    def generate_report(self, results: Dict, output_path: str = None):
        """
        生成评估报告
        """
        if output_path is None:
            timestamp = datetime.now().strftime('%Y%m%d')
            output_path = f'benchmark_report_{timestamp}.md'
        
        report = f"""# HexStrike Benchmark 评估报告

**生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**测试查询数**: {results['query_count']} 条

## 评估指标

### Recall@K (召回率)
"""
        for k, v in results['recall'].items():
            report += f"- **Recall{k}**: {v:.4f}\n"
        
        report += "\n### nDCG@K (归一化折损累积增益)\n"
        for k, v in results['ndcg'].items():
            report += f"- **nDCG{k}**: {v:.4f}\n"
        
        report += "\n### Precision@K (精确率)\n"
        for k, v in results['precision'].items():
            report += f"- **Precision{k}**: {v:.4f}\n"
        
        report += f"\n### 综合指标\n- **MRR**: {results['mrr']:.4f}\n- **MAP**: {results['map']:.4f}\n"
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report)
        
        print(f"✅ 报告已保存：{output_path}")
        return report


def create_test_dataset(output_path: str = 'test_queries_v1.json'):
    """
    创建示例测试数据集
    """
    test_queries = [
        {
            "query_id": "q001",
            "query": "SQL 注入攻击手法",
            "gold_docs": ["doc_sqli_001", "doc_sqli_002", "doc_sqli_003"]
        },
        {
            "query_id": "q002",
            "query": "远程代码执行漏洞",
            "gold_docs": ["doc_rce_001", "doc_rce_002"]
        },
        {
            "query_id": "q003",
            "query": "XSS 跨站脚本攻击",
            "gold_docs": ["doc_xss_001", "doc_xss_002", "doc_xss_003", "doc_xss_004"]
        }
    ]
    
    dataset = {
        "version": "1.0",
        "created_at": datetime.now().isoformat(),
        "query_count": len(test_queries),
        "queries": test_queries
    }
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(dataset, f, indent=2, ensure_ascii=False)
    
    print(f"✅ 测试数据集已创建：{output_path}")
    return output_path


if __name__ == '__main__':
    print("=" * 60)
    print("Benchmark 评估工具 v1.0 测试")
    print("=" * 60)
    
    create_test_dataset()
    
    evaluator = BenchmarkEvaluator()
    evaluator.load_test_dataset('test_queries_v1.json')
    
    print("\n⚠️  注意：当前为 Mock 测试，需连接真实检索链路")
    print("\n✅ Benchmark 模块测试完成！")

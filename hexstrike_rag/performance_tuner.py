#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
性能调优工具
HexStrike 项目第三周核心模块
"""

import time
import statistics
from typing import List, Dict, Any, Callable
from datetime import datetime


class PerformanceProfiler:
    """
    性能分析器
    
    功能：
    - 分步耗时统计
    - P50/P95/P99 延迟计算
    - 性能瓶颈识别
    """
    
    def __init__(self):
        self.timings = {}
        self.queries = []
    
    def record(self, step: str, elapsed_ms: float):
        """记录单次耗时"""
        if step not in self.timings:
            self.timings[step] = []
        self.timings[step].append(elapsed_ms)
    
    def profile_query(self, pipeline, query: str) -> Dict:
        """
        分析单次查询的性能
        
        Returns:
            各步骤耗时字典
        """
        start_total = time.time()
        timings = {}
        
        steps = [
            ('BM25', lambda: pipeline.bm25_search(query, top_k=50)),
            ('Vector', lambda: pipeline.vector_search(query, top_k=50)),
            ('Fusion', lambda: pipeline.fuse_results(timings.get('bm25_results', []), timings.get('vector_results', []))),
            ('Rerank', lambda: pipeline.rerank(query, timings.get('fused_results', []))),
            ('Filter', lambda: pipeline.filter_results(timings.get('reranked_results', [])))
        ]
        
        for step_name, step_func in steps:
            step_start = time.time()
            try:
                result = step_func()
                step_elapsed = (time.time() - step_start) * 1000
                timings[f'{step_name.lower()}_results'] = result
                self.record(step_name, step_elapsed)
            except Exception as e:
                print(f"⚠️  {step_name} 步骤失败：{e}")
        
        total_elapsed = (time.time() - start_total) * 1000
        self.record('Total', total_elapsed)
        timings['total_ms'] = total_elapsed
        
        return timings
    
    def benchmark(self, pipeline, queries: List[str], warmup: int = 10) -> Dict:
        """
        批量基准测试
        
        Args:
            pipeline: 检索链路
            queries: 查询列表
            warmup: 预热查询数
            
        Returns:
            性能统计报告
        """
        print(f"🔍 开始基准测试：{len(queries)} 条查询")
        
        for i, query in enumerate(queries[:warmup]):
            pipeline.search(query)
        
        print(f"✅ 预热完成：{warmup} 条查询")
        
        all_timings = {'Total': []}
        
        for i, query in enumerate(queries):
            timings = self.profile_query(pipeline, query)
            for step, elapsed in timings.items():
                if isinstance(elapsed, (int, float)):
                    if step not in all_timings:
                        all_timings[step] = []
                    all_timings[step].append(elapsed)
            
            if (i + 1) % 100 == 0:
                print(f"  进度：{i + 1}/{len(queries)}")
        
        report = self._generate_report(all_timings)
        return report
    
    def _generate_report(self, all_timings: Dict) -> Dict:
        """生成性能报告"""
        report = {
            'steps': {},
            'summary': {}
        }
        
        for step, timings in all_timings.items():
            if not timings:
                continue
            
            sorted_t = sorted(timings)
            n = len(timings)
            
            report['steps'][step] = {
                'count': n,
                'mean': statistics.mean(timings),
                'median': statistics.median(timings),
                'std': statistics.stdev(timings) if n > 1 else 0,
                'p50': sorted_t[int(n * 0.50)] if n > 0 else 0,
                'p95': sorted_t[int(n * 0.95)] if n > 0 else 0,
                'p99': sorted_t[int(n * 0.99)] if n > 0 else 0,
                'min': min(timings),
                'max': max(timings)
            }
        
        if 'Total' in all_timings:
            total_t = all_timings['Total']
            sorted_total = sorted(total_t)
            n = len(sorted_total)
            report['summary'] = {
                'p50': sorted_total[int(n * 0.50)] if n > 0 else 0,
                'p95': sorted_total[min(int(n * 0.95), n - 1)] if n > 0 else 0,
                'p99': sorted_total[min(int(n * 0.99), n - 1)] if n > 0 else 0,
                'target_p95': 500,
                'passed': sorted_total[min(int(n * 0.95), n - 1)] < 500 if n > 0 else False
            }
        
        return report
    
    def print_report(self, report: Dict):
        """打印性能报告"""
        print("\n" + "=" * 60)
        print("性能测试报告")
        print("=" * 60)
        
        for step, stats in report.get('steps', {}).items():
            print(f"\n{step}:")
            print(f"  查询数：{stats['count']}")
            print(f"  平均：{stats['mean']:.1f}ms")
            print(f"  P50:  {stats['p50']:.1f}ms")
            print(f"  P95:  {stats['p95']:.1f}ms")
            print(f"  P99:  {stats['p99']:.1f}ms")
        
        summary = report.get('summary', {})
        if summary:
            print("\n" + "-" * 60)
            print("总体性能:")
            print(f"  P50:  {summary.get('p50', 0):.1f}ms")
            print(f"  P95:  {summary.get('p95', 0):.1f}ms (目标：<500ms)")
            print(f"  P99:  {summary.get('p99', 0):.1f}ms")
            print(f"  状态：{'✅ 达标' if summary.get('passed') else '⚠️ 未达标'}")


class PerformanceTuner:
    """
    性能调优器
    
    提供优化建议和参数调整
    """
    
    def __init__(self):
        self.recommendations = []
    
    def analyze_bottleneck(self, report: Dict) -> List[Dict]:
        """
        分析性能瓶颈
        
        Returns:
            瓶颈列表和优化建议
        """
        bottlenecks = []
        
        steps = report.get('steps', {})
        total_p95 = report.get('summary', {}).get('p95', 0)
        
        for step, stats in steps.items():
            if step == 'Total':
                continue
            
            step_p95 = stats.get('p95', 0)
            if step_p95 == 0:
                continue
            
            ratio = step_p95 / total_p95 if total_p95 > 0 else 0
            
            if ratio > 0.4:
                bottlenecks.append({
                    'step': step,
                    'p95_ms': step_p95,
                    'ratio': f"{ratio:.1%}",
                    'recommendation': self._get_recommendation(step, stats)
                })
        
        # 使用 safe 排序，防止空列表或无 p95 的情况
        if bottlenecks:
            return sorted(bottlenecks, key=lambda x: x.get('p95_ms', 0), reverse=True)
        return bottlenecks
    
    def _get_recommendation(self, step: str, stats: Dict) -> str:
        """根据步骤给出优化建议"""
        recommendations = {
            'BM25': '考虑使用 Elasticsearch 替代 rank-bm25 库',
            'Vector': '优化 HNSW 索引参数 (M=32, ef_construct=400)',
            'Fusion': '减少融合路数或使用更高效的融合算法',
            'Rerank': '使用轻量模型或减少重排文档数 (top_k=20)',
            'Filter': '优化 Qdrant payload 索引',
            'Total': '引入 Redis 缓存层，降低重复查询延迟'
        }
        return recommendations.get(step, '性能分析中...')


if __name__ == '__main__':
    print("=" * 60)
    print("性能调优工具测试")
    print("=" * 60)
    
    profiler = PerformanceProfiler()
    
    mock_timings = {
        'BM25': [12.3, 11.5, 13.2, 10.8, 12.1],
        'Vector': [45.2, 43.8, 47.1, 44.5, 46.3],
        'Fusion': [8.5, 7.9, 9.2, 8.1, 8.8],
        'Rerank': [125.3, 120.5, 130.2, 122.8, 128.1],
        'Filter': [15.2, 14.8, 16.1, 14.5, 15.9],
        'Total': [285.4, 278.2, 292.5, 280.1, 288.9]
    }
    
    report = {
        'steps': {},
        'summary': {'p95': 292.5, 'target_p95': 500, 'passed': True}
    }
    
    for step, timings in mock_timings.items():
        sorted_t = sorted(timings)
        n = len(timings)
        report['steps'][step] = {
            'count': n,
            'mean': statistics.mean(timings),
            'p50': sorted_t[int(n * 0.50)],
            'p95': sorted_t[int(n * 0.95)],
            'p99': sorted_t[int(n * 0.99)]
        }
    
    profiler.print_report(report)
    
    tuner = PerformanceTuner()
    bottlenecks = tuner.analyze_bottleneck(report)
    
    print("\n" + "=" * 60)
    print("性能瓶颈分析:")
    print("=" * 60)
    
    for bn in bottlenecks:
        print(f"\n{bn['step']} (P95: {bn['p95_ms']:.1f}ms, 占比：{bn['ratio']})")
        print(f"  建议：{bn['recommendation']}")
    
    print("\n✅ 性能调优工具测试完成！")

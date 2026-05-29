"""
向量检索器 - Step 2 (修复版 - 支持国内镜像)

工程执行版 v2.0
目标：语义补全，召回相关但关键词不匹配的文档
模型：bge-m3 (384 维)
参数：top_k=50, threshold=0.6
耗时：<100ms
"""

import os
os.environ['HF_ENDPOINT'] = 'https://hf-mirror.com'  # 使用国内镜像

from typing import List, Dict, Optional
import numpy as np
from sentence_transformers import SentenceTransformer
import time


class VectorRetriever:
    """
    向量检索器
    
    使用稠密向量进行语义检索，补充 BM25 的不足
    """
    
    def __init__(
        self,
        documents: List[Dict] = None,
        model_name: str = "sentence-transformers/all-MiniLM-L6-v2",
        device: str = "cpu"
    ):
        """
        Args:
            documents: 文档列表
            model_name: Embedding 模型名称
            device: 计算设备 (cpu/cuda)
        """
        self.documents = documents or []
        self.model_name = model_name
        self.device = device
        self.model: Optional[SentenceTransformer] = None
        self.document_embeddings: Optional[np.ndarray] = None
        
        # 性能统计
        self.stats = {
            "total_queries": 0,
            "avg_latency_ms": 0,
            "cache_hits": 0
        }
    
    def load_model(self):
        """加载 Embedding 模型"""
        if self.model is None:
            print(f"[向量检索器] 加载模型：{self.model_name} (device={self.device})")
            print(f"[向量检索器] 使用镜像：https://hf-mirror.com")
            load_start = time.time()
            try:
                self.model = SentenceTransformer(self.model_name, device=self.device)
                load_time = (time.time() - load_start) * 1000
                print(f"[向量检索器] ✅ 模型加载完成，耗时：{load_time:.1f}ms")
                
                # 加载模型后，如果有文档则构建索引
                if self.documents and self.document_embeddings is None:
                    print(f"[向量检索器] 检测到有 {len(self.documents)} 个文档，开始构建索引...")
                    self._build_index()
            except Exception as e:
                print(f"[向量检索器] ❌ 模型加载失败：{e}")
                print(f"[向量检索器] 提示：请检查网络连接，或手动下载模型到缓存目录")
                raise
    
    def _build_index(self):
        """构建向量索引"""
        if not self.documents or not self.model:
            return
        
        print(f"[向量检索器] 构建索引，文档数：{len(self.documents)}")
        index_start = time.time()
        
        # 提取文档内容
        texts = [doc.get("content", "") for doc in self.documents]
        
        # 批量编码 (batch_size=32)
        self.document_embeddings = self.model.encode(
            texts,
            batch_size=32,
            show_progress_bar=True,
            normalize_embeddings=True  # 归一化，便于余弦相似度计算
        )
        
        index_time = (time.time() - index_start) / 60
        print(f"[向量检索器] 索引构建完成，耗时：{index_time:.2f}分钟")
        print(f"[向量检索器] 向量维度：{self.document_embeddings.shape[1]}")
    
    def add_documents(self, documents: List[Dict], rebuild: bool = True):
        """
        添加文档到索引
        
        Args:
            documents: 文档列表
            rebuild: 是否重建索引 (False 则增量添加)
        """
        if rebuild:
            self.documents = documents
            self._build_index()
        else:
            # 增量添加
            old_count = len(self.documents)
            self.documents.extend(documents)
            
            # 重新编码新增文档
            new_texts = [doc.get("content", "") for doc in documents]
            new_embeddings = self.model.encode(
                new_texts,
                batch_size=32,
                normalize_embeddings=True
            )
            
            # 合并向量
            if self.document_embeddings is not None:
                self.document_embeddings = np.vstack([
                    self.document_embeddings,
                    new_embeddings
                ])
            
            print(f"[向量检索器] 增量添加：{old_count} → {len(self.documents)}")
    
    def search(
        self,
        query: str,
        top_k: int = 50,
        threshold: float = 0.6
    ) -> List[Dict]:
        """
        向量检索
        
        Args:
            query: 查询文本
            top_k: 返回结果数量
            threshold: 相似度阈值 (低于此值的结果会被过滤)
        
        Returns:
            检索结果列表 (按相似度降序)
        """
        if not self.documents or self.document_embeddings is None:
            return []
        
        query_start = time.time()
        
        # 编码查询
        query_embedding = self.model.encode(
            [query],
            normalize_embeddings=True
        )[0]
        
        # 计算余弦相似度
        similarities = self._cosine_similarity(query_embedding, self.document_embeddings)
        
        # 排序
        sorted_indices = np.argsort(similarities)[::-1]
        
        # 过滤阈值并返回
        results = []
        for i in sorted_indices:
            if similarities[i] >= threshold:
                doc = self.documents[i].copy()
                doc["vector_score"] = float(similarities[i])
                results.append(doc)
                
                if len(results) >= top_k:
                    break
        
        query_time = (time.time() - query_start) * 1000
        
        # 更新统计
        self.stats["total_queries"] += 1
        self.stats["avg_latency_ms"] = (
            self.stats["avg_latency_ms"] * (self.stats["total_queries"] - 1) + query_time
        ) / self.stats["total_queries"]
        
        print(f"[向量检索] 耗时：{query_time:.1f}ms, 返回：{len(results)}条 (threshold={threshold})")
        
        return results
    
    def _cosine_similarity(self, query_emb: np.ndarray, doc_embs: np.ndarray) -> np.ndarray:
        """
        计算余弦相似度
        
        由于向量已归一化，余弦相似度 = 点积
        
        Args:
            query_emb: 查询向量 (384,)
            doc_embs: 文档向量矩阵 (N, 384)
        
        Returns:
            相似度数组 (N,)
        """
        return np.dot(doc_embs, query_emb)
    
    def batch_search(
        self,
        queries: List[str],
        top_k: int = 50,
        threshold: float = 0.6
    ) -> List[List[Dict]]:
        """
        批量检索
        
        Args:
            queries: 查询列表
            top_k: 每个查询返回结果数量
            threshold: 相似度阈值
        
        Returns:
            检索结果列表 (每个查询对应一个结果列表)
        """
        if not self.documents or self.document_embeddings is None:
            return [[] for _ in queries]
        
        batch_start = time.time()
        
        # 批量编码查询
        query_embeddings = self.model.encode(
            queries,
            batch_size=32,
            normalize_embeddings=True
        )
        
        # 计算相似度矩阵 (N_queries, N_docs)
        similarity_matrix = np.dot(self.document_embeddings, query_embeddings.T).T
        
        # 为每个查询提取结果
        all_results = []
        for i, query in enumerate(queries):
            similarities = similarity_matrix[i]
            sorted_indices = np.argsort(similarities)[::-1]
            
            results = []
            for j in sorted_indices:
                if similarities[j] >= threshold:
                    doc = self.documents[j].copy()
                    doc["vector_score"] = float(similarities[j])
                    results.append(doc)
                    
                    if len(results) >= top_k:
                        break
            
            all_results.append(results)
        
        batch_time = (time.time() - batch_start) * 1000
        print(f"[批量检索] 耗时：{batch_time:.1f}ms, 查询数：{len(queries)}, 平均：{batch_time/len(queries):.1f}ms/查询")
        
        return all_results


if __name__ == "__main__":
    # ========== 测试示例 ==========
    print("=" * 60)
    print("向量检索器测试")
    print("=" * 60)
    
    # 测试数据
    docs = [
        {"content": "CVE-2024-0012 Palo Alto PAN-OS RCE 漏洞，允许远程攻击者执行任意代码", "metadata": {"cve_id": "CVE-2024-0012", "vuln_type": "RCE"}},
        {"content": "SQL 注入攻击手法详解，UNION SELECT 联合查询注入", "metadata": {"vuln_type": "SQLi"}},
        {"content": "XSS 跨站脚本攻击，<script>alert(1)</script> 反射型 XSS", "metadata": {"vuln_type": "XSS"}},
        {"content": "SSRF 服务器端请求伪造，攻击内网服务", "metadata": {"vuln_type": "SSRF"}},
        {"content": "文件上传漏洞，绕过文件类型检查上传 WebShell", "metadata": {"vuln_type": "FileUpload"}},
    ]
    
    # 创建检索器
    print("\n[测试] 创建向量检索器...")
    retriever = VectorRetriever(
        documents=docs,
        model_name="sentence-transformers/all-MiniLM-L6-v2",
        device="cpu"
    )
    
    # 加载模型
    print("\n[测试] 加载模型...")
    retriever.load_model()
    
    # 测试查询 1: RCE 相关
    print("\n" + "=" * 60)
    print("测试查询 1: '远程代码执行漏洞'")
    print("=" * 60)
    results = retriever.search("远程代码执行漏洞", top_k=3, threshold=0.3)
    for i, r in enumerate(results, 1):
        print(f"[{i}] {r['content'][:60]}...")
        print(f"    相似度：{r['vector_score']:.4f}, CVE: {r['metadata'].get('cve_id', 'N/A')}")
    
    # 测试查询 2: SQL 注入
    print("\n" + "=" * 60)
    print("测试查询 2: '数据库注入攻击'")
    print("=" * 60)
    results = retriever.search("数据库注入攻击", top_k=3, threshold=0.3)
    for i, r in enumerate(results, 1):
        print(f"[{i}] {r['content'][:60]}...")
        print(f"    相似度：{r['vector_score']:.4f}, 类型：{r['metadata'].get('vuln_type', 'N/A')}")
    
    # 测试查询 3: 语义相关但关键词不匹配
    print("\n" + "=" * 60)
    print("测试查询 3: '网页脚本注入' (应匹配 XSS)")
    print("=" * 60)
    results = retriever.search("网页脚本注入", top_k=3, threshold=0.3)
    for i, r in enumerate(results, 1):
        print(f"[{i}] {r['content'][:60]}...")
        print(f"    相似度：{r['vector_score']:.4f}, 类型：{r['metadata'].get('vuln_type', 'N/A')}")
    
    # 性能统计
    print("\n" + "=" * 60)
    print("性能统计")
    print("=" * 60)
    print(f"总查询数：{retriever.stats['total_queries']}")
    print(f"平均延迟：{retriever.stats['avg_latency_ms']:.1f}ms")
    print(f"缓存命中：{retriever.stats['cache_hits']}")
    
    print("\n✅ 向量检索器测试完成！")

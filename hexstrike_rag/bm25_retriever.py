"""
BM25 召回器 - Step 1

工程执行版 v2.0
目标：保证精确实体召回 (CVE 编号、端口号、产品名)
耗时：<50ms
"""

from typing import List, Dict
from rank_bm25 import BM25Okapi
import re


class BM25Retriever:
    """
    BM25 召回器
    
    用于精确匹配 CVE 编号、端口号、产品名等专业术语
    """
    
    def __init__(self, documents: List[Dict] = None):
        """
        Args:
            documents: 文档列表，每个文档包含：
                - content: 内容
                - metadata: 元数据
                - chunk_hash: 哈希值
        """
        self.documents = documents or []
        self.bm25 = None
        
        if documents:
            self._build_index()
    
    def _tokenize(self, text: str) -> List[str]:
        """
        分词器
        
        针对安全知识优化：
        - 保留 CVE 编号 (CVE-2024-0012)
        - 保留端口号 (4444, 8080)
        - 保留产品名 (Palo Alto, PAN-OS)
        - 保留专业术语 (RCE, SQLi, XSS)
        """
        # 提取 CVE 编号
        cve_pattern = r'CVE-\d{4}-\d+'
        cve_matches = re.findall(cve_pattern, text, re.IGNORECASE)
        
        # 提取端口号
        port_pattern = r'\b\d{2,5}\b'
        port_matches = re.findall(port_pattern, text)
        
        # 提取专业术语
        tech_terms = ['RCE', 'SQLi', 'XSS', 'SSRF', 'XXE', 'SSTI', 'CSRF', 'DoS', 'PoC', 'Exploit']
        term_matches = [term for term in tech_terms if term.lower() in text.lower()]
        
        # 普通分词
        words = text.lower().split()
        
        # 合并所有 token
        tokens = words + cve_matches + port_matches + term_matches
        return tokens
    
    def _build_index(self):
        """构建 BM25 索引"""
        if not self.documents:
            return
        
        # 分词
        tokenized_docs = [self._tokenize(doc.get("content", "")) for doc in self.documents]
        
        # 构建 BM25 索引
        self.bm25 = BM25Okapi(tokenized_docs)
    
    def add_documents(self, documents: List[Dict]):
        """添加文档到索引"""
        self.documents.extend(documents)
        self._build_index()
    
    def search(self, query: str, top_k: int = 50) -> List[Dict]:
        """
        BM25 检索
        
        Args:
            query: 查询文本
            top_k: 返回结果数量
        
        Returns:
            检索结果列表
        """
        if not self.bm25 or not self.documents:
            return []
        
        # 分词
        query_tokens = self._tokenize(query)
        
        # 计算 BM25 分数
        scores = self.bm25.get_scores(query_tokens)
        
        # 排序
        sorted_indices = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)
        
        # 返回 top-k
        results = []
        for i in sorted_indices[:top_k]:
            if scores[i] > 0:
                doc = self.documents[i].copy()
                doc["bm25_score"] = float(scores[i])
                results.append(doc)
        
        return results


if __name__ == "__main__":
    # 测试示例
    docs = [
        {"content": "CVE-2024-0012 Palo Alto PAN-OS RCE 漏洞", "metadata": {"cve_id": "CVE-2024-0012"}},
        {"content": "SQL 注入攻击手法 UNION SELECT", "metadata": {"vuln_type": "SQLi"}},
        {"content": "XSS 跨站脚本攻击 <script>alert(1)</script>", "metadata": {"vuln_type": "XSS"}},
    ]
    
    retriever = BM25Retriever(docs)
    
    # 测试 CVE 查询
    results = retriever.search("CVE-2024-0012", top_k=2)
    print(f"CVE 查询结果：{len(results)}条")
    for r in results:
        print(f"  - {r['content'][:50]}... (score: {r['bm25_score']:.2f})")

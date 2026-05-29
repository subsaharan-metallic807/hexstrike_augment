"""
去重模块 - 基于哈希去重

工程执行版 v2.0
"""

import hashlib
from typing import List, Dict, Set
from dataclasses import dataclass
import json
import os


@dataclass
class DeduplicationResult:
    """去重结果"""
    total: int  # 总文档数
    unique: int  # 去重后数量
    duplicates: int  # 重复数量
    duplicate_rate: float  # 重复率
    
    def __str__(self):
        return f"去重：{self.total} → {self.unique} (重复{self.duplicates}条，{self.duplicate_rate:.2%})"


class DocumentDeduplicator:
    """
    文档去重器
    
    支持 3 种去重策略：
    1. 精确去重：基于内容哈希
    2. 模糊去重：基于元数据组合
    3. 语义去重：基于向量相似度 (需要额外配置)
    """
    
    def __init__(self, strategy: str = "exact"):
        """
        Args:
            strategy: 去重策略
                - "exact": 精确去重 (基于内容哈希)
                - "fuzzy": 模糊去重 (基于元数据)
                - "semantic": 语义去重 (基于向量相似度)
        """
        self.strategy = strategy
        self.seen_hashes: Set[str] = set()
        self.seen_metadata: Dict[str, str] = {}  # hash -> chunk_id
    
    def compute_content_hash(self, content: str) -> str:
        """
        计算内容哈希
        
        Args:
            content: 文档内容
        
        Returns:
            MD5 哈希值
        """
        # 标准化：去除空白字符
        normalized = " ".join(content.split())
        return hashlib.md5(normalized.encode()).hexdigest()
    
    def compute_metadata_hash(self, metadata: dict) -> str:
        """
        计算元数据哈希
        
        Args:
            metadata: 元数据字典
        
        Returns:
            MD5 哈希值
        """
        # 提取关键字段
        key_fields = {
            "cve_id": metadata.get("cve_id", ""),
            "product": metadata.get("product", ""),
            "vuln_type": metadata.get("vuln_type", ""),
            "source": metadata.get("source", "")
        }
        
        # 排序后哈希 (保证一致性)
        key_str = json.dumps(key_fields, sort_keys=True)
        return hashlib.md5(key_str.encode()).hexdigest()
    
    def deduplicate_exact(self, documents: List[dict]) -> tuple[List[dict], DeduplicationResult]:
        """
        精确去重 (基于内容哈希)
        
        Args:
            documents: 文档列表，每个文档包含：
                - content: 内容
                - metadata: 元数据
                - chunk_id: 唯一标识
        
        Returns:
            (去重后的文档列表，去重结果)
        """
        unique_docs = []
        seen_hashes = set()
        duplicate_count = 0
        
        for doc in documents:
            content_hash = self.compute_content_hash(doc.get("content", ""))
            
            if content_hash not in seen_hashes:
                seen_hashes.add(content_hash)
                unique_docs.append(doc)
            else:
                duplicate_count += 1
        
        result = DeduplicationResult(
            total=len(documents),
            unique=len(unique_docs),
            duplicates=duplicate_count,
            duplicate_rate=duplicate_count / len(documents) if documents else 0
        )
        
        return unique_docs, result
    
    def deduplicate_fuzzy(self, documents: List[dict]) -> tuple[List[dict], DeduplicationResult]:
        """
        模糊去重 (基于元数据组合)
        
        Args:
            documents: 文档列表
        
        Returns:
            (去重后的文档列表，去重结果)
        """
        unique_docs = []
        seen_metadata_hashes = {}
        duplicate_count = 0
        
        for doc in documents:
            metadata = doc.get("metadata", {})
            metadata_hash = self.compute_metadata_hash(metadata)
            
            if metadata_hash not in seen_metadata_hashes:
                seen_metadata_hashes[metadata_hash] = doc
                unique_docs.append(doc)
            else:
                # 保留置信度更高的
                existing_doc = seen_metadata_hashes[metadata_hash]
                existing_conf = existing_doc.get("metadata", {}).get("confidence", 0)
                current_conf = metadata.get("confidence", 0)
                
                if current_conf > existing_conf:
                    # 替换为置信度更高的
                    idx = unique_docs.index(existing_doc)
                    unique_docs[idx] = doc
                    seen_metadata_hashes[metadata_hash] = doc
                
                duplicate_count += 1
        
        result = DeduplicationResult(
            total=len(documents),
            unique=len(unique_docs),
            duplicates=duplicate_count,
            duplicate_rate=duplicate_count / len(documents) if documents else 0
        )
        
        return unique_docs, result
    
    def deduplicate(self, documents: List[dict]) -> tuple[List[dict], DeduplicationResult]:
        """
        执行去重
        
        Args:
            documents: 文档列表
        
        Returns:
            (去重后的文档列表，去重结果)
        """
        if self.strategy == "exact":
            return self.deduplicate_exact(documents)
        elif self.strategy == "fuzzy":
            return self.deduplicate_fuzzy(documents)
        else:
            # 默认使用精确去重
            return self.deduplicate_exact(documents)
    
    def save_state(self, filepath: str):
        """保存去重状态"""
        state = {
            "seen_hashes": list(self.seen_hashes),
            "seen_metadata": self.seen_metadata
        }
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(state, f, indent=2)
    
    def load_state(self, filepath: str):
        """加载去重状态"""
        if not os.path.exists(filepath):
            return
        
        with open(filepath, 'r', encoding='utf-8') as f:
            state = json.load(f)
        
        self.seen_hashes = set(state.get("seen_hashes", []))
        self.seen_metadata = state.get("seen_metadata", {})


if __name__ == "__main__":
    # 测试示例
    docs = [
        {"content": "CVE-2024-0012 RCE 漏洞", "metadata": {"cve_id": "CVE-2024-0012"}, "chunk_id": "1"},
        {"content": "CVE-2024-0012 RCE 漏洞", "metadata": {"cve_id": "CVE-2024-0012"}, "chunk_id": "2"},  # 重复
        {"content": "SQL 注入攻击", "metadata": {"vuln_type": "SQLi"}, "chunk_id": "3"},
        {"content": "CVE-2024-0013 XSS 漏洞", "metadata": {"cve_id": "CVE-2024-0013"}, "chunk_id": "4"},
    ]
    
    dedup = DocumentDeduplicator(strategy="exact")
    unique_docs, result = dedup.deduplicate(docs)
    
    print(f"原始文档：{len(docs)}")
    print(f"去重结果：{result}")
    print(f"去重后文档：{len(unique_docs)}")

"""
安全知识统一元数据 Schema

工程执行版 v2.0 - 14 个核心字段
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional
import hashlib
import json


@dataclass
class SecurityKnowledgeMetadata:
    """安全知识元数据 - 14 个核心字段"""
    
    # ========== 1. 核心标识 ==========
    cve_id: Optional[str] = None
    chunk_hash: str = ""
    
    # ========== 2. 漏洞属性 ==========
    product: str = ""
    version_range: str = ""
    vuln_type: str = ""
    cvss_score: float = 0.0
    severity: str = ""
    
    # ========== 3. 攻击属性 ==========
    attack_stage: str = ""
    tool_tags: List[str] = field(default_factory=list)
    
    # ========== 4. 时效属性 ==========
    publish_time: Optional[datetime] = None
    last_verified_time: Optional[datetime] = None
    is_expired: bool = False
    
    # ========== 5. 质量属性 ==========
    confidence: float = 1.0
    source: str = ""
    has_poc: bool = False
    has_payload: bool = False
    
    def __post_init__(self):
        if not self.chunk_hash:
            self.chunk_hash = self._generate_hash()
        if self.last_verified_time and not self.is_expired:
            days_since_verify = (datetime.now() - self.last_verified_time).days
            if days_since_verify > 730:
                self.is_expired = True
    
    def _generate_hash(self) -> str:
        content = f"{self.cve_id}|{self.product}|{self.vuln_type}|{self.source}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "chunk_hash": self.chunk_hash,
            "product": self.product,
            "version_range": self.version_range,
            "vuln_type": self.vuln_type,
            "cvss_score": self.cvss_score,
            "severity": self.severity,
            "attack_stage": self.attack_stage,
            "tool_tags": self.tool_tags,
            "publish_time": self.publish_time.isoformat() if self.publish_time else None,
            "last_verified_time": self.last_verified_time.isoformat() if self.last_verified_time else None,
            "is_expired": self.is_expired,
            "confidence": self.confidence,
            "source": self.source,
            "has_poc": self.has_poc,
            "has_payload": self.has_payload
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "SecurityKnowledgeMetadata":
        publish_time = None
        if data.get("publish_time"):
            try:
                publish_time = datetime.fromisoformat(data["publish_time"])
            except:
                pass
        
        last_verified_time = None
        if data.get("last_verified_time"):
            try:
                last_verified_time = datetime.fromisoformat(data["last_verified_time"])
            except:
                pass
        
        return cls(
            cve_id=data.get("cve_id"),
            chunk_hash=data.get("chunk_hash", ""),
            product=data.get("product", ""),
            version_range=data.get("version_range", ""),
            vuln_type=data.get("vuln_type", ""),
            cvss_score=float(data.get("cvss_score", 0.0)),
            severity=data.get("severity", ""),
            attack_stage=data.get("attack_stage", ""),
            tool_tags=data.get("tool_tags", []),
            publish_time=publish_time,
            last_verified_time=last_verified_time,
            is_expired=data.get("is_expired", False),
            confidence=float(data.get("confidence", 1.0)),
            source=data.get("source", ""),
            has_poc=data.get("has_poc", False),
            has_payload=data.get("has_payload", False)
        )
    
    def to_filter_dict(self) -> dict:
        conditions = {}
        if self.cve_id:
            conditions["cve_id"] = self.cve_id
        if self.product:
            conditions["product"] = self.product
        if self.vuln_type:
            conditions["vuln_type"] = self.vuln_type
        if self.severity:
            conditions["severity"] = self.severity
        if self.attack_stage:
            conditions["attack_stage"] = self.attack_stage
        if self.source:
            conditions["source"] = self.source
        conditions["is_expired"] = False
        return conditions
    
    def validate(self) -> tuple:
        errors = []
        required_fields = ["product", "vuln_type", "source", "chunk_hash"]
        for field_name in required_fields:
            if not getattr(self, field_name):
                errors.append(f"必填字段缺失：{field_name}")
        if not (0.0 <= self.cvss_score <= 10.0):
            errors.append(f"CVSS 评分超出范围：{self.cvss_score}")
        if not (0.0 <= self.confidence <= 1.0):
            errors.append(f"置信度超出范围：{self.confidence}")
        valid_severity = ["Critical", "High", "Medium", "Low", "Info", ""]
        if self.severity not in valid_severity:
            errors.append(f"无效的严重程度：{self.severity}")
        return (len(errors) == 0, errors)


if __name__ == "__main__":
    metadata = SecurityKnowledgeMetadata(
        cve_id="CVE-2024-0012",
        product="Palo Alto PAN-OS",
        vuln_type="RCE",
        severity="Critical",
        source="CVE",
        has_poc=True
    )
    print(f"✅ 元数据创建成功：{metadata}")
    print(f"✅ 验证结果：{metadata.validate()}")

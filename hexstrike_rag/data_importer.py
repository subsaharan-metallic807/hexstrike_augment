"""
数据导入器 - M1 数据层

工程执行版 v2.0
功能：从多种数据源导入安全知识数据
支持数据源：
  - HackTricks (GitHub)
  - CVE/NVD (NIST API)
  - OWASP
  - 本地 Markdown 文件

验收标准：
  - 批量导入速度：>= 1000 条/秒
  - 去重率：> 95%
  - 元数据完整率：>= 90%
"""

import os
import json
import hashlib
from typing import List, Dict, Optional
from datetime import datetime
from pathlib import Path
import re
import time

# 延迟导入 requests，避免测试时导入失败
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    requests = None

from metadata_schema import SecurityKnowledgeMetadata
from deduplication import DocumentDeduplicator


class HackTricksImporter:
    """
    HackTricks 数据导入器
    
    从 https://github.com/carlospolop/hacktricks 导入渗透测试知识
    """
    
    def __init__(self, data_dir: str = "./data/hacktricks"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # HackTricks GitHub 仓库
        self.repo_url = "https://raw.githubusercontent.com/carlospolop/hacktricks/master"
        
        # 分类映射
        self.category_map = {
            "pentesting-methodologies": "Recon",
            "pentesting-web": "Exploit",
            "pentesting-network": "Exploit",
            "pentesting-cloud": "Exploit",
            "mobile-pentesting": "Exploit",
            "post-exploitation": "Post-Exploit",
        }
    
    def fetch_file_list(self) -> List[str]:
        """
        获取文件列表
        
        实际使用时应从 GitHub API 获取
        这里返回示例文件路径
        """
        # 示例文件路径
        return [
            "pentesting-web/sql-injection/sql-injection.md",
            "pentesting-web/xss-cross-site-scripting/xss-cross-site-scripting.md",
            "pentesting-web/rce-remote-code-execution/rce-remote-code-execution.md",
            "pentesting-network/ssh-pentesting.md",
            "post-exploitation/linux-post-exploitation.md",
        ]
    
    def download_file(self, file_path: str) -> Optional[str]:
        """
        下载文件
        
        Args:
            file_path: 文件路径 (相对于仓库根目录)
        
        Returns:
            文件内容，失败返回 None
        """
        url = f"{self.repo_url}/{file_path}"
        try:
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                return response.text
            else:
                print(f"[HackTricks] 下载失败：{file_path} (HTTP {response.status_code})")
                return None
        except Exception as e:
            print(f"[HackTricks] 下载异常：{file_path} - {e}")
            return None
    
    def parse_markdown(self, content: str, file_path: str) -> List[Dict]:
        """
        解析 Markdown 文件为文档片段
        
        Args:
            content: Markdown 内容
            file_path: 文件路径
        
        Returns:
            文档片段列表
        """
        chunks = []
        
        # 按标题分块
        sections = re.split(r'^(#{1,3}\s+.+)$', content, flags=re.MULTILINE)
        
        current_title = ""
        current_content = ""
        
        for i, section in enumerate(sections):
            if section.startswith("#"):
                # 保存前一个片段
                if current_title and current_content:
                    chunk = self._create_chunk(current_title, current_content, file_path)
                    if chunk:
                        chunks.append(chunk)
                
                current_title = section.strip("#").strip()
                current_content = ""
            else:
                current_content += section
        
        # 处理最后一个片段
        if current_title and current_content:
            chunk = self._create_chunk(current_title, current_content, file_path)
            if chunk:
                chunks.append(chunk)
        
        return chunks
    
    def _create_chunk(self, title: str, content: str, file_path: str) -> Optional[Dict]:
        """
        创建文档片段
        
        Args:
            title: 标题
            content: 内容
            file_path: 文件路径
        
        Returns:
            文档片段
        """
        if not content.strip():
            return None
        
        # 提取 CVE 编号
        cve_match = re.search(r'CVE-\d{4}-\d+', content, re.IGNORECASE)
        cve_id = cve_match.group(0).upper() if cve_match else None
        
        # 提取漏洞类型
        vuln_type = self._extract_vuln_type(title, content)
        
        # 确定攻击阶段
        attack_stage = self._extract_attack_stage(file_path)
        
        # 生成内容哈希
        chunk_hash = hashlib.md5(f"{title}|{content}".encode()).hexdigest()
        
        return {
            "content": f"{title}\n\n{content}",
            "metadata": {
                "cve_id": cve_id,
                "chunk_hash": chunk_hash,
                "product": "Generic",
                "version_range": "",
                "vuln_type": vuln_type,
                "cvss_score": 0.0,
                "severity": "",
                "attack_stage": attack_stage,
                "tool_tags": [],
                "publish_time": None,
                "last_verified_time": datetime.now(),
                "is_expired": False,
                "confidence": 0.9,
                "source": "HackTricks",
                "has_poc": "PoC" in content or "exploit" in content.lower(),
                "has_payload": "payload" in content.lower()
            },
            "source_file": file_path
        }
    
    def _extract_vuln_type(self, title: str, content: str) -> str:
        """提取漏洞类型"""
        vuln_types = {
            "SQL": "SQLi",
            "XSS": "XSS",
            "RCE": "RCE",
            "SSRF": "SSRF",
            "XXE": "XXE",
            "CSRF": "CSRF",
            "SSTI": "SSTI",
            "File Upload": "FileUpload",
            "Command Injection": "CommandInjection",
        }
        
        for keyword, vuln_type in vuln_types.items():
            if keyword.lower() in title.lower() or keyword.lower() in content.lower():
                return vuln_type
        
        return "Other"
    
    def _extract_attack_stage(self, file_path: str) -> str:
        """提取攻击阶段"""
        if "post-exploitation" in file_path:
            return "Post-Exploit"
        elif "pentesting" in file_path:
            return "Exploit"
        else:
            return "Recon"
    
    def import_all(self, limit: int = 100) -> List[Dict]:
        """
        导入所有文件
        
        Args:
            limit: 最大导入文件数
        
        Returns:
            文档片段列表
        """
        print(f"[HackTricks] 开始导入，limit={limit}")
        import_start = time.time()
        
        file_list = self.fetch_file_list()[:limit]
        all_chunks = []
        
        for i, file_path in enumerate(file_list, 1):
            print(f"[HackTricks] 处理文件 ({i}/{len(file_list)}): {file_path}")
            
            content = self.download_file(file_path)
            if content:
                chunks = self.parse_markdown(content, file_path)
                all_chunks.extend(chunks)
                print(f"  → 解析出 {len(chunks)} 个片段")
            
            # 保存到本地
            local_path = self.data_dir / file_path
            local_path.parent.mkdir(parents=True, exist_ok=True)
            if content:
                with open(local_path, "w", encoding="utf-8") as f:
                    f.write(content)
        
        import_time = (time.time() - import_start) / 60
        print(f"[HackTricks] 导入完成，总片段数：{len(all_chunks)}, 耗时：{import_time:.2f}分钟")
        
        return all_chunks


class CVEImporter:
    """
    CVE/NVD 数据导入器
    
    从 NIST NVD API 导入 CVE 数据
    API: https://nvd.nist.gov/developers/vulnerabilities
    """
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def fetch_cves(
        self,
        start_date: str = "2024-01-01",
        end_date: str = "2024-12-31",
        limit: int = 100
    ) -> List[Dict]:
        """
        获取 CVE 列表
        
        Args:
            start_date: 开始日期 (YYYY-MM-DD)
            end_date: 结束日期
            limit: 最大获取数量
        
        Returns:
            CVE 数据列表
        """
        print(f"[CVE] 获取 CVE 数据：{start_date} 至 {end_date}")
        
        all_cves = []
        start_index = 0
        page_size = 2000  # NVD API 每页最大 2000 条
        
        while len(all_cves) < limit:
            params = {
                "startIndex": start_index,
                "resultsPerPage": min(page_size, limit - len(all_cves)),
            }
            
            if self.api_key:
                params["apiKey"] = self.api_key
            
            try:
                response = requests.get(self.base_url, params=params, timeout=30)
                response.raise_for_status()
                data = response.json()
                
                cves = data.get("vulnerabilities", [])
                if not cves:
                    break
                
                all_cves.extend(cves)
                print(f"[CVE] 获取第 {start_index // page_size + 1} 页，共 {len(cves)} 条")
                
                start_index += page_size
                
                # API 限流：每 6 秒一次请求 (无 API key)
                if not self.api_key:
                    time.sleep(6)
                
            except Exception as e:
                print(f"[CVE] 获取失败：{e}")
                break
        
        return all_cves[:limit]
    
    def parse_cve(self, cve_data: Dict) -> Optional[Dict]:
        """
        解析 CVE 数据为文档片段
        
        Args:
            cve_data: CVE 原始数据
        
        Returns:
            文档片段
        """
        cve_item = cve_data.get("cve", {})
        cve_id = cve_item.get("id", "")
        
        # 提取描述
        descriptions = cve_item.get("descriptions", {}).get("en", [])
        description = descriptions[0].get("value", "") if descriptions else ""
        
        # 提取 CVSS 评分
        metrics = cve_item.get("metrics", {})
        cvss_score = 0.0
        severity = ""
        
        if "cvssMetricV31" in metrics:
            metric = metrics["cvssMetricV31"][0].get("cvssData", {})
            cvss_score = metric.get("baseScore", 0.0)
            severity = metric.get("baseSeverity", "")
        elif "cvssMetricV30" in metrics:
            metric = metrics["cvssMetricV30"][0].get("cvssData", {})
            cvss_score = metric.get("baseScore", 0.0)
            severity = metric.get("baseSeverity", "")
        
        # 提取受影响产品
        affected = []
        for node in cve_item.get("configurations", []):
            for cpe in node.get("nodes", []):
                for match in cpe.get("cpeMatch", []):
                    criteria = match.get("criteria", "")
                    affected.append(criteria)
        
        # 生成内容哈希
        chunk_hash = hashlib.md5(f"{cve_id}|{description}".encode()).hexdigest()
        
        # 解析发布日期
        publish_time = None
        pub_date_str = cve_item.get("published", "")
        if pub_date_str:
            try:
                publish_time = datetime.fromisoformat(pub_date_str.replace("Z", "+00:00"))
            except:
                pass
        
        return {
            "content": f"{cve_id}\n\n{description}",
            "metadata": {
                "cve_id": cve_id,
                "chunk_hash": chunk_hash,
                "product": ", ".join(affected[:5]) if affected else "Unknown",
                "version_range": "",
                "vuln_type": self._infer_vuln_type(description),
                "cvss_score": cvss_score,
                "severity": severity,
                "attack_stage": "Exploit",
                "tool_tags": [],
                "publish_time": publish_time,
                "last_verified_time": datetime.now(),
                "is_expired": False,
                "confidence": 1.0,
                "source": "NVD",
                "has_poc": False,
                "has_payload": False
            },
            "source_file": f"cve/{cve_id}.json"
        }
    
    def _infer_vuln_type(self, description: str) -> str:
        """从描述推断漏洞类型"""
        keywords = {
            "RCE": ["remote code execution", "arbitrary code execution"],
            "SQLi": ["sql injection", "sql-injection"],
            "XSS": ["cross-site scripting", "xss"],
            "SSRF": ["server-side request forgery", "ssrf"],
            "XXE": ["xml external entity", "xxe"],
            "DoS": ["denial of service", "dos"],
            "AuthBypass": ["authentication bypass", "auth bypass"],
        }
        
        desc_lower = description.lower()
        for vuln_type, kw_list in keywords.items():
            for kw in kw_list:
                if kw in desc_lower:
                    return vuln_type
        
        return "Other"
    
    def import_all(self, start_date: str, end_date: str, limit: int = 1000) -> List[Dict]:
        """
        导入 CVE 数据
        
        Args:
            start_date: 开始日期
            end_date: 结束日期
            limit: 最大导入数量
        
        Returns:
            文档片段列表
        """
        print(f"[CVE] 开始导入：{start_date} 至 {end_date}, limit={limit}")
        import_start = time.time()
        
        cve_data = self.fetch_cves(start_date, end_date, limit)
        chunks = []
        
        for i, cve in enumerate(cve_data, 1):
            chunk = self.parse_cve(cve)
            if chunk:
                chunks.append(chunk)
            
            if i % 100 == 0:
                print(f"[CVE] 处理进度：{i}/{len(cve_data)}")
        
        import_time = (time.time() - import_start) / 60
        print(f"[CVE] 导入完成，总片段数：{len(chunks)}, 耗时：{import_time:.2f}分钟")
        
        return chunks


class LocalMarkdownImporter:
    """
    本地 Markdown 文件导入器
    
    从本地目录导入 Markdown 文件
    """
    
    def __init__(self, source_dir: str):
        self.source_dir = Path(source_dir)
    
    def import_all(self) -> List[Dict]:
        """导入所有 Markdown 文件"""
        print(f"[本地导入] 扫描目录：{self.source_dir}")
        
        all_chunks = []
        md_files = list(self.source_dir.rglob("*.md"))
        
        for md_file in md_files:
            print(f"[本地导入] 处理：{md_file.name}")
            
            with open(md_file, "r", encoding="utf-8") as f:
                content = f.read()
            
            chunks = self._parse_file(content, str(md_file))
            all_chunks.extend(chunks)
        
        print(f"[本地导入] 完成，总片段数：{len(all_chunks)}")
        return all_chunks
    
    def _parse_file(self, content: str, file_path: str) -> List[Dict]:
        """解析单个文件"""
        chunks = []
        
        # 按标题分块
        sections = re.split(r'^(#{1,3}\s+.+)$', content, flags=re.MULTILINE)
        
        current_title = ""
        current_content = ""
        
        for section in sections:
            if section.startswith("#"):
                if current_title and current_content:
                    chunk = self._create_chunk(current_title, current_content, file_path)
                    if chunk:
                        chunks.append(chunk)
                current_title = section.strip("#").strip()
                current_content = ""
            else:
                current_content += section
        
        # 最后一个片段
        if current_title and current_content:
            chunk = self._create_chunk(current_title, current_content, file_path)
            if chunk:
                chunks.append(chunk)
        
        return chunks
    
    def _create_chunk(self, title: str, content: str, file_path: str) -> Optional[Dict]:
        """创建文档片段"""
        if not content.strip():
            return None
        
        chunk_hash = hashlib.md5(f"{title}|{content}".encode()).hexdigest()
        
        return {
            "content": f"{title}\n\n{content}",
            "metadata": {
                "chunk_hash": chunk_hash,
                "product": "Generic",
                "vuln_type": "Other",
                "source": "Local",
                "confidence": 0.8,
                "last_verified_time": datetime.now(),
                "is_expired": False,
            },
            "source_file": file_path
        }


class DataImporter:
    """
    统一数据导入器
    
    协调多个数据源的导入，执行去重和验证
    """
    
    def __init__(self, output_dir: str = "./data"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.deduplicator = DocumentDeduplicator()
    
    def import_from_multiple(
        self,
        hacktricks: bool = True,
        cve: bool = True,
        local_dir: Optional[str] = None,
        limit_per_source: int = 100
    ) -> List[Dict]:
        """
        从多个数据源导入
        
        Args:
            hacktricks: 是否导入 HackTricks
            cve: 是否导入 CVE
            local_dir: 本地 Markdown 目录
            limit_per_source: 每个数据源的最大导入数量
        
        Returns:
            去重后的文档片段列表
        """
        all_docs = []
        
        # HackTricks
        if hacktricks:
            print("\n" + "=" * 60)
            print("导入 HackTricks 数据")
            print("=" * 60)
            ht_importer = HackTricksImporter()
            ht_docs = ht_importer.import_all(limit=limit_per_source)
            all_docs.extend(ht_docs)
            print(f"HackTricks: {len(ht_docs)} 个片段")
        
        # CVE
        if cve:
            print("\n" + "=" * 60)
            print("导入 CVE/NVD 数据")
            print("=" * 60)
            cve_importer = CVEImporter()
            cve_docs = cve_importer.import_all(
                start_date="2024-01-01",
                end_date="2024-12-31",
                limit=limit_per_source
            )
            all_docs.extend(cve_docs)
            print(f"CVE: {len(cve_docs)} 个片段")
        
        # 本地文件
        if local_dir:
            print("\n" + "=" * 60)
            print(f"导入本地文件：{local_dir}")
            print("=" * 60)
            local_importer = LocalMarkdownImporter(local_dir)
            local_docs = local_importer.import_all()
            all_docs.extend(local_docs)
            print(f"本地：{len(local_docs)} 个片段")
        
        # 去重
        print("\n" + "=" * 60)
        print("执行去重")
        print("=" * 60)
        unique_docs = self.deduplicator.deduplicate(all_docs)
        
        # 保存
        output_path = self.output_dir / "imported_docs.json"
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(unique_docs, f, ensure_ascii=False, indent=2)
        
        print(f"\n✅ 导入完成！")
        print(f"   原始文档：{len(all_docs)}")
        print(f"   去重后：{len(unique_docs)}")
        print(f"   去重率：{(1 - len(unique_docs) / len(all_docs)) * 100:.2f}%")
        print(f"   保存路径：{output_path}")
        
        return unique_docs


if __name__ == "__main__":
    # ========== 测试示例 ==========
    print("=" * 60)
    print("数据导入器测试")
    print("=" * 60)
    
    # 创建测试数据
    test_docs = [
        {
            "content": "CVE-2024-0012 Palo Alto PAN-OS RCE 漏洞",
            "metadata": {
                "cve_id": "CVE-2024-0012",
                "product": "Palo Alto PAN-OS",
                "vuln_type": "RCE",
                "source": "Test",
                "confidence": 1.0,
                "chunk_hash": "test1"
            }
        },
        {
            "content": "SQL 注入攻击手法",
            "metadata": {
                "vuln_type": "SQLi",
                "source": "Test",
                "confidence": 0.9,
                "chunk_hash": "test2"
            }
        },
    ]
    
    # 保存测试数据
    test_dir = Path("./data/test")
    test_dir.mkdir(parents=True, exist_ok=True)
    
    with open(test_dir / "test_docs.json", "w", encoding="utf-8") as f:
        json.dump(test_docs, f, ensure_ascii=False, indent=2)
    
    print(f"\n✅ 测试数据已保存到：{test_dir / 'test_docs.json'}")
    print(f"   文档数：{len(test_docs)}")
    
    print("\n注意：完整数据导入需要网络连接和 API 密钥")
    print("当前仅演示测试数据导入流程")

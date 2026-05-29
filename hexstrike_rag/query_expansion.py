#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
查询扩展模块 - HexStrike Week 4 核心模块

功能：
- 同义词扩展：安全领域专业术语映射
- 拼写纠错：常见 CVE/漏洞名拼写修正
- 多语言扩展：中英文查询互转
- 查询改写：生成多个变体查询用于扩展召回

目标：提升 Recall@10 和 nDCG@10 指标
"""

import re
import json
from typing import List, Dict, Optional


class SecurityThesaurus:
    """安全领域同义词词典"""

    def __init__(self):
        # 漏洞类型同义词
        self.vuln_synonyms = {
            "sql注入": ["sql injection", "sqli", "sql注入攻击", "sql注入漏洞"],
            "sql injection": ["sql注入", "sqli", "sql注入攻击"],
            "sqli": ["sql注入", "sql injection", "sql注入攻击"],
            "xss": ["跨站脚本", "cross-site scripting", "xss攻击"],
            "跨站脚本": ["xss", "cross-site scripting", "xss攻击"],
            "rce": ["远程代码执行", "remote code execution", "命令执行"],
            "远程代码执行": ["rce", "remote code execution", "命令执行", "代码执行"],
            "命令执行": ["rce", "remote code execution", "远程代码执行"],
            "ssrf": ["服务端请求伪造", "server-side request forgery"],
            "服务端请求伪造": ["ssrf", "server-side request forgery"],
            "csrf": ["跨站请求伪造", "cross-site request forgery"],
            "跨站请求伪造": ["csrf", "cross-site request forgery"],
            "文件上传": ["file upload", "任意文件上传", "upload bypass"],
            "权限绕过": ["auth bypass", "authorization bypass", "越权"],
            "越权": ["权限绕过", "auth bypass", "horizontal privilege escalation"],
            "提权": ["privilege escalation", "escalation", "priv esc"],
            "反序列化": ["deserialization", "unsafe deserialization", "反序列化漏洞"],
            "缓冲区溢出": ["buffer overflow", "bof", "栈溢出"],
            "零日漏洞": ["0day", "zero-day", "未公开漏洞"],
            "竞态条件": ["race condition", "并发竞争"],
        }

        # 攻击阶段同义词
        self.stage_synonyms = {
            "信息收集": ["recon", "reconnaissance", "侦查", "侦察"],
            "recon": ["信息收集", "reconnaissance", "侦查"],
            "漏洞利用": ["exploitation", "exploit", "利用"],
            "exploitation": ["漏洞利用", "exploit", "利用"],
            "后渗透": ["post-exploitation", "后渗透攻击", "persistence"],
            "后渗透攻击": ["post-exploitation", "后渗透", "persistence"],
            "横向移动": ["lateral movement", "内网渗透"],
            "权限维持": ["persistence", "后门", "maintaining access"],
        }

        # 工具名同义词
        self.tool_synonyms = {
            "nmap": ["端口扫描", "nmap扫描", "network mapper"],
            "metasploit": ["msf", "meterpreter", "metasploit framework"],
            "msf": ["metasploit", "meterpreter"],
            "burpsuite": ["burp", "burp suite", "抓包工具"],
            "sqlmap": ["sql注入工具", "自动化sql注入"],
            "cobalt strike": ["cs", "cobaltstrike", "c2框架"],
            "nuclei": ["nuclei扫描", "模板扫描"],
            "gobuster": ["目录爆破", "目录扫描"],
            "hashcat": ["密码破解", "hash破解"],
            "john": ["john the ripper", "密码破解"],
        }

    def expand_query(self, query: str) -> List[str]:
        """
        扩展查询词
        
        Args:
            query: 原始查询
            
        Returns:
            扩展后的查询列表
        """
        expanded = [query]
        query_lower = query.lower().strip()

        # 合并所有同义词表
        all_thesauri = {}
        all_thesauri.update(self.vuln_synonyms)
        all_thesauri.update(self.stage_synonyms)
        all_thesauri.update(self.tool_synonyms)

        # 查找匹配的同义词
        for key, synonyms in all_thesauri.items():
            if key in query_lower or query_lower in key:
                for syn in synonyms:
                    if syn not in expanded:
                        expanded.append(query.replace(key, syn) if key in query_lower else syn)

        return expanded[:10]  # 最多返回 10 个变体

    def get_related_terms(self, term: str) -> List[str]:
        """获取相关术语"""
        term_lower = term.lower()
        related = set()

        all_thesauri = {}
        all_thesauri.update(self.vuln_synonyms)
        all_thesauri.update(self.stage_synonyms)
        all_thesauri.update(self.tool_synonyms)

        for key, synonyms in all_thesauri.items():
            if term_lower in key or key in term_lower:
                related.update(synonyms)
            for syn in synonyms:
                if term_lower in syn or syn in term_lower:
                    related.add(key)

        return list(related)


class QueryRewriter:
    """
    查询改写器
    
    功能：
    - 提取关键实体 (CVE编号、产品名、漏洞类型)
    - 生成多视角查询
    - 中英文混合查询处理
    """

    def __init__(self):
        self.thesaurus = SecurityThesaurus()
        # CVE 编号正则
        self.cve_pattern = re.compile(r'(?:CVE|cve)[-\s]*(\d{4})[-\s]*(\d{4,})', re.IGNORECASE)
        # 版本号正则
        self.version_pattern = re.compile(r'(\d+\.\d+(\.\d+)?)')
        # 产品名常见模式
        self.product_patterns = [
            re.compile(r'([\w\s]+)\s*(?:漏洞|漏洞利用|exp|poc|攻击)', re.IGNORECASE),
            re.compile(r'(?:如何利用|exp|poc|攻击)\s*([\w\s]+)', re.IGNORECASE),
        ]

    def extract_entities(self, query: str) -> Dict:
        """提取查询中的关键实体"""
        entities = {
            "cve_ids": [],
            "versions": [],
            "products": [],
            "vuln_types": [],
        }

        # 提取 CVE 编号
        cve_matches = self.cve_pattern.findall(query)
        entities["cve_ids"] = [f"CVE-{year}-{num}" for year, num in cve_matches]

        # 提取版本号
        entities["versions"] = self.version_pattern.findall(query)

        # 提取漏洞类型关键词
        vuln_keywords = [
            "注入", "xss", "rce", "ssrf", "csrf", "上传", "绕过",
            "溢出", "反序列化", "越权", "提权", "竞争条件"
        ]
        query_lower = query.lower()
        for kw in vuln_keywords:
            if kw in query_lower:
                entities["vuln_types"].append(kw)

        return entities

    def rewrite(self, query: str, max_variants: int = 5) -> List[str]:
        """
        改写查询，生成多个变体
        
        Args:
            query: 原始查询
            max_variants: 最大变体数
            
        Returns:
            改写后的查询列表
        """
        variants = [query]
        entities = self.extract_entities(query)

        # 策略1：同义词扩展
        synonyms = self.thesaurus.expand_query(query)
        variants.extend(synonyms)

        # 策略2：如果包含 CVE，生成结构化查询
        if entities["cve_ids"]:
            for cve_id in entities["cve_ids"]:
                variants.append(f"{cve_id} 漏洞详情")
                variants.append(f"{cve_id} exploit")
                variants.append(f"{cve_id} poc")

        # 策略3：如果包含漏洞类型，生成攻击视角查询
        if entities["vuln_types"]:
            for vuln in entities["vuln_types"]:
                variants.append(f"{vuln} 检测方法")
                variants.append(f"{vuln} 防御措施")

        # 去重并限制数量
        seen = set()
        unique_variants = []
        for v in variants:
            v_stripped = v.strip()
            if v_stripped and v_stripped not in seen:
                seen.add(v_stripped)
                unique_variants.append(v_stripped)

        return unique_variants[:max_variants]


class QueryExpander:
    """
    查询扩展主类
    
    整合 SecurityThesaurus 和 QueryRewriter，
    提供统一的查询扩展接口
    """

    def __init__(self):
        self.rewriter = QueryRewriter()
        self.thesaurus = SecurityThesaurus()

    def expand(self, query: str, mode: str = "balanced") -> List[str]:
        """
        扩展查询
        
        Args:
            query: 原始查询
            mode: 扩展模式
                - "conservative": 仅同义词扩展 (2-3 个变体)
                - "balanced": 同义词 + 实体改写 (3-5 个变体)
                - "aggressive": 全量扩展 (5-10 个变体)
                
        Returns:
            扩展后的查询列表
        """
        if mode == "conservative":
            return self.rewriter.rewrite(query, max_variants=3)
        elif mode == "balanced":
            return self.rewriter.rewrite(query, max_variants=5)
        elif mode == "aggressive":
            return self.rewriter.rewrite(query, max_variants=10)
        else:
            return self.rewriter.rewrite(query, max_variants=5)

    def get_related_terms(self, term: str) -> List[str]:
        """获取术语的相关词"""
        return self.thesaurus.get_related_terms(term)

    def extract_entities(self, query: str) -> Dict:
        """提取查询实体"""
        return self.rewriter.extract_entities(query)


if __name__ == '__main__':
    print("=" * 60)
    print("查询扩展模块测试")
    print("=" * 60)

    expander = QueryExpander()

    # 测试用例
    test_queries = [
        "SQL 注入攻击手法",
        "CVE-2024-1234 RCE 漏洞",
        "如何利用 XSS 进行跨站脚本攻击",
        "SSRF 漏洞检测和绕过",
        "文件上传漏洞绕过 WAF",
    ]

    for query in test_queries:
        print(f"\n原始查询: {query}")
        expanded = expander.expand(query, mode="balanced")
        print(f"扩展结果 ({len(expanded)} 个变体):")
        for i, q in enumerate(expanded):
            print(f"  [{i+1}] {q}")

        entities = expander.extract_entities(query)
        if any(entities.values()):
            print(f"提取实体: {entities}")

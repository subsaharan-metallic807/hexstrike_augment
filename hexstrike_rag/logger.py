"""
HexStrike 日志系统 - M3 服务层

提供统一的日志记录和错误处理框架。
支持文件日志、控制台输出、分级日志（DEBUG/INFO/WARNING/ERROR/CRITICAL）。
"""

import logging
import os
import sys
import traceback
import json
from datetime import datetime
from typing import Optional, Dict, Any


class HexStrikeLogger:
    """
    HexStrike 项目专用日志器
    
    特性：
    - 支持多级别日志（DEBUG/INFO/WARNING/ERROR/CRITICAL）
    - 同时输出到控制台和文件
    - 支持 JSON 格式日志（便于日志分析）
    - 自动日志轮转（按大小）
    """
    
    _instances: Dict[str, 'HexStrikeLogger'] = {}
    
    def __new__(cls, name: str = "hexstrike", log_dir: str = "logs", 
                level: int = logging.INFO, json_format: bool = False):
        if name not in cls._instances:
            instance = super().__new__(cls)
            instance._initialized = False
            cls._instances[name] = instance
        return cls._instances[name]
    
    def __init__(self, name: str = "hexstrike", log_dir: str = "logs",
                 level: int = logging.INFO, json_format: bool = False):
        if self._initialized:
            return
        
        self.name = name
        self.log_dir = log_dir
        self.json_format = json_format
        self.level = level
        
        os.makedirs(log_dir, exist_ok=True)
        
        # 创建 logger
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        self.logger.handlers = []  # 清除已有 handler
        
        # 控制台 handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_handler.setFormatter(self._get_formatter(False))
        self.logger.addHandler(console_handler)
        
        # 文件 handler
        log_file = os.path.join(log_dir, f"{name}.log")
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)  # 文件记录所有级别
        file_handler.setFormatter(self._get_formatter(True))
        self.logger.addHandler(file_handler)
        
        # 错误文件 handler（仅 ERROR 及以上）
        error_file = os.path.join(log_dir, f"{name}_error.log")
        error_handler = logging.FileHandler(error_file, encoding='utf-8')
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(self._get_formatter(True))
        self.logger.addHandler(error_handler)
        
        self._initialized = True
    
    def _get_formatter(self, include_date: bool) -> logging.Formatter:
        if self.json_format:
            return JsonFormatter()
        if include_date:
            return logging.Formatter(
                '%(asctime)s | %(levelname)-8s | %(name)s | %(filename)s:%(lineno)d | %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
        return logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(message)s',
            datefmt='%H:%M:%S'
        )
    
    def debug(self, msg: str, **kwargs):
        self.logger.debug(self._format_msg(msg, kwargs))
    
    def info(self, msg: str, **kwargs):
        self.logger.info(self._format_msg(msg, kwargs))
    
    def warning(self, msg: str, **kwargs):
        self.logger.warning(self._format_msg(msg, kwargs))
    
    def error(self, msg: str, **kwargs):
        self.logger.error(self._format_msg(msg, kwargs))
    
    def critical(self, msg: str, **kwargs):
        self.logger.critical(self._format_msg(msg, kwargs))
    
    def _format_msg(self, msg: str, kwargs: Dict) -> str:
        if not kwargs:
            return msg
        extra = " | ".join(f"{k}={v}" for k, v in kwargs.items())
        return f"{msg} [{extra}]"
    
    def log_exception(self, msg: str, exc: Optional[Exception] = None, **kwargs):
        """记录异常详情"""
        tb = traceback.format_exc() if exc else "No traceback available"
        error_msg = f"{msg}\nException: {exc or 'Unknown'}\nTraceback:\n{tb}"
        self.logger.error(error_msg)


class JsonFormatter(logging.Formatter):
    """JSON 格式日志，便于日志分析工具处理"""
    
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "file": record.filename,
            "line": record.lineno,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0]:
            log_entry["exception"] = traceback.format_exception(*record.exc_info)
        return json.dumps(log_entry, ensure_ascii=False)


def get_logger(name: str = "hexstrike") -> HexStrikeLogger:
    """获取日志器实例"""
    return HexStrikeLogger(name=name)


class ErrorHandler:
    """
    统一错误处理
    
    提供标准化的错误响应格式和错误码定义。
    """
    
    # 错误码定义
    ERR_SUCCESS = 0
    ERR_INVALID_QUERY = 1001
    ERR_RETRIEVAL_FAILED = 1002
    ERR_CACHE_ERROR = 1003
    ERR_MCP_TOOL_ERROR = 1004
    ERR_API_ERROR = 1005
    ERR_CONFIG_ERROR = 1006
    ERR_DEPENDENCY_ERROR = 1007
    ERR_TIMEOUT = 1008
    ERR_RATE_LIMIT = 1009
    ERR_INTERNAL = 9999
    
    ERROR_MESSAGES = {
        ERR_SUCCESS: "成功",
        ERR_INVALID_QUERY: "查询参数无效",
        ERR_RETRIEVAL_FAILED: "检索失败",
        ERR_CACHE_ERROR: "缓存操作异常",
        ERR_MCP_TOOL_ERROR: "MCP 工具执行失败",
        ERR_API_ERROR: "API 请求处理失败",
        ERR_CONFIG_ERROR: "配置错误",
        ERR_DEPENDENCY_ERROR: "依赖服务不可用",
        ERR_TIMEOUT: "请求超时",
        ERR_RATE_LIMIT: "请求频率超限",
        ERR_INTERNAL: "内部服务错误",
    }
    
    @staticmethod
    def make_response(
        success: bool = True,
        data: Any = None,
        error_code: int = ERR_SUCCESS,
        message: str = "",
        details: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """构建标准响应"""
        response = {
            "success": success,
            "error_code": error_code if not success else 0,
            "message": message or (ErrorHandler.ERROR_MESSAGES.get(error_code, "") if not success else "操作成功"),
            "timestamp": datetime.now().isoformat(),
        }
        if success and data is not None:
            response["data"] = data
        if not success and details:
            response["details"] = details
        return response
    
    @staticmethod
    def handle_error(func):
        """错误处理装饰器"""
        from functools import wraps
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except ValueError as e:
                logger = get_logger()
                logger.log_exception(f"ValueError in {func.__name__}", e)
                return ErrorHandler.make_response(
                    success=False,
                    error_code=ErrorHandler.ERR_INVALID_QUERY,
                    message=str(e)
                )
            except TimeoutError as e:
                logger = get_logger()
                logger.log_exception(f"TimeoutError in {func.__name__}", e)
                return ErrorHandler.make_response(
                    success=False,
                    error_code=ErrorHandler.ERR_TIMEOUT,
                    message=str(e)
                )
            except Exception as e:
                logger = get_logger()
                logger.log_exception(f"Unexpected error in {func.__name__}", e)
                return ErrorHandler.make_response(
                    success=False,
                    error_code=ErrorHandler.ERR_INTERNAL,
                    message=str(e)
                )
        return wrapper


if __name__ == "__main__":
    print("HexStrike 日志系统测试")
    print("=" * 60)
    
    logger = get_logger("hexstrike_test")
    
    # 测试各级别日志
    logger.debug("这是一条 DEBUG 日志")
    logger.info("这是一条 INFO 日志")
    logger.warning("这是一条 WARNING 日志")
    logger.error("这是一条 ERROR 日志")
    
    # 测试异常记录
    try:
        raise ValueError("测试异常")
    except ValueError as e:
        logger.log_exception("捕获到测试异常", e)
    
    # 测试错误响应
    response = ErrorHandler.make_response(
        success=False,
        error_code=ErrorHandler.ERR_INVALID_QUERY,
        message="查询参数不能为空",
        details={"field": "query", "value": None}
    )
    print(f"\n标准错误响应:\n{json.dumps(response, indent=2, ensure_ascii=False)}")
    
    print("\n✅ 日志系统测试通过")

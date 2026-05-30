import json
from logging.handlers import RotatingFileHandler
from pathlib import Path
from datetime import datetime

import logging


def get_log_dir() -> Path:
    log_dir = Path.home() / ".aiops" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir


def setup_logger(
    log_max_size_mb: int = 10,
    log_backup_count: int = 5,
) -> logging.Logger:
    logger = logging.getLogger("aiops")
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    log_path = get_log_dir() / "ops.log"
    handler = RotatingFileHandler(
        log_path,
        maxBytes=log_max_size_mb * 1024 * 1024,
        backupCount=log_backup_count,
        encoding="utf-8",
    )
    handler.setLevel(logging.DEBUG)

    class JSONFormatter(logging.Formatter):
        def format(self, record: logging.LogRecord) -> str:
            log_entry = {
                "timestamp": datetime.fromtimestamp(record.created).isoformat(),
                "level": record.levelname,
            }
            if hasattr(record, "extra_data"):
                log_entry.update(record.extra_data)
            return json.dumps(log_entry, ensure_ascii=False)

    handler.setFormatter(JSONFormatter())
    logger.addHandler(handler)
    return logger


class OpsLogger:
    def __init__(self, log_max_size_mb: int = 10, log_backup_count: int = 5):
        self._logger = setup_logger(log_max_size_mb, log_backup_count)

    def log_tool_call(
        self,
        tool: str,
        request_id: str = "",
        command: str = "",
        params: dict | None = None,
        path: str = "",
        risk: str = "safe",
        action: str = "executed",
        result: str = "success",
        output_len: int = 0,
        error: str = "",
        level: str = "INFO",
        **extra,
    ):
        """记录一次工具调用。已知字段为强类型；**extra 兜底接纳工具层未来追加的
        字段（如 sandboxed/sandbox_requested），避免每加一字段就改 logger 签名。
        值为 None/空串/0 的强类型字段不写入；extra 内全部原样写入。"""
        extra_data = {
            "request_id": request_id,
            "tool": tool,
            "action": action,
            "result": result,
        }
        if command:
            extra_data["command"] = command
        if params:
            extra_data["params"] = params
        if path:
            extra_data["path"] = path
        if risk:
            extra_data["risk"] = risk
        if output_len:
            extra_data["output_len"] = output_len
        if error:
            extra_data["error"] = error
        extra_data.update(extra)

        log_level = getattr(logging, level.upper(), logging.INFO)
        record = self._logger.makeRecord(
            self._logger.name, log_level, "", 0, "", (), None
        )
        record.extra_data = extra_data
        self._logger.handle(record)

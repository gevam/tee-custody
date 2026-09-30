"""Allow-listed JSON logger."""

import logging
from typing import TextIO

from teecustody.obs.types import AllowListedLogger


def get_logger(name: str) -> AllowListedLogger:
    raise NotImplementedError


class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        raise NotImplementedError


def configure_logging(stream: TextIO, level: int = logging.INFO) -> None:
    raise NotImplementedError

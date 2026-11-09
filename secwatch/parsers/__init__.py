"""Log parsers that normalize raw logs into Event objects."""

from secwatch.parsers.auth_log import parse_auth_log
from secwatch.parsers.cloudtrail import parse_cloudtrail
from secwatch.parsers.web_log import parse_web_log

__all__ = ["parse_auth_log", "parse_web_log", "parse_cloudtrail"]

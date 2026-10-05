"""领域错误：携带 HTTP 状态码与机器可读错误码。"""
from __future__ import annotations


class DomainError(Exception):
    def __init__(self, status: int, code: str, message: str, details: dict | list | None = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.details = details

    def to_response(self) -> dict:
        body: dict = {"error": self.code, "message": self.message}
        if self.details is not None:
            body["details"] = self.details
        return body


def not_found(message: str = "资源不存在或不属于本机构") -> DomainError:
    # 跨机构访问统一 404：既不返回数据，也不泄露资源是否存在。
    return DomainError(404, "NOT_FOUND", message)


def forbidden(message: str) -> DomainError:
    return DomainError(403, "FORBIDDEN", message)


def conflict(code: str, message: str, details=None) -> DomainError:
    return DomainError(409, code, message, details)


def unprocessable(code: str, message: str, details=None) -> DomainError:
    return DomainError(422, code, message, details)

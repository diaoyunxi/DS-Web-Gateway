"""图片代下载的 URL 安全校验（SSRF 防护）。

调用方可以在 messages 里塞任意 image_url，②会代表服务端发起 GET。
若不加限制，可被用于探测/访问本机管理面、内网服务与云元数据地址。
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit


def is_public_host(host: str) -> bool:
    """主机（字面量 IP 或域名）是否只解析到公网单播地址。"""
    host = host.strip("[]")
    try:
        ip = ipaddress.ip_address(host)
        return bool(ip.is_global and not ip.is_multicast and not ip.is_reserved)
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            return False
        if not (ip.is_global and not ip.is_multicast and not ip.is_reserved):
            return False
    return True


def assert_public_image_url(url: str) -> None:
    """校验图片 URL 为 http(s) 且目标为公网地址，否则抛 ValueError。"""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("图片 URL 必须是 http(s) 绝对地址")
    if not is_public_host(parts.hostname):
        raise ValueError("图片 URL 指向非公网地址，已拒绝代下载")

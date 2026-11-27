"""图片代下载 SSRF 防护单测（纯 IP 字面量，不依赖 DNS）。

运行：pytest pytests/test_image_url_guard.py -q
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from gateway.image_guard import assert_public_image_url


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8444/admin/stats",
        "http://localhost/a.png",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.5/a.png",
        "http://192.168.1.1/a.png",
        "http://[::1]/a.png",
        "http://0.0.0.0/a.png",
        "ftp://example.com/a.png",
    ],
)
def test_private_or_reserved_targets_rejected(url):
    # localhost 依赖本机解析，单独保证一定不是公网字面量
    with pytest.raises(ValueError):
        assert_public_image_url(url)


def test_public_ip_accepted():
    assert_public_image_url("http://8.8.8.8/a.png")
    assert_public_image_url("https://93.184.216.34/a.png")

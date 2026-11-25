# -*- coding: utf-8 -*-
"""离线单元测试：不访问网络，覆盖去重、关注列表匹配与表格渲染。"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fetch_intel import dedup, match_watchlist, table  # noqa: E402


def test_dedup_marks_and_splits():
    state = {"seen": {"CVE-2020-1": "2026-01-01"}}
    items = [{"id": "CVE-2020-1"}, {"id": "CVE-2026-9"}, {"id": ""}]
    fresh, total = dedup(items, state)
    assert total == 3
    assert [x["id"] for x in fresh] == ["CVE-2026-9"]
    # 处理过的条目全部入 state，且重复运行不再产生新条目
    fresh2, _ = dedup(items, state)
    assert fresh2 == []


def test_watchlist_case_insensitive_multiword():
    hits = match_watchlist("Unreal Engine RPC vulnerability in FFMPEG plugin")
    assert any("unreal engine" in h for h in hits)
    assert any("ffmpeg" in h for h in hits)

    # 词边界：community 不应命中 unity；onnxruntime 只命中自身，不误命中 onnx
    assert all("unity" not in h for h in
               match_watchlist("Redis cluster bus parser in community edition"))
    assert "AI 运行时: onnx" not in match_watchlist("onnxruntime memory leak")
    assert "AI 运行时: onnxruntime" in match_watchlist("onnxruntime memory leak")
    # 变体本身要能命中
    assert any("cocos" in h for h in match_watchlist("Cocos2d-x scene deserialization"))
    assert match_watchlist("nothing relevant here") == []


def test_table_caps_rows_and_escapes():
    rows = [[f"cve-{i}", "a|b"] for i in range(40)]
    md = table(["id", "desc"], rows, cap=25)
    assert md.count("\n| cve-") == 25
    assert "a\\|b" in md
    assert "共 40 条" in md


if __name__ == "__main__":
    test_dedup_marks_and_splits()
    test_watchlist_case_insensitive_multiword()
    test_table_caps_rows_and_escapes()
    print("离线单元测试 3/3 通过")

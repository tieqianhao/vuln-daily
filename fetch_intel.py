#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""漏洞情报日报聚合器。

三个公开数据源（全部免密钥可用）：
  1. CISA KEV         已知被在野利用的漏洞目录（最高优先级信号）
  2. NVD API 2.0      近 48 小时内修改、CVSS v3 基础分 >= 7.0 的 CVE
  3. GitHub Advisory  近 48 小时内更新的 high / critical 安全公告

关注方向（config/watchlist.json）：关键词命中游戏引擎、内容安全组件等
条目单独成节。去重靠 data/state.json，同一 ID 不重复上报。

用法：
    python fetch_intel.py                # 按当前北京时间生成当日日报
    python fetch_intel.py --dry-run      # 只打印摘要，不写文件
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CN_TZ = timezone(timedelta(hours=8))
WINDOW_HOURS = 48          # NVD / GHSA 回看窗口
KEV_RECENT_DAYS = 3        # KEV 只看近 3 日新增
MAX_ROWS = 25              # 每节最多展示行数
MIN_CVSS = 7.0             # NVD 过滤阈值

WATCHLIST = json.loads((ROOT / "config" / "watchlist.json").read_text(encoding="utf-8"))
STATE_FILE = ROOT / "data" / "state.json"
REPORT_DIR = ROOT / "reports"
DATA_DIR = ROOT / "data"


class SourceError(Exception):
    """单个数据源拉取失败，不影响其他来源。"""


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime, ms: bool = True) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + (".000" if ms else "") + "+00:00"


def http_get_json(url: str, token: str | None = None, timeout: int = 45):
    headers = {"User-Agent": "vuln-daily/1.0", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"token {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)
    except Exception as e:  # noqa: BLE001 —— 统一转成可读的来源级错误
        raise SourceError(f"{url.split('/')[2]}: {e}") from e


def load_state() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    return {"seen": {}}


def save_state(state: dict) -> None:
    seen = state["seen"]
    # 只保留最近 8000 条，防止无限膨胀
    if len(seen) > 8000:
        trimmed = dict(sorted(seen.items(), key=lambda kv: kv[1], reverse=True)[:8000])
        state["seen"] = trimmed
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=1), encoding="utf-8")


# ---------------------------------------------------------------- 三路来源

def fetch_kev(token: str | None) -> list[dict]:
    """CISA KEV：已知被在野利用漏洞。返回全部目录，由调用方筛近 N 日新增。"""
    url = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
    data = http_get_json(url, token)
    out = []
    for v in data.get("vulnerabilities", []):
        out.append({
            "id": v.get("cveID", ""),
            "name": v.get("vulnerabilityName", ""),
            "vendor": f"{v.get('vendorProject', '')} {v.get('product', '')}".strip(),
            "date_added": v.get("dateAdded", ""),
            "ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
            "url": f"https://nvd.nist.gov/vuln/detail/{v.get('cveID', '')}",
        })
    return out


def fetch_nvd(token: str | None) -> list[dict]:
    """NVD：近 48h 修改且 CVSS >= 7.0 的 CVE。"""
    end = now_utc()
    start = end - timedelta(hours=WINDOW_HOURS)
    q = urllib.parse.urlencode({
        "lastModStartDate": iso(start), "lastModEndDate": iso(end),
        "resultsPerPage": 2000,
    })
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{q}"
    data = http_get_json(url, token, timeout=60)

    out = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cid = cve.get("id", "")
        score = None
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                score = metrics[key][0]["cvssData"].get("baseScore")
                break
        if score is None or float(score) < MIN_CVSS:
            continue
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        out.append({
            "id": cid,
            "score": score,
            "desc": desc[:140],
            "modified": (cve.get("lastModified") or "")[:10],
            "url": f"https://nvd.nist.gov/vuln/detail/{cid}",
        })
    out.sort(key=lambda x: -x["score"])
    return out


def fetch_ghsa(token: str | None) -> list[dict]:
    """GitHub Advisory：近 48h 更新的 high / critical 公告。"""
    since = urllib.parse.quote(">" + iso(now_utc() - timedelta(hours=WINDOW_HOURS), ms=False))
    url = f"https://api.github.com/advisories?updated={since}&per_page=100"
    data = http_get_json(url, token)
    out = []
    for a in data if isinstance(data, list) else []:
        if a.get("severity") not in ("high", "critical"):
            continue
        score = ((a.get("cvss") or {}).get("score")) or a.get("cvss_score")
        out.append({
            "id": a.get("ghsa_id", ""),
            "cve": a.get("cve_id") or "-",
            "score": score if score is not None else "-",
            "pkg": (a.get("summary") or "")[:60],
            "desc": (a.get("description") or "")[:140],
            "url": a.get("html_url") or f"https://github.com/advisories/{a.get('ghsa_id','')}",
        })
    out.sort(key=lambda x: -(x["score"] if isinstance(x["score"], (int, float)) else 0))
    return out


# ---------------------------------------------------------------- 过滤与渲染

def match_watchlist(text: str) -> list[str]:
    """返回命中的「分类: 关键词」列表。

    用词边界匹配避免子串误报（如 community 含 unity、onnxruntime 含 onnx）；
    词边界只看字母数字，下划线/连字符不算边界，pytorch_xxx 仍能命中 pytorch。
    """
    low = (text or "").lower()
    hits = []
    for cat, words in WATCHLIST.get("categories", {}).items():
        for w in words:
            pat = r"(?<![a-z0-9])" + re.escape(w) + r"(?![a-z0-9])"
            if re.search(pat, low):
                hits.append(f"{cat}: {w}")
    return hits


def dedup(items: list[dict], state: dict, id_key: str = "id") -> tuple[list[dict], int]:
    """拆分「未上报过的」与总数，并把全部 ID 记入 state（今日处理即视为已覆盖）。"""
    seen = state["seen"]
    today = datetime.now(CN_TZ).strftime("%Y-%m-%d")
    fresh = [x for x in items if x.get(id_key) and x[id_key] not in seen]
    for x in items:
        if x.get(id_key):
            seen[x[id_key]] = today
    return fresh, len(items)


def table(headers: list[str], rows: list[list[str]], cap: int = MAX_ROWS) -> str:
    def cell(c) -> str:
        s = str(c).replace("\r", " ").replace("\n", " ")   # 换行会破坏表格渲染
        return s.replace("|", "\\|")
    lines = ["| " + " | ".join(headers) + " |",
             "|" + "|".join(["---"] * len(headers)) + "|"]
    for r in rows[:cap]:
        lines.append("| " + " | ".join(cell(c) for c in r) + " |")
    if len(rows) > cap:
        lines.append(f"\n> 仅展示前 {cap} 条，共 {len(rows)} 条，完整列表见上方链接检索。")
    return "\n".join(lines)


def render_report(report_date: str, kev_new: list[dict], nvd_new: list[dict],
                  ghsa_new: list[dict], watch_hits: list[dict],
                  failed: list[str]) -> str:
    lines = [f"# 漏洞情报日报 · {report_date}", "",
             f"> 生成时间（北京时间）：{datetime.now(CN_TZ):%Y-%m-%d %H:%M} ｜ "
             f"回看窗口：KEV 近 {KEV_RECENT_DAYS} 日新增，NVD / GHSA 近 {WINDOW_HOURS} 小时", ""]
    lines += ["## 概览", "",
              f"- CISA KEV 近 {KEV_RECENT_DAYS} 日新增：**{len(kev_new)}**",
              f"- NVD 高危（CVSS ≥ {MIN_CVSS}）：窗口内 **{len(nvd_new)}**",
              f"- GitHub Advisory 高危：窗口内 **{len(ghsa_new)}**",
              f"- 关注列表命中：**{len(watch_hits)}**"]
    if failed:
        lines += [f"- 来源异常（不影响其余来源）：{ '、'.join(failed) }"]
    lines.append("")

    if kev_new:
        lines += ["## 已知被在野利用（KEV）新增", "",
                  table(["CVE", "厂商/产品", "漏洞名称", "收录日期", "勒索利用"],
                        [[x["id"], f"[{x['vendor']}]({x['url']})", x["name"][:60],
                          x["date_added"], "是" if x["ransomware"] == "Known" else "-"]
                         for x in kev_new]), ""]
    else:
        lines += [f"## 已知被在野利用（KEV）新增", "", f"近 {KEV_RECENT_DAYS} 日无新增。", ""]

    if watch_hits:
        lines += ["## 关注列表命中（游戏引擎 / 内容安全组件等）", "",
                  table(["来源", "ID", "评分", "说明", "命中"],
                        [[x["src"], f"[{x['id']}]({x['url']})",
                          x.get("score", "-"), x.get("desc", "")[:80],
                          "、".join(x["hits"][:3])] for x in watch_hits]), ""]

    if nvd_new:
        lines += ["## NVD 高危 CVE", "",
                  table(["CVE", "CVSS", "摘要", "修改日期"],
                        [[f"[{x['id']}]({x['url']})", x["score"], x["desc"], x["modified"]]
                         for x in nvd_new]), ""]

    if ghsa_new:
        lines += ["## GitHub 安全公告（high / critical）", "",
                  table(["GHSA", "CVE", "评分", "摘要"],
                        [[f"[{x['id']}]({x['url']})", x["cve"], x["score"], x["pkg"]]
                         for x in ghsa_new]), ""]

    if not (kev_new or nvd_new or ghsa_new or watch_hits):
        lines += ["窗口期内无新增条目。", ""]

    lines += ["---", "",
              "*本日报由 GitHub Actions 每日自动生成，数据来自公开渠道，"
              "仅作威胁情报参考，不构成风险处置依据。*"]
    return "\n".join(lines) + "\n"


def collect_watch_hits(kev_new, nvd_new, ghsa_new) -> list[dict]:
    """命中条目按「分类优先级」排序：游戏引擎 > 内容组件 > AI 运行时 > 基础设施。"""
    cat_order = {cat: i for i, cat in enumerate(WATCHLIST.get("categories", {}))}
    hits = []
    for src, items in (("KEV", kev_new), ("NVD", nvd_new), ("GHSA", ghsa_new)):
        for x in items:
            blob = " ".join(str(v) for v in x.values())
            m = match_watchlist(blob)
            if m:
                y = dict(x)
                y.update({"src": src, "hits": m})
                y["prio"] = min(cat_order.get(h.split(": ", 1)[0], 99) for h in m)
                hits.append(y)
    hits.sort(key=lambda x: (x["prio"], x["src"] != "KEV",
                             -(x.get("score") if isinstance(x.get("score"), (int, float)) else 0)))
    return hits


def write_badge(reports: int) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    badge = {"schemaVersion": 1, "label": "连续运行",
             "message": f"{reports} 天", "color": "brightgreen"}
    (DATA_DIR / "badge.json").write_text(
        json.dumps(badge, ensure_ascii=False), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="漏洞情报日报聚合器")
    ap.add_argument("--dry-run", action="store_true", help="只打印摘要，不写文件")
    args = ap.parse_args()

    token = os.environ.get("GITHUB_TOKEN") or None
    state = load_state()
    report_date = datetime.now(CN_TZ).strftime("%Y-%m-%d")
    failed: list[str] = []

    def safe(fn, *a):
        try:
            return fn(*a)
        except SourceError as e:
            failed.append(str(e))
            return []

    kev_all = safe(fetch_kev, token)
    cutoff = (datetime.now(CN_TZ) - timedelta(days=KEV_RECENT_DAYS)).strftime("%Y-%m-%d")
    kev_recent = [x for x in kev_all if x["date_added"] >= cutoff]
    nvd = safe(fetch_nvd, token)
    ghsa = safe(fetch_ghsa, token)

    if failed and not (kev_all or nvd or ghsa):
        print("所有来源均失败：", failed)
        return 1

    kev_new, _ = dedup(kev_recent, state)
    nvd_new, _ = dedup(nvd, state)
    ghsa_new, _ = dedup(ghsa, state)
    watch = collect_watch_hits(kev_new, nvd_new, ghsa_new)

    report = render_report(report_date, kev_new, nvd_new, ghsa_new, watch, failed)

    if args.dry_run:
        print(f"[dry-run] {report_date}")
        print(f"  KEV 新增 {len(kev_new)} ｜ NVD 高危 {len(nvd_new)} ｜ "
              f"GHSA 高危 {len(ghsa_new)} ｜ 关注命中 {len(watch)}")
        if failed:
            print("  来源异常:", failed)
        print("  --- 报告前 40 行 ---")
        print("\n".join(report.splitlines()[:40]))
        # dry-run 不改 state，方便反复调试
        return 0

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    out = REPORT_DIR / f"{report_date}.md"
    out.write_text(report, encoding="utf-8")
    save_state(state)
    write_badge(len(list(REPORT_DIR.glob("*.md"))))
    print(f"已生成 {out}（KEV {len(kev_new)} / NVD {len(nvd_new)} / "
          f"GHSA {len(ghsa_new)} / 关注命中 {len(watch)}）")
    if failed:
        print("来源异常:", failed)
    return 0


if __name__ == "__main__":
    sys.exit(main())

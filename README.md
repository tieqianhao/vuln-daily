# vuln-daily · 漏洞情报日报

![daily](https://github.com/tieqianhao/vuln-daily/actions/workflows/daily.yml/badge.svg)
![连续运行](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/tieqianhao/vuln-daily/main/data/badge.json&cacheSeconds=3600)

一个**全自动运行**的漏洞情报聚合系统：GitHub Actions 每日定时拉取三个公开情报源，
聚合、去重、按关注方向过滤，生成 Markdown 日报自动提交回本仓库。
零密钥、零服务器、零人工干预——clone 下来配上 Actions 就能跑。

## 数据源

| 来源 | 内容 | 过滤条件 |
|---|---|---|
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | 已知被在野利用漏洞目录 | 近 3 日新增（最高优先级信号） |
| [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) | CVE 漏洞库 | 近 48 小时修改且 CVSS ≥ 7.0 |
| [GitHub Advisory](https://github.com/advisories) | 生态安全公告 | 近 48 小时更新的 high / critical |

## 关注方向

`config/watchlist.json` 中按四个类别维护关键词：**游戏引擎与平台、内容与多媒体组件、
AI 运行时、高频基础设施**。命中条目在日报中单独成节——这一节是给"游戏安全 / 内容安全"
方向看的定制情报。

## 输出

- `reports/YYYY-MM-DD.md` —— 当日日报（概览统计 / KEV 新增 / 关注命中 / NVD 高危 / GHSA）
- `data/state.json` —— 已上报条目索引（去重，防止同一漏洞重复推送）
- `data/badge.json` —— 顶部"连续运行 N 天"徽章的数据源

单来源失败不影响整体：失败来源在日报概览中如实标注，其余来源正常产出。

## 本地运行

```bash
python fetch_intel.py             # 生成今日日报（无需任何密钥）
python fetch_intel.py --dry-run   # 只看摘要，不写文件、不改去重状态
python tests/test_digest.py       # 离线单元测试
```

## 工作流

每日北京时间 07:00 自动执行（UTC 23:00 cron），也可在 Actions 页面手动
`workflow_dispatch` 触发。流程：拉取三个来源 → 去重 → 渲染日报 → 自动 commit 回仓库。

## 许可

MIT

# 公告源、索引结构与字段抽取

本文件只描述**公开页面结构与抽取规则**，不收录具体 CVE 条目。

## 1. 源清单

| 源 | 用途 | 覆盖 | 备注 |
|----|------|------|------|
| `https://consumer.huawei.com/cn/support/bulletin/` | 手机/平板月度安全更新**索引** | 2017-12 起按月 | 页面内嵌 JSON 列出全部年月链接 |
| `https://consumer.huawei.com/cn/support/bulletin/<年>/<月>/` | 单月公告正文 | 见索引 | 月份**不带前导零**：`2026/1`、`2026/10` |
| `https://www.huawei.com/cn/psirt` | 华为 PSIRT 总入口 | 产品线安全通告 | 含「全部安全通告」子页 |
| `https://securitybulletin.huawei.com/enterprise/cn/security-advisory` | 企业业务公告 | 企业产品 | 与消费者手机/平板公告**不是同一批** |
| `https://gitee.com/openharmony/security` → `zh/security-disclosure/<年>/<年>-<月>.md` | OpenHarmony 月度安全公告 | 见下方时效 | **给出受影响仓库 + 修复 PR/commit** |

### 时效边界（必须实测，不得假设）

- 消费者公告索引会列出当年及历史年份的**全部月份**，但**尚未发布的月份会 404**（实测 `2026/12`、`2027/1` 均为 404，而 `2026/11` 正常）。
- OpenHarmony `security-disclosure` 实测只有 `2021`–`2025`，**没有 2026 目录**；且 2025 只到 `2025-09`（`2025-10`、`2025-12` 均 404）。
- 因此：**不要**假设「索引里的某月一定已发布」，也**不要**假设「OpenHarmony 公告与消费者公告同步」。

正确做法：先取索引 → 逐链接探测 → 记录 `ok` / `404` / `failed` 三态，失败月份写入缺口清单。

仓库内提供了零依赖解析器 `bulletin-hunting/scripts/parse-bulletin.mjs`：

```bash
node bulletin-hunting/scripts/parse-bulletin.mjs --index
node bulletin-hunting/scripts/parse-bulletin.mjs 2026/10 --out baseline-2026-10.json
```

它已实现本节全部规则（索引反转义、两表按表头取值、描述拆分、CVE 去重、前导零拒绝）。自行写脚本时以它为准。

### 路径格式陷阱（实测）

消费者公告的月份路径**不带前导零**：

- `https://consumer.huawei.com/cn/support/bulletin/2026/8/` → 200；
- `https://consumer.huawei.com/cn/support/bulletin/2026/08/` → 404。

**不要**用 `padStart(2, "0")` 生成月份。索引里的 `link` 字段是唯一权威，直接用它。

## 2. 索引解析

索引页把全部年月放在一个隐藏 `<div class="data_bulletins_invisible hidden">` 里，内容是 HTML 转义的 JSON：

```
[{"year":"2026","bulletins":[{"title":"1 月","link":"https://consumer.huawei.com/cn/support/bulletin/2026/1/"}, ...]}, ...]
```

抽取步骤：

1. 取 `data_bulletins_invisible` 所在块；
2. 反转义 `&#34;` → `"`、`&amp;` → `&`；
3. `JSON.parse`；
4. 展开成 `{year, month, url}`。

不要用正则从 `<a href>` 里抓链接——索引是 JS 渲染的，静态 HTML 里没有逐月 `<a>`。

## 3. 单月公告字段

单月页有两张表，**表头不同、语义不同**，必须分开处理：

| 表 | 引导语（前一个 `<p class="titile-size">`） | 表头 | 含义 |
|----|------|------|------|
| 表 1 | `本次安全更新软件包含如下华为补丁：` | `CVE` / `漏洞描述` / `漏洞影响` / `严重程度` / `受影响版本` | 华为自研组件 |
| 表 2 | `本次安全更新软件包含如下三方库补丁：` | `CVE` / `严重程度` / `受影响版本` | 三方库/上游组件 |

注意：

- 表 1 有「漏洞描述」，可解析出 `组件` 与 `机理`；
- 表 2 **没有**「漏洞描述」，只有 CVE 与版本——**不能**从中推断组件或机理；
- 两表的「严重程度」列位置不同，按表头取值，**不要按列序硬编码**；
- 页脚有 `更新时间：YYYY-MM-DD`，用于判断该月是否被追加更新；
- 同一 CVE 会在**不同月份重复出现**（实测 909 行中有 15 个 CVE 重复），去重键用 `CVE`。

### 描述字段的两种句式

表 1 的「漏洞描述」主要有两种写法，抽取规则不同：

| 句式 | 例（结构示意） | 抽取 |
|------|----------------|------|
| `{组件}存在{机理}漏洞` | `软总线模块存在拒绝服务漏洞` | 组件 = 前缀，机理 = 中间 |
| `{组件}{动作/条件}存在{机理}漏洞` | `3D引擎模块加载gltf模型存在越界写漏洞` | 组件需保留修饰语，否则会与同族混淆 |

抽取时保留**完整前缀**作为组件键（含「加载gltf模型」这类修饰），否则会把不同攻击面合并成一个。

无法匹配句式时：`component = null`、`mechanism_raw = 原文`，进入人工复核清单，不要强行切分。

实测（2025–2026 全量）自研表 346 行中有 20 行无法按标准句式切分，典型形态：

- 描述尾部带句号（`…漏洞。`）——解析前先去掉尾随 `。`/`.`；
- 复合句（`{组件}存在{原因}导致{结果}的问题`）——`mechanism_raw` 会很长，需人工归并；
- 组件名被拆进条件从句（`文件预览在解析矢量图时存在…`）——组件键会带修饰语，属预期。

这 20 行不要硬塞进标准句式；标 `needs_review` 后人工归并。

## 4. 抽取产物

```json
{
  "source": "consumer.huawei.com/cn/support/bulletin",
  "fetched_at": "YYYY-MM-DD",
  "months": [
    {
      "year": 2026, "month": 10, "status": "ok",
      "updated_at": "2026-10-10",
      "rows": [
        {
          "cve": "CVE-XXXX-XXXXX",
          "table": "huawei | third_party",
          "component": "软总线模块",
          "mechanism_raw": "拒绝服务",
          "impact_text": "成功利用此漏洞可能导致可用性受影响。",
          "vendor_severity": "中",
          "affected_versions": ["HarmonyOS7.0.0", "HarmonyOS6.1.0"]
        }
      ]
    }
  ],
  "gaps": [{ "year": 2026, "month": 9, "status": "404" }]
}
```

规则：

- `vendor_severity` 原样保留，**不改写**为 `critical/high/medium/low`；
- `affected_versions` 按 `，` 切分并 trim；
- `table` 必须标注，因为三方库表不能做组件归因；
- `gaps` 显式记录失败月份，避免「没抓到 = 没公告」的误判。

## 5. 抓取纪律

- **单页节流**：请求间隔 ≥ 0.5–1 秒；批量抓取逐月串行，不并发轰炸；
- **重试**：`404` 不重试（视为不存在）；`429` / `403` / 5xx 指数退避重试 2–3 次；
- **限流识别**：连续请求后若突然大面积 `403`，先停 60 秒再验一个已知可用 URL，确认是限流而不是页面变更；
- **响应校验**：长度过短（如 < 20 KB）视为异常页，不要当成「空公告」；
- **不绕过**：不使用代理池、不伪造身份、不绕过访问控制；需要登录的内容不抓；
- **不执行页面脚本**：只做静态 HTML 解析，不跑页面里的 JS。

## 6. 交叉源：OpenHarmony 公告

OpenHarmony 月度公告是**唯一稳定提供「受影响仓库 + 修复链接」的公开源**，字段为：

`CVE` / `漏洞描述` / `漏洞影响` / `严重程度` / `CVSS 3.1得分` / `受影响的版本` / `受影响的仓库` / `修复链接`

用法与边界：

- 它是**独立公告体系**，与华为消费者公告**不是同一批 CVE**；
- 实测华为公告 2025–2026 共 894 个去重 CVE；OpenHarmony 公告 2024-01–2025-09 共 815 个去重 CVE；两者交集 135 条，**全部来自华为三方库表**（`kernel_linux_5.10`、`arkcompiler_ets_runtime` 等），**自研模块表零命中**；
- 因此：OpenHarmony 公告适合做**三方库/上游组件的落点证据**，**不能**用来证明华为自研模块（如「软总线模块」）对应哪个仓；
- 三方库条目按 `vuln-definitions-oh` 的 INV4 处理：默认不投递，除非 OH 默认路径可独立演示实害。

结论必须写成：「本 CVE 在 OpenHarmony 公告中的仓库为 X」；**不要**写成「华为的该模块就是 X」。

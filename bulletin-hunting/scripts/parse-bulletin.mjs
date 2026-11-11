#!/usr/bin/env node
// 华为手机/平板月度安全更新解析器（零依赖，Node >= 18）。
//
// 用法：
//   node bulletin-hunting/scripts/parse-bulletin.mjs 2026/10
//   node bulletin-hunting/scripts/parse-bulletin.mjs --index
//   node bulletin-hunting/scripts/parse-bulletin.mjs 2026/10 --out baseline.json
//
// 只做静态 HTML 解析，不执行页面脚本；单页请求，不并发。

const BASE = "https://consumer.huawei.com/cn/support/bulletin";
const UA = "Mozilla/5.0 (compatible; bulletin-hunting/0.1)";

const strip = (s) =>
  s
    .replace(/<[^>]+>/g, " ")
    .replace(/&#34;/g, '"')
    .replace(/&amp;/g, "&")
    .replace(/&nbsp;/g, " ")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/\s+/g, " ")
    .trim();

async function fetchPage(url) {
  const res = await fetch(url, { headers: { "user-agent": UA, "accept-language": "zh-CN" } });
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
  const html = await res.text();
  if (html.length < 20000) throw new Error(`suspiciously short page (${html.length} bytes): ${url}`);
  return html;
}

/** 索引页把年月放在 data_bulletins_invisible 的转义 JSON 里。 */
export function parseIndex(html) {
  const m = html.match(/class="data_bulletins_invisible[^"]*"[^>]*>([\s\S]*?)<\/div>/);
  if (!m) throw new Error("index block not found");
  const raw = m[1].replace(/&#34;/g, '"').replace(/&amp;/g, "&");
  const years = JSON.parse(raw);
  return years.flatMap((y) =>
    (y.bulletins ?? []).map((b) => ({ year: Number(y.year), monthLabel: b.title, url: b.link })),
  );
}

/** 单月页：两张表，表头不同；按表头取值，不按列序。 */
export function parseMonth(html) {
  const updatedAt = (html.match(/更新时间[：:]\s*([0-9]{4}-[0-9]{2}-[0-9]{2})/) ?? [])[1] ?? null;
  const intro = [...html.matchAll(/<p class="titile-size">([\s\S]*?)<\/p>/g)].map((m) => strip(m[1]));
  const rows = [];
  const tables = [...html.matchAll(/<table>([\s\S]*?)<\/table>/g)].map((m) => m[1]);

  tables.forEach((table, i) => {
    const headBlock = (table.match(/<thead>([\s\S]*?)<\/thead>/) ?? ["", ""])[1];
    const heads = [...headBlock.matchAll(/<th[^>]*>([\s\S]*?)<\/th>/g)].map((m) => strip(m[1]));
    if (!heads.length) return;
    const kind = heads.includes("漏洞描述") ? "huawei" : "third_party";
    for (const tr of table.matchAll(/<tr>([\s\S]*?)<\/tr>/g)) {
      const cells = [...tr[1].matchAll(/<td[^>]*>([\s\S]*?)<\/td>/g)].map((m) => strip(m[1]));
      if (cells.length < 3 || !/^CVE-\d{4}-\d+$/.test(cells[0])) continue;
      const row = {};
      heads.forEach((h, j) => (row[h] = cells[j] ?? ""));
      rows.push(toRow(row, kind, i, intro[i] ?? null));
    }
  });

  return { updatedAt, tables: tables.length, rows };
}

/** 「{组件}存在{机理}漏洞」；组件保留修饰语，不合并同族。 */
export function splitDescription(desc) {
  if (!desc) return { component: null, mechanism_raw: null };
  const cleaned = desc.replace(/[。．.]+$/g, "").trim();
  const m = cleaned.match(/^(.*?)存在(.+?)漏洞$/);
  if (!m) return { component: null, mechanism_raw: cleaned };
  return { component: normalizeComponent(m[1]), mechanism_raw: m[2].trim() };
}

/** 页面原文会带尾随空格（如「UIExtension 」），归并成同一组件键。 */
export function normalizeComponent(s) {
  return s.replace(/\s+/g, " ").trim();
}

function toRow(row, kind, tableIndex, intro) {
  const desc = row["漏洞描述"] ?? "";
  const { component, mechanism_raw } = splitDescription(desc);
  const normalizedDesc = component && mechanism_raw ? `${component}存在${mechanism_raw}漏洞` : desc || null;
  return {
    cve: row["CVE"],
    table: kind,
    table_index: tableIndex,
    intro,
    component,
    mechanism_raw,
    description: normalizedDesc,
    impact_text: row["漏洞影响"] ?? null,
    vendor_severity: row["严重程度"] ?? null,
    affected_versions: (row["受影响版本"] ?? "")
      .split("，")
      .map((v) => v.trim())
      .filter(Boolean),
  };
}

function dedupe(rows) {
  const seen = new Map();
  for (const r of rows) if (!seen.has(r.cve)) seen.set(r.cve, r);
  return [...seen.values()];
}

async function main() {
  const args = process.argv.slice(2);
  const outIdx = args.indexOf("--out");
  const out = outIdx >= 0 ? args[outIdx + 1] : null;
  const target = args.find((a, i) => !a.startsWith("--") && args[i - 1] !== "--out");

  if (args.includes("--index")) {
    const months = parseIndex(await fetchPage(`${BASE}/`));
    console.log(JSON.stringify({ source: BASE, months }, null, 2));
    return;
  }
  if (!target) {
    console.error("usage: node parse-bulletin.mjs <yyyy/m> | --index   [--out file]");
    process.exit(2);
  }
  if (!/^\d{4}\/[1-9]\d?$/.test(target)) {
    console.error(`month must look like 2026/8 (no leading zero): ${target}`);
    process.exitCode = 2;
    return;
  }

  const [year, month] = target.split("/");
  const { updatedAt, tables, rows } = parseMonth(await fetchPage(`${BASE}/${target}/`));
  const result = {
    source: `${BASE}/${target}/`,
    fetched_at: new Date().toISOString().slice(0, 10),
    year: Number(year),
    month: Number(month),
    updated_at: updatedAt,
    tables,
    row_count: rows.length,
    unique_cves: dedupe(rows).length,
    rows: dedupe(rows),
  };
  const text = JSON.stringify(result, null, 2);
  if (out) {
    const { writeFileSync } = await import("node:fs");
    writeFileSync(out, text);
    console.log(`wrote ${out}: ${result.row_count} rows, ${result.unique_cves} unique CVEs`);
  } else {
    console.log(text);
  }
}

const entryHref = (() => {
  const entry = process.argv[1];
  if (!entry) return null;
  const normalized = entry.replace(/\\/g, "/");
  return `file:///${normalized.replace(/^\/+/, "")}`;
})();

if (import.meta.url === entryHref) {
  main().catch((err) => {
    console.error(err.message);
    process.exitCode = 1;
  });
}

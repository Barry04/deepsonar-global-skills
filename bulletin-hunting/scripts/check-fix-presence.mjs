#!/usr/bin/env node
// 分支滞后检测：判断某修复特征是否存在于指定分支的指定文件。
// 零依赖，Node >= 18。
//
// 用法：
//   node check-fix-presence.mjs \
//     --repo openharmony/communication_dsoftbus \
//     --path core/bus_center/lnn/lane_hub/time_sync/src/lnn_time_sync_manager.c \
//     --marker g_startReqListLock \
//     --branches OpenHarmony-5.0.3-Release,OpenHarmony-6.0-Release,master
//
// 输出 JSON：每个分支的 present / absent / file_missing。
// 注意：absent 只表示「该文件未见该特征」，不是「存在漏洞」。

const RAW = "https://gitee.com";
const UA = "Mozilla/5.0 (compatible; bulletin-hunting/0.1)";
const GAP_MS = 800;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i];
    if (!key.startsWith("--")) throw new Error(`unexpected argument: ${key}`);
    out[key.slice(2)] = argv[i + 1];
  }
  for (const required of ["repo", "path", "marker", "branches"]) {
    if (!out[required]) throw new Error(`missing --${required}`);
  }
  return out;
}

async function fetchText(url, attempts = 3) {
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetch(url, { headers: { "user-agent": UA } });
      if (res.status === 200) return await res.text();
      if (res.status === 404) return null;
      if (res.status === 403 || res.status === 429 || res.status >= 500) {
        await sleep(GAP_MS * (i + 2));
        continue;
      }
      throw new Error(`HTTP ${res.status} for ${url}`);
    } catch (err) {
      if (i === attempts - 1) throw err;
      await sleep(GAP_MS * (i + 2));
    }
  }
  throw new Error(`exhausted retries: ${url}`);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const branches = args.branches.split(",").map((b) => b.trim()).filter(Boolean);
  const marker = args.marker;
  const results = [];

  for (const branch of branches) {
    const url = `${RAW}/${args.repo}/raw/${encodeURIComponent(branch)}/${args.path}`;
    const body = await fetchText(url);
    if (body === null) {
      results.push({ branch, state: "file_missing", url });
    } else {
      const lines = body.split("\n");
      const hits = lines.flatMap((line, i) => (line.includes(marker) ? [i + 1] : []));
      results.push({
        branch,
        state: hits.length ? "present" : "absent",
        marker_lines: hits,
        url,
      });
    }
    await sleep(GAP_MS);
  }

  const absent = results.filter((r) => r.state === "absent").map((r) => r.branch);
  console.log(
    JSON.stringify(
      {
        repo: args.repo,
        path: args.path,
        marker,
        branches: results,
        // 只给「待验证分支」，不下漏洞结论。
        needs_verification: absent,
        note: "absent 仅表示该分支该文件未见该特征；不等于存在漏洞，须继续验证可达性。",
      },
      null,
      2,
    ),
  );
  if (absent.length) process.exitCode = 0;
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

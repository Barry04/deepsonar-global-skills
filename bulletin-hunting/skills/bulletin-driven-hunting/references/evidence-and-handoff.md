# 证据包与定级移交

## 1. 证据包结构

工作目录按 `work/<target>-<yyyy-mm>/` 组织，包含：

| 文件 | 内容 |
|------|------|
| `bulletin-baseline.json` | 结构化公告基线（去重、表类型、更新时间） |
| `bulletin-baseline.md` | 人读版：按月 / 按组件 / 按机理 |
| `triage.md` | 入选面、排除面、排除理由 |
| `attribution.md` | 组件 → 落点，每条带证据等级 |
| `candidates.md` | 候选点（假设、同族依据、验证状态），无 severity |
| `evidence/diff-<pattern_id>.txt` | 修复 diff 摘录，只保留相关 hunk |
| `evidence/branch-check.md` | 逐分支修复特征比对 |
| `evidence/code-<n>.md` | 同族点代码摘录，带 `文件:行` |
| `evidence/verify-<n>.md` | 授权环境验证记录 |

## 2. 候选记录格式

```yaml
id: BH-001
pattern_id: P-001
hypothesis: "同模块另一处解析函数缺少长度上界检查"
evidence_level: C2
code_refs:
  - path: <file>
    lines: "120-160"
family_basis: "与修复点共用同一解析入口与长度字段"
reachability: "默认配置下由近场报文触发"
verify_method: "构造超长长度字段，观察是否越界写"
status: hypothesis | verified | rejected
notes: ""
```

**禁止**在本文件写 `severity` / `critical` / `high` 等档位。

## 3. 移交定级

候选成立后，交给 `vuln-definitions-oh`：

1. 过 Gate S（资产范围）→ Gate V（活树/最新公开版本）→ Gate A–D；
2. 填 `mechanism`（机理 ID）、`phone_os_class`（形态 ID）；
3. 填 `asset_repo`（**精确**仓名）、`asset_scope`（分桶）；
4. 填 `subject_revision`（`<仓>@<sha>`）；
5. `severity_rule` 指向条款号，如 `severity-levels.md#H5`；
6. `severity` 由定级模块裁定，本 skill 不填。

字段定义见 `../../../shared/finding-schema.md` 的「系统类 / OpenHarmony」段。

## 4. 与公告的关系怎么写

正确：

- 「该候选与 2026-10 公告中『软总线模块 / 拒绝服务』同一面，但为**独立未修点**」；
- 「修复模式来自 OpenHarmony 公告 CVE-XXXX 的 PR，本候选为同族另一调用点」。

错误：

- 「复现了 CVE-XXXX」（本 skill 不复现已公开 CVE）；
- 「公告说高危，所以本候选高危」（档位由条款决定）；
- 「与 CVE-XXXX 同组件，因此同等级」（组件相同不等于档位相同）。

## 5. 披露纪律

- 未修复漏洞：先按厂商披露流程（`https://www.huawei.com/cn/psirt/report-vulnerabilities`）或对应赏金项目规则提交；
- 在厂商修复或同意公开前，不写入本仓、不写入公开 PR、不贴到 issue；
- 本仓只沉淀**方法、模式、误判教训**，不沉淀未修复细节；
- 证据包留在项目内，按项目访问控制管理；
- 过曝的凭据、设备标识、用户数据一律打码或删除。

## 6. 交接检查清单

- [ ] 公告基线有 `gaps`（失败月份），没有把「没抓到」当「没公告」；
- [ ] 三方库表与自研表分开聚合；
- [ ] 每条归因都标了 `A1`/`B1`/`C1`/`C0`；
- [ ] `C1` 没有被写成事实；
- [ ] 每条候选都有可证伪的验证方法；
- [ ] 分支结论用了「未见修复特征」而不是「存在漏洞」；
- [ ] 没有写 severity；
- [ ] 没有复现已公开 CVE 的完整攻击链；
- [ ] 未修复细节没有进入公开产物。

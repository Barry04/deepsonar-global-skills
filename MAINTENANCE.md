# Barry 全局 Skill 维护

本仓库维护可跨项目复用的安全研究 Skill。初始基线为上游 `SummerSec/DeepSonar-Skills` 的 `063872aaa398194b89804cbe87d6685472b56655`，初始化日期为 2026-11-09。保留上游 Git 历史、原始署名和 LICENSE。

## 内容归属

- 项目事实、目标账号条件、私有 Evidence、候选漏洞和任务原始日志留在 DeepSonar 项目内。
- 可复验、已去除项目敏感信息、写清触发条件和不适用边界的通用步骤，才进入本仓库对应 Skill 或 reference。
- 23 个初始 Skill 是导入的既有内容，不能作为任务自动沉淀已经成功的证据。

## 修改与验证

1. 先读 AGENTS.md；修改指令文本时再读 semantic-rules.md。
2. 新厂商的规则归入对应领域 reference；已有步骤修订原 Skill，避免重复创建同义 Skill。
3. 变更说明列出来源、实际观察、适用输入、可观察产物、停止条件和未验证项。不得提交凭据、会话 Cookie 或原始私有证据。
4. Skill 内容变化时按 AGENTS.md 同步插件与 marketplace 版本，执行 `npm run check`，在 PR 记录实际结果。
5. 经人工检查后合并。定期吸收上游时先检查 diff，不直接覆盖本仓修订。

## 与 DeepSonar 对接

DeepSonar 的全局 Git Skill 源与项目 Memory/Skill 是两条链路：

- 全局源通过管理 API 登记 Git URL，经 sync、信任审批和启用后进入新 Job 的冻结目录。
- 项目知识由正在运行的 Job 使用 `request_project_knowledge` 请求首次整理，或通过实际 usage 的 `record_knowledge_feedback` 请求修订；候选经独立评测和检查后激活。
- Job 成功结束不会自行把任务日志写入 Git 仓库。现有项目知识操作也不授予 GitHub 写权限。

本仓初始为私有仓库。Scheduler 的 Git 同步环境必须先具备对此仓库的只读访问能力；本机 `gh` 已登录不代表 Docker 容器自动取得相同权限。不要把 GitHub Token 放进 repo_url 或 Skill 正文。

## 后续任务沉淀的验收点

若增加任务收尾沉淀机制，必须在既有 Control API、Job/Attempt 和知识 work 流程内实现：

- 对有可引用来源的任务，提交有界整理请求并保存 durable receipt；无可复用内容或输入不足时明确记录原因。
- 用 work、proposal、evaluation、review、active version 分别证明各阶段结果，不能以任务成功或 Skill 数量替代。
- 失败、未知外部效果、预算耗尽和撤权继续遵守既有停止规则；不能为获得新内容绕过独立评测。
- 发布到本仓是独立的脱敏和 GitHub 变更动作，需具备相应授权；平台未实现自动导出时如实标注为手工维护。

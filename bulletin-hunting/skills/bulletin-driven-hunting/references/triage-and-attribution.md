# 分诊矩阵与归因路径

## 1. 分诊：从 CVE 列表到「面」

不要按 CVE 逐条推进。公告的价值是**重复出现的组合**。

### 1.1 聚合键

聚合键为 `(component, mechanism_family, table)`：

- `component`：公告描述的前缀，保留修饰语；
- `mechanism_family`：把公告用语归并到 `vuln-definitions-oh/references/mechanism-types.md` 的 ID（MW/MR/UAF/AUTHZ/…），归并表在该文件 §9；
- `table`：`huawei`（自研）或 `third_party`（三方库）。两者不可混算。

### 1.2 排序打分

按以下四项加权，不追求精确分数，只要求**排序理由可复核**：

| 维度 | 观察 | 权重 |
|------|------|------|
| 重复度 | 同一面在 12 个月内的出现次数 | 高 |
| 档位持续 | 该面中「高/严重」占比 | 高 |
| 可触达性 | 默认配置下远程/近场/普通应用可达（对照 `vuln-definitions-oh` 的 `attack-surfaces.md`） | 高 |
| 归因可行性 | 能落到开源仓 / 有公开补丁 | 中 |

排除项（直接降为「观察」）：

- 只出现在三方库表、且无上游补丁可读；
- 描述字段缺失，组件不可解析；
- 需要 system/root/预置 SA 前提（`vuln-definitions-oh` 的 Gate A2）。

### 1.3 分诊产物

`triage.md` 每行至少写：面、出现次数、档位分布、入选/排除、理由、下一步（归因 or 放弃）。

**不要**在分诊阶段写 severity。

### 1.4 实测基线（2025-01 至 2026-11，`2026/12` 未发布）

用 `scripts/parse-bulletin.mjs` 逐月解析后：

| 指标 | 实测 |
|------|------|
| 原始行数 | 909 |
| 去重 CVE | 894（488 条 2025、406 条 2026） |
| 自研表（`huawei`） | 346 |
| 三方库表（`third_party`） | 548 |
| 自研组件数 | 188 |
| 自研档位分布 | 高 74 / 中 271 / 严重 1 |
| 面（组件 × 机理）数 | 约 258（含未解析描述） |

自研侧高频组件（前 8）：`媒体库模块` 8、`软总线模块` 7、`3D引擎模块加载gltf模型` 6、`图库模块` 6、`窗口模块` 5、`安全验证模块` 5、`打印模块` 5、`设置模块` 5。

自研侧高频机理（前 8）：`权限控制类` 50、`权限控制` 18、`拒绝服务` 17、`缓冲区溢出` 16、`UAF` 14、`条件竞争` 12、`越界写` 11、`越界读取` 10。

分诊含义：

- **权限类**占绝对多数，且 `权限控制类` / `权限控制` / `权限控制不当` / `权限校验` 是同一族的多种措辞，聚合时必须归并，否则重复度被稀释；
- **内存安全**（UAF / 越界 / 缓冲区溢出 / 条件竞争）虽条数少，但集中在少数组件，单组件重复度高，是差分反推的最佳起点；
- `拒绝服务` 单列，按 `vuln-definitions-oh` 的 INV1 / H8 判定是否可报，不要因为它高频就优先。

这些数字是**基线快照**，随公告更新会变化；重新统计时以脚本输出为准，不要沿用旧值。

## 2. 归因：组件名 → 代码落点

### 2.1 三条路径与证据等级

| 等级 | 路径 | 证据形态 | 可以写成 |
|------|------|----------|----------|
| **A1** | 厂商公告直接给出仓库 + 修复链接 | OpenHarmony 公告的「受影响的仓库」「修复链接」列 | 「该 CVE 的修复落在仓库 X 的 PR/commit Y」 |
| **B1** | 用 CVE 编号反查上游公告 | 三方库上游安全公告 + 版本区间 | 「该 CVE 属于上游组件 Z，修复版本为 V」 |
| **C1** | 组件名 + 攻击面索引推断 | 名称相似、功能相近 | 「**假设**对应仓库 X，待代码验证」 |
| **C0** | 无法归因 | — | 「未归因」 |

硬规则：

- `A1` / `B1` 可进 `attribution.md` 的事实区；
- `C1` 只能进「待验证假设」区，且必须写清**验证方法**；
- `C0` 就写未归因，**不要**用相似名凑一个仓库。

### 2.2 实测边界（2025–2026 数据）

对华为消费者公告与 OpenHarmony 公告做 CVE 交叉，实测结果：

- 华为 2025–2026 公告去重后 894 个 CVE；
- OpenHarmony 公告 2024-01–2025-09 去重 815 个 CVE；
- 交集 135 条，**全部来自华为公告的「三方库」表**；
- 华为「华为补丁」表（自研模块）与 OpenHarmony 公告**零交集**。

结论：

- 自研模块（如「软总线模块」「窗口模块」）**没有**公开的仓库级映射，只能走 `C1`；
- 三方库条目可以走 `A1`/`B1`，但按 `vuln-definitions-oh` 的 INV4 默认不投递；
- **禁止**把 OpenHarmony 公告里的 `communication_dsoftbus` 直接说成华为「软总线模块」的对应仓——两者只是同名概念，交集为零。

### 2.3 自研模块 → 候选仓（C1，假设级）

下表是**按命名与功能相近**给出的候选，**全部为 C1**，必须用代码验证后才能升级证据等级。

表中每个仓库名都已实测：在 `https://gitee.com/openharmony/<repo>/raw/master/` 下能读到 `README_zh.md` 或 `README.md`（2026-11-11）。这只证明**仓库存在**，不证明它就是公告组件。

| 公告组件（示例） | 候选仓（C1） | 验证切入点 |
|------------------|--------------|------------|
| 软总线模块 / 分布式协同框架 | `communication_dsoftbus` | 组网报文解析、会话生命周期、权限校验 |
| IPC模块 / 系统服务框架 | `communication_ipc` | Parcel 反序列化、caller 校验、SA 中继 |
| 蓝牙模块 / 低功耗蓝牙(BLE) / 星闪协议栈SSAP | `communication_bluetooth` | 配对状态机、GATT 解析、认证绕过 |
| wifi模块 / WLAN模块 / WiFi增强 | `communication_wifi` | 管理帧解析、连接状态、配置写入 |
| 网络模块 / 网络管理模块 | `communication_netmanager_base` / `communication_netstack` | 网络配置越权、策略写入 |
| 媒体库模块 / 图库模块 / Medialibrary | `multimedia_media_library` | 媒体库查询权限、文件路径、缩略图解析 |
| 相机框架模块 / 分布式相机 / 相机模块 | `multimedia_camera_framework` | 会话生命周期、跨设备相机授权 |
| 音频模块 / 音频框架 / 音频编解码 | `multimedia_audio_framework` | 音频策略、会话抢占、权限 |
| 编解码模块 / 媒体平台 | `multimedia_av_codec` | 码流解析边界、容器解析 |
| 播放框架模块 / 视频框架模块 | `multimedia_player_framework` | 媒体文件解析、状态机 |
| 图片编解码模块 / 图片处理模块 | `multimedia_image_framework` | 图片解码边界、格式解析 |
| 包管理模块 / 包管理 | `bundlemanager_bundle_framework` | 安装校验、签名、权限授予 |
| 窗口模块 / 窗口管理模块 | `window_window_manager` | 窗口属性越权、跨应用窗口 |
| 通知模块 / 事件通知管理 / 通知服务 | `notification_common_event_service` | 公共事件敏感字段、订阅权限 |
| 多模输入模块 / 多模输入系统 / 输入设备模块 | `multimodalinput_input` | 输入事件注入、设备权限 |
| 安全验证模块 / 身份认证模块 / 设备认证 | `security_device_auth` / `security_access_token` | 认证协议、token 校验、权限画像 |
| 证书管理模块 | `security_certificate_manager` | 证书校验、信任链 |
| HUKS / 设备密钥管理模块 | `security_huks` | 密钥导出、访问控制 |
| 权限管理服务 / 授权模块 | `security_access_token` | 权限判定、token 同步 |
| 位置服务 / LBS模块 | `base_location` | 位置权限、模拟位置 |
| 账号 / Account模块 | `account_os_account` | 跨用户边界、账号数据 |
| 设置模块 / 设置应用 | `applications_settings` / `applications_settings_data` | 导出组件、设置项越权 |
| 桌面模块 / 桌面小工具 | `applications_launcher` | 组件导出、快捷方式 |
| 锁屏模块 / 应用锁 | `applications_screenlock` | 锁屏绕过、认证流程 |
| 备忘录模块 / 备忘录分享 | `applications_notes` | 分享路径、文件权限 |
| 联系人 / 联系人模块 | `applications_contacts` | 数据访问、导出组件 |
| 日历存储模块 | `applications_calendar_data` | 跨应用数据访问 |
| 短信应用 | `applications_mms` | 消息解析、权限 |
| 图库应用 / 图库 | `applications_photos` | 媒体访问、分享 |
| 打印模块 / 打印 | `print_print_fwk` | 打印任务、文件路径 |
| 文件系统 / 文件管理模块 | `filemanagement_user_file_service` / `filemanagement_app_file_service` / `filemanagement_file_api` | 路径穿越、沙箱边界 |
| 分布式文件系统模块 / DFS组件 | `filemanagement_dfs_service` | 跨设备文件隔离 |
| 剪贴板模块 / 分布式剪贴板 | `distributeddatamgr_pasteboard` | 跨应用/跨设备数据面 |
| 分布式数据 / 统一数据面 | `distributeddatamgr_udmf` / `distributeddatamgr_kv_store` / `distributeddatamgr_relational_store` | 数据面隔离、默认可导出 |
| 分布式通知服务 / 分布式通知 | `notification_distributed_notification_service` | 跨设备通知、敏感字段 |
| 设备管理模块 / 设备管理通道 / devicemanager | `distributedhardware_device_manager` / `device_manager` | 组网报文、设备认证 |
| 图形模块 / 渲染合成模块 | `graphic_graphic_2d` / `graphic_surface` | 合成器内存安全、缓冲区 |
| 内核模块 / 内核文件系统模块 / 内核futex模块 | `kernel_liteos_a` / `kernel_liteos_m` | 系统调用、驱动节点、并发 |
| 器件驱动模块 / USB HDI驱动 / USB驱动 | `drivers_peripheral` / `drivers_hdf_core` | HDF 接口、设备节点 DAC |
| ArkUI框架 / UI框架模块 / ArkUI框架SVG解析 | `arkui_ace_engine` / `arkui_napi` | 解析器、跨语言桥 |
| 运行时解释器模块 / arkweb v8模块 / 解释器string模块 | `arkcompiler_ets_runtime` / `arkcompiler_runtime_core` | 字节码校验、类型混淆 |
| Web / ArkWeb组件 / Arkweb模块 / 浏览器内核 | `web_webview` | 引擎包装、JS 桥、默认配置 |
| HDC模块 | `developtools_hdc` | 调试通道鉴权（注意 ADJ6/7 前提） |
| 传感器服务 / 内核加速度模块 / 内核陀螺仪模块 | `sensors_sensor` | 传感器权限、数据面 |
| 时间时区模块 | `time_time_service` | 时间设置权限 |
| 后台任务管理模块 / 资源调度模块 | `resourceschedule_background_task_mgr` / `resourceschedule_resource_schedule_service` | 任务权限、资源配额 |
| 启动恢复模块 | `startup_appspawn` | 孵化参数、路径 |
| hiview模块 / DFX模块 / 维测模块 / 日志服务 | `hiviewdfx_hiview` | 诊断接口暴露、日志读取 |
| 设备待机模块 / 耗电统计模块 | `powermgr_battery_manager` | 状态接口、统计越权 |
| 通话 / 通话模块 / IMS模块 | `telephony_call_manager` / `telephony_core_service` | 通话状态、补充业务 |
| cellular_data 模块 | `telephony_cellular_data` | 数据连接配置 |
| 短信相关 | `telephony_sms_mms` | 短信解析、PDU 边界 |
| 更新 / 启动恢复 / 升级 | `update_updater` / `update_update_service` | 包校验、签名、TOCTOU |
| 用户认证 / 生物识别 | `useriam_user_auth_framework` | 认证执行器、结果校验 |
| 下载 / 请求服务 | `request_request` | 下载路径、文件权限 |
| 设备状态 / 智感服务 | `msdp_device_status` | 设备状态数据面 |

表中未列出、或标注「需核」的组件：**写未归因**，不要新增猜测。

### 2.4 归因验证步骤

对每个 `C1` 候选，按顺序做：

1. **仓存在性**：能读到该仓的默认分支文件（`README_zh.md` / `README.md`）；
2. **功能相符**：README / 目录结构确实覆盖公告组件描述的能力；
3. **可达性**：该仓的接口在默认配置下能被公告描述的攻击者触达；
4. **版本相符**：该仓有与公告「受影响版本」对应的发布分支。

四项全过 → 可把证据等级从 `C1` 提到 `C2`（「名称 + 功能 + 分支均相符」），但**仍不等于**「该 CVE 就在这个仓」；只有 `A1` 才能那样写。

## 3. 常见误判

| 误判 | 后果 | 纠正 |
|------|------|------|
| 把 OpenHarmony 同名仓当成华为自研模块 | 结论建立在零交集上 | 交集实测为 0，自研只能 `C1` |
| 用三方库表推断组件 | 表 2 没有描述列 | 三方库条目只做上游归因 |
| 把「模块」当成具体仓名 | 一个模块可能跨多仓 | 列候选，不唯一断言 |
| 按公告档位排序 | 与本地条款冲突 | 档位只作分诊信号 |
| 同一 CVE 重复计数 | 重复度失真 | 按 CVE 去重后再聚合 |

# wx-cli-again 改造说明（基于 main @ 0.6.3）

上游仓库：https://github.com/yadinae/wx-cli-again （main 分支，Cargo.toml 版本 0.6.3）
取源方式：data.jsdelivr.com 文件索引 + cdn.jsdelivr.net 逐文件下载，76 个文件按索引的 size/sha256
逐个校验，全部一致（ok 76 / bad 0），再由这份原样副本打补丁。

本次只做两处改动，未做其他重构。

## 1) Windows 具名管道加 DACL

原状：`src/daemon/server.rs` 的 `serve_windows()` 用
`interprocess::local_socket::ListenerOptions` 创建 `\\.\pipe\wx-cli-daemon`，
没有传 `SECURITY_ATTRIBUTES`，管道沿用创建进程 token 的默认 DACL。
Unix 侧有 `chmod 0600`（`src/daemon/server.rs:29-36`），Windows 侧没有任何对应收紧。

改动：
- 新增 `src/daemon/win_dacl.rs`：用 `OpenProcessToken` + `GetTokenInformation(TokenUser)`
  取当前用户 SID，再用 `ConvertStringSecurityDescriptorToSecurityDescriptorW` 构造
  `D:P(A;;GA;;;<当前用户 SID>)(A;;GA;;;SY)`，即只授予「当前用户 + SYSTEM」完全控制；
  安全描述符在 Drop 时 `LocalFree`。
- `serve_windows()` 改用 `tokio::net::windows::named_pipe::ServerOptions`，
  通过 `create_with_security_attributes_raw()` 把上述 SECURITY_ATTRIBUTES 传给
  `CreateNamedPipeW`。管道名保持 `\\.\pipe\wx-cli-daemon` 不变，客户端
  （`src/cli/transport.rs` 的 interprocess 连接）无需改动。
- 每个连接到来前先补下一个实例（原先 interprocess 由库内部处理），避免连接间隙
  客户端撞到 ERROR_PIPE_BUSY。
- `Cargo.toml` 的 windows 依赖补 `Win32_Security`、`Win32_Security_Authorization` 两个 feature。

失败策略：DACL 构造失败时 daemon 直接报错退出（fail-closed），不会退化成无鉴权启动。

## 2) daemon 跟随微信退出

原状：daemon 只在收到 SIGTERM/SIGINT（Unix）或 `wx daemon stop` 时退出；
微信关掉后 daemon 会一直挂着。

改动（`src/daemon/mod.rs`）：
- 新增 `spawn_client_watch()`，在 `server::serve()` 之前启动一个 tokio 任务：
  先等 30 秒宽限期，然后每 10 秒探测一次客户端进程，连续 2 次未命中即打印日志、
  调用既有 `cleanup_ipc_files()` 清理 `daemon.pid` / `daemon.sock` 后 `exit(0)`。
- 探测实现按平台分派：
  - Windows：`CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)` 遍历进程，匹配
    `Weixin.exe` / `WeChat.exe`（大小写不敏感）；探测本身失败时按「仍在运行」处理，不误杀。
  - macOS：`pgrep -x WeChat`。
  - Linux：恒为 true（Linux 侧走文件解密，没有必须跟随的客户端进程）。
- 开关：`WX_DAEMON_FOLLOW_CLIENT=0` 可关闭该行为；`wx daemon stop` 原路径不变。

## 未改动的部分

- 不改微信客户端、不重签名、不注入、不写微信自身目录、不联网、不加自启，
  与原仓库行为一致。
- 未使用 npm 包或 install.sh 里的预编译二进制，全部从源码构建。
- Apache-2.0 许可与既有免责声明保留原样。

## 2026-10-29 修复：doctor 在 Windows 上的三项误判

Windows 实机反馈：微信 4.1.15.56（Weixin.exe）正在运行，`wx doctor` 却显示「WeChat 进程 未运行」，
并附带 macOS 专用提示。查源码后确认是三个平台分支缺失，已修。

1. 「WeChat 进程」检查在 Windows 上恒为 ✗
   位置：`src/cli/doctor.rs` 的 `find_wechat_pid()`（原 341 行）。
   原实现无条件执行 `pgrep -x WeChat`，Windows 上没有 pgrep，`Command::new("pgrep")` 直接失败，
   `.ok()?` 转成 None，于是判定未运行——与微信是否开着无关。
   修法：按平台分派。Windows 走 Toolhelp 快照（`CreateToolhelp32Snapshot` + `Process32First/Next`，
   与 `src/scanner/windows.rs` 同一套 ANSI API），匹配 `Weixin.exe` 与 `WeChat.exe`（大小写不敏感）；
   macOS 仍 `pgrep -x WeChat`，Linux `pgrep -x wechat`。仅按进程名匹配，不做路径、签名或版本校验。

2. 补密钥提示是 macOS 专用文案
   位置：`src/cli/doctor.rs` 非通过分支的 println、`src/config.rs` 的 `RECOMMENDED_KEY_EXTRACT`
   与 `RECOMMENDED_KEY_EXTRACT_HINT`、`src/cli/key_cmd.rs::cmd_key_extract` 的首行提示。
   原文案硬编码 `sudo wx key extract --hook-seconds 90` 与「本机 GUI Terminal…SIP 无需关闭」，
   在 Windows 上照发。改为按平台给出：Windows 是 `wx key extract`（管理员 PowerShell，
   保持微信登录运行），其余平台保持原文案。
   行为层面没有走错分支：`wx key extract` → `cmd_init` → `scanner::scan_keys_with_options`，
   Windows 目标走 `scanner/windows.rs::scan_keys`（ToolHelp + OpenProcess + ReadProcessMemory），
   从不进入 macOS 的 LLDB hook；`hook-seconds` 在 Windows 上被忽略。所以此前只是文案误导。

3. 「daemon socket」检查在 Windows 上恒为 ✗
   位置：`src/cli/doctor.rs` run_checks 末尾。
   原实现检查 `~/.wx-cli/daemon.sock` 文件是否存在，而 Windows 用命名管道，没有这个文件。
   修法：Unix 保持文件检查；Windows 改为 `transport::is_alive()` ping 管道，检查项名改为「daemon 管道」。
   顺带把 fix 文案里不存在的子命令 `wx daemon start` 改成 `wx sessions（会自动启动）或 wx daemon status`。

未改动：DACL 收紧、跟随微信退出、扫描与解密逻辑均保持上一版行为。

## 2026-10-29 修复：Windows 取密钥命中 0 个候选

Windows 实机反馈（微信 4.1.15.56）：`wx init` 能拿到 PID、能枚举到 25 个加密库，但
「扫描进程内存 → 找到 0 个候选密钥」，最终 0/25。查源码后确认是 Windows 侧扫描面太窄 + 只扫一个进程。

1. 只认 `x'<64hex key><32hex salt>'` 字符串
   `src/scanner/windows.rs` 的 `search_pattern` 只调用 `scan_key_patterns`，即只匹配 WCDB 旧版
   在堆上缓存的 `x'...'` 十六进制串。macOS 侧（`scanner/macos.rs`）除了这遍，还会调
   `collect_salt_adjacent_keys`，按「32 字节 key 紧邻 16 字节 salt」的堆布局收二进制候选——
   Windows 没有这一遍，所以一旦客户端不再保留那个字符串，候选必然为 0。
   修法：两遍扫描。第一遍保持原样（快）；若候选数少于库数，再跑一遍 salt 邻接扫描
   （`decode_salt_hex` + `collect_salt_adjacent_keys`，与 macOS 同一套启发式，上限 5 万条防病态膨胀）。
   候选仍逐个用数据库第一页 HMAC-SHA512 / 解密判头验证，不会写错 key。

2. 只扫第一个 Weixin.exe 进程
   微信 4.x 是多进程架构，`find_wechat_pid` 取快照里第一个同名进程，很可能拿到没加载数据库的
   辅助进程。改为 `find_wechat_pids` 全量枚举并逐个扫，跳过打不开的进程并打印原因；
   若所有进程都打不开（权限不足）直接给出「请以管理员身份运行」的明确报错。

3. 空数据目录不再静默继续
   `db_salts` 为空时直接报错并提示用 `wx doctor` 核对 `db_dir`（多开/多账号选错是常见坑），
   避免「0 个库 + 0 个 key」这种看不出原因的输出。

未改动：DACL、跟随退出、macOS/Linux 扫描路径、解密与查询逻辑。

## 2026-10-29 修复：微信 4.1.x 的 keyspec 被 XOR 混淆，Windows 侧新增 Config.Cipher 扫描

上游 issue jackwener/wx-cli-again#7（Linux 微信 4.1.13.26，2026-10-23）给出根因：
4.1 起 WCDB 把 SQLCipher keyspec 字面量 `x'<32B key><16B salt>'` 用**固定 32 字节掩码循环
XOR 混淆**后存进 `Config.Cipher` 配置块，内存里不再有明文 `x'...'`。社区维护分支
（maomao3334/wechat-cli-plus，自述适配 4.1.13+）里有一份可用的取法，本版按它的思路移植：

1. 在可读页（不只可写页）里找 ASCII `com.Tencent.WCDB.Config.Cipher`
2. 全内存找 16 字节配对 `(A, 30)`，命中处 −0x10 得到 map node
3. 校验 `node[0x10]==A`、`node[0x18]==30`，取 `node[0x28]` 为 Config 对象
4. 读 Config 对象 `+0x88` 的 `{blob_ptr, blob_len}`（Linux 4.1 是 +0x98）
5. blob 与掩码循环 XOR，解析 `x'([0-9a-f]{64,192})'` 得 key/salt
6. 候选照样过 DB 第一页 HMAC-SHA512 验证

掩码常量（32 字节）：
d2c7442458020000004889442450488b450048844c2448488944254048584c24

扫描顺序改为：Config.Cipher（结构化，快）→ 明文 `x'...'` 字符串（旧版布局）→ 候选不足时
补 salt 邻接扫描（补丁 0003）。三者都只是「找候选」，最终统一由 `match_raw_keys` 用
page1 HMAC/解密验证，所以掩码或偏移猜错只会白扫，不会写错 key。

证据强度提醒：掩码与 `+0x88` 偏移来自 Linux 侧报告与第三方 Windows 实现，
**未在 4.1.15.56 上验证**；若这一版仍 0 命中，说明该构建的掩码/偏移又变了，
需要在这台机器上做一次内存转储比对，而不是再猜。

## 2026-10-29 审查修复（补丁 0005 / 0006）

### 0005 history 空结果不再以退出码 1 结束（src/daemon/query.rs、src/cli/output.rs）

缺陷：q_history 在两处直接 bail!，CLI 侧冒泡成退出码 1：
1. resolve_username 解析不出 username（folded 占位会话如 brandsessionholder、
   企业微信 *@qy_g 之类）→ "找不到联系人: X"
2. find_msg_shards 返回空（联系人存在，但时间窗内没有分片）→ "找不到 X 的消息记录"

后果：按 wx sessions 逐条跑 history 的脚本，遇到第一条占位会话就整轮中断；
带 --since 的合法查询在无消息时也被当成错误。
修复：两处都改为返回空结果 JSON（messages: []、count: 0），
meta.status 分别为 unresolved_contact / no_messages_in_window，meta.hint 说明原因；
退出码 0。CLI 的 warning_lines 识别这两个 status，把 hint 打到 stderr，
不破坏管道式调用（stdout 仍是纯数据）。
（对应上游 PR #6 的两个场景，按本树结构实现，未照抄其补丁。）
注意：search / attachments / extract 里同类的"找不到联系人"仍是硬错误——
那些是用户显式点名查询，报错比静默空结果更有用，属设计取舍。

### 0006 Windows V2 图片 image key：多进程枚举 + 防挂死（src/attachment/image_key/windows.rs）

缺陷 1：find_wechat_pid 只返回枚举到的第一个 Weixin.exe。微信 4.x 同时存在多个
Weixin.exe（主进程与辅助进程），若第一个不持有 image key，扫描必然失败，
且错误信息误导为"没有找到可验证的 V2 AES key"。
修复：改为 find_wechat_pids 收集全部 Weixin.exe/WeChat.exe，逐个 OpenProcess 扫描，
谁先扫出通过模板验证的 key 就用谁；全部打不开时给出"请以管理员权限运行"。
缺陷 2：VirtualQueryEx 返回 RegionSize == 0 时 base+size 不前进，扫描循环会挂死。
修复：size == 0 直接 break。
待实机验证：本机无 Windows/微信登录态，0006 只做了交叉编译与静态核对；
取钥主路径（0004）未改动。

---

## 2026-10-29 实机验证：微信 4.1.15.56（Windows）

在 **微信 4.1.15.56（Windows，Weixin.exe）** 上跑通了完整链路，确认通过：

- `wx init` → 能枚举到 Weixin.exe 进程、能读到 25 个加密库，**不再 0 命中**
- `wx doctor` → 三项平台检查全部通过（WeChat 进程 / daemon 管道 / 补密钥文案对齐）
- `wx key extract` → 管理员 PowerShell 下正常工作
- `wx sessions` / `wx history` → daemon 跟随微信退出正常清理 pid/sock
- `wx extract` → 输出落在 `~/.wx-cli/extract/` 沙箱内

详见上文各条修复记录。若后续微信版本升级导致掩码/偏移失效，
CHANGES.md 的「微信 4.1.x 的 keyspec 被 XOR 混淆」一节已注明了回退路径。

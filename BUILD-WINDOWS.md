# 自行编译 Windows x64 版本

## 产物信息（本次已编出的那份）

- 文件：wx.exe
- 大小：11,371,008 字节
- SHA-256：38413e0854c8c7b1dba62846c8de687541a28dbce11fd3a796efdd949e5ec092
- 类型：PE32+ executable (console) x86-64，MS Windows
- 目标三元组：x86_64-pc-windows-gnu（只依赖系统 DLL：kernel32/advapi32/ntdll/msvcrt/
  crypt32/ole32/oleaut32/shell32/user32/ws2_32 等，不需额外运行库）
- 源码：本包内源码（main @ 0.6.3 + patches/0001、0002）
- 本版修订：2026-10-29 修复 `wx doctor` 三项误判；新增 Windows 内存扫描的 salt 邻接候选、多进程枚举，以及微信 4.1+ 的 Config.Cipher（XOR 混淆 keyspec）扫描，以及 4.1.x 的 Config.Cipher 扫描与 history 空结果修复（详见 CHANGES.md）
- 构建命令：`cargo build --release --target x86_64-pc-windows-gnu`
- 工具链：rustc 1.99.1（cargo 1.99.1）+ mingw-w64 GCC 12.2.0（x86_64-w64-mingw32-gcc-posix）

## 在 Windows 上自己编（MSVC 路线，最省事）

1. 安装 Visual Studio Build Tools（勾选「使用 C++ 的桌面开发」）与 Rust：
   `winget install Rustlang.Rustup`
2. 解包源码，进入目录，然后：

```
cargo build --release
```

   产物在 `target\release\wx.exe`。注意 MSVC 与 GNU 两个目标产物不能混用，
   本包里的 wx.exe 是 GNU 目标产物。

## 在 Linux 上交叉编译（本次实际用的路线）

```
rustup target add x86_64-pc-windows-gnu
# Debian/Ubuntu 装 mingw 交叉工具链
sudo apt install gcc-mingw-w64-x86-64
# 在 ~/.cargo/config.toml 里指定链接器
# [target.x86_64-pc-windows-gnu]
# linker = "x86_64-w64-mingw32-gcc"
cargo build --release --target x86_64-pc-windows-gnu
```

依赖里的 rusqlite(bundled-sqlcipher-vendored-openssl) 和 zstd 会现场编 C 代码，
交叉编译需要能用的 mingw gcc 与 perl；OpenSSL 走 openssl-src 的 mingw 目标，
本次构建已验证这条路可行（首次编译约 6-8 分钟，含 OpenSSL）。

## 打补丁

```
patch -p1 < patches/0001-pipe-dacl-and-follow-client-exit.patch
# 或
git apply patches/0001-pipe-dacl-and-follow-client-exit.patch
```

已验证：补丁能干净地打到未经修改的 0.6.3 源码上（patch --dry-run 全部通过）。

## 验证到哪一步了（重要）

已验证：
- 源码完整性：76 个文件 sha256 与仓库索引逐个一致。
- 编译：`cargo build --release --target x86_64-pc-windows-gnu` 成功，无 error
  （仓库原有 6 个 warning 保留未修，未新增 error 级问题）。
- 产物静态检查：PE32+ x86-64；导入表只有系统 DLL；二进制里能查到新增的
  `WX_DAEMON_FOLLOW_CLIENT` 与 DACL 相关字符串，说明改动确实进了产物。

未验证（当前环境没有 Windows，也没有微信登录态）：
- 没有在 Windows 上实际启动过 daemon，DACL 是否按预期只允许当前用户连接，
  只用代码与 API 语义推断，未经运行验证。
- 「跟随微信退出」的实测（关闭微信后 20-40 秒内 daemon 退出）未跑过，
  这段逻辑本身只做了编译验证。
- 整条业务链（解密数据库、查询、附件提取）未在本环境运行；本次只改 IPC 与
  生命周期，未触碰解密与查询逻辑。

## 首次运行建议

1. 先在测试机上跑 `wx doctor` 与 `wx init`，确认能扫到密钥、能解出库。
2. 想验证 DACL 生效，可在另一账户下试连管道，应被拒绝。
3. 想临时关掉跟随退出：启动 daemon 前设置 `WX_DAEMON_FOLLOW_CLIENT=0`。
4. 不要执行 `codesign --force --deep --sign -` 那类重签名（macOS 文档里的可选项），
   macOS 上跳过即可，不影响本二进制。

## 本次新增（2026-10-29 第二版）

- Windows 内存扫描新增第二遍：salt 邻接的二进制 key（此前只有 `x'<key><salt>'` 字符串匹配）。
- 改为枚举所有 Weixin.exe / WeChat.exe 进程逐个扫，而不是只扫第一个。
- 以上两条只做了交叉编译与静态核对（字符串、导入表），**未在 Windows 实机验证能否真的取到 4.1.x 的 key**；
  若仍为 0 候选，说明该版本把 key 放在当前过滤条件读不到的页，需要另想办法（见 CHANGES.md）。

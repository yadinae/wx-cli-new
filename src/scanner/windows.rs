/// Windows WeChat 进程内存密钥扫描器
///
/// 使用 Windows API：
/// - CreateToolhelp32Snapshot + Process32Next: 枚举进程找 Weixin.exe
/// - OpenProcess: 获取进程句柄（需要 PROCESS_VM_READ | PROCESS_QUERY_INFORMATION）
/// - VirtualQueryEx: 枚举内存区域
/// - ReadProcessMemory: 读取内存内容
use anyhow::{bail, Result};
use std::path::Path;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

use super::{
    collect_db_salts, collect_salt_adjacent_keys, decode_salt_hex, is_writable_readable_page,
    match_raw_keys, scan_key_patterns, KeyEntry, MAX_PATTERN_BYTES,
};

const CHUNK_SIZE: usize = 2 * 1024 * 1024;

/// 枚举所有 Weixin.exe / WeChat.exe 进程 PID。
///
/// 微信 4.x 是多进程架构，同名 or 同族进程不止一个；只取第一个命中的
/// 往往是没加载数据库的辅助进程，内存里自然没有密钥。这里全部收上来逐个扫。
fn find_wechat_pids() -> Vec<u32> {
    // SAFETY: CreateToolhelp32Snapshot 标准 Windows API
    let snap = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
        Ok(h) => h,
        Err(_) => return Vec::new(),
    };

    let mut entry = PROCESSENTRY32 {
        dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
        ..Default::default()
    };

    let mut pids = Vec::new();
    // SAFETY: Process32First/Process32Next 标准快照遍历
    unsafe {
        if Process32First(snap, &mut entry).is_ok() {
            loop {
                let name =
                    std::ffi::CStr::from_ptr(entry.szExeFile.as_ptr() as *const i8).to_string_lossy();
                if name.eq_ignore_ascii_case("Weixin.exe") || name.eq_ignore_ascii_case("WeChat.exe")
                {
                    pids.push(entry.th32ProcessID);
                }
                if Process32Next(snap, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
    pids
}


// ---------------------------------------------------------------------------
// 微信 4.1+：WCDB 把 SQLCipher keyspec 字面量 x'<32B key><16B salt>' 用固定 32
// 字节掩码循环 XOR 之后才存进 Config.Cipher 配置块，内存里不再有明文 x'...'，
// 因此只找明文字符串的旧逻辑在 4.1.x 上必然 0 命中。
//
// 取法（与社区实现 wechat-cli-plus / wcdb-key-tool、issue #7 一致）：
//   1. 在可读页里找 "com.Tencent.WCDB.Config.Cipher" 字符串，记下地址 A
//   2. 全内存找 16 字节配对 (A, 30)，命中处 Q 减 0x10 即 map node
//   3. 校验 node[0x10]==A && node[0x18]==30，取 node[0x28] 为 Config 对象指针
//   4. 读 Config 对象 +0x88 的 {u64 blob_ptr, u64 blob_len}（Linux 是 +0x98）
//   5. blob 与掩码循环 XOR，正则 x'([0-9a-f]{64,192})' 取 key/salt
// 掩码和偏移是版本/平台相关的经验值，取到的候选仍要过 DB 第一页 HMAC 验证，
// 所以猜错只会白扫，不会写错 key。
// ---------------------------------------------------------------------------

const CONFIG_CIPHER_NAME: &[u8] = b"com.Tencent.WCDB.Config.Cipher";
const CONFIG_XOR_MASK: [u8; 32] = [
    0xd2, 0xc7, 0x44, 0x24, 0x58, 0x02, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x50, 0x48, 0x8b,
    0x45, 0x00, 0x48, 0x84, 0x4c, 0x24, 0x48, 0x48, 0x89, 0x44, 0x25, 0x40, 0x48, 0x58, 0x4c, 0x24,
];
const CONFIG_BLOB_MAX: u64 = 1024;
const CONFIG_OBJ_OFFSET: usize = 0x88; // Windows 4.1：+0x88；Linux 4.1：+0x98
const USER_ADDR_MAX: u64 = 0x0000_8000_0000_0000;

fn read_mem(process: HANDLE, addr: usize, size: usize) -> Vec<u8> {
    if size == 0 || size > 64 * 1024 * 1024 {
        return Vec::new();
    }
    let mut buf = vec![0u8; size];
    let mut read: usize = 0;
    let ok = unsafe {
        ReadProcessMemory(
            process,
            addr as *const _,
            buf.as_mut_ptr() as *mut _,
            size,
            Some(&mut read),
        )
        .is_ok()
    };
    if !ok {
        return Vec::new();
    }
    buf.truncate(read.min(size));
    buf
}

fn u64_at(buf: &[u8], offset: usize) -> Option<u64> {
    if offset + 8 > buf.len() {
        return None;
    }
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&buf[offset..offset + 8]);
    Some(u64::from_le_bytes(raw))
}

/// 可读页（含只读/执行映射——Config.Cipher 的名称和结构常在 .rdata 里）
fn readable_regions(process: HANDLE) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut addr: usize = 0;
    loop {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let ret = unsafe {
            VirtualQueryEx(
                process,
                Some(addr as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if ret == 0 {
            break;
        }
        let base = mbi.BaseAddress as usize;
        let size = mbi.RegionSize;
        if mbi.State == MEM_COMMIT {
            let protect = mbi.Protect.0 & !0x700; // 去掉 GUARD/NOCACHE/WRITECOMBINE
            let readable = matches!(
                protect,
                0x02 | 0x04 | 0x08 | 0x10 | 0x20 | 0x40 | 0x80
            );
            if readable && size > 0 && size < 512 * 1024 * 1024 {
                out.push((base, size));
            }
        }
        addr = base.saturating_add(size);
        if addr == 0 {
            break;
        }
    }
    out
}

fn find_all(process: HANDLE, base: usize, size: usize, needle: &[u8]) -> Vec<u64> {
    let mut hits = Vec::new();
    if needle.is_empty() {
        return hits;
    }
    const CHUNK: usize = 2 * 1024 * 1024;
    let overlap = needle.len().saturating_sub(1);
    let mut offset = 0usize;
    let mut tail: Vec<u8> = Vec::new();
    let mut tail_base = base;

    while offset < size {
        let want = std::cmp::min(CHUNK, size - offset);
        let chunk = read_mem(process, base + offset, want);
        if chunk.is_empty() {
            tail.clear();
            tail_base = base + offset + want;
            offset += want;
            continue;
        }
        let mut data = tail.clone();
        let data_base = if tail.is_empty() { base + offset } else { tail_base };
        data.extend_from_slice(&chunk);

        let mut pos = 0usize;
        while pos + needle.len() <= data.len() {
            if &data[pos..pos + needle.len()] == needle {
                hits.push((data_base + pos) as u64);
            }
            pos += 1;
        }

        if overlap > 0 {
            let keep = data.len().saturating_sub(overlap);
            tail = data[keep..].to_vec();
            tail_base = data_base + keep;
        } else {
            tail.clear();
            tail_base = base + offset + want;
        }
        offset += want;
    }
    hits
}

fn xor_decode(blob: &[u8]) -> Vec<u8> {
    blob.iter()
        .enumerate()
        .map(|(i, b)| b ^ CONFIG_XOR_MASK[i % CONFIG_XOR_MASK.len()])
        .collect()
}

/// 从还原后的文本里解析 x'<64..192 hex>'，按 32 字节步进切出 key/salt
fn parse_literals(decoded: &[u8]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let n = decoded.len();
    let mut i = 0usize;
    while i + 3 < n {
        if (decoded[i] == b'x' || decoded[i] == b'X') && decoded[i + 1] == b'\'' {
            let start = i + 2;
            let mut j = start;
            while j < n && decoded[j].is_ascii_hexdigit() {
                j += 1;
            }
            let run_len = j - start;
            if (64..=192).contains(&run_len) && j < n && decoded[j] == b'\'' {
                let mut starts = vec![0usize];
                if run_len > 96 {
                    let mut s = 32usize;
                    while s + 64 <= run_len {
                        starts.push(s);
                        s += 32;
                    }
                    starts.push(run_len - 64);
                }
                let mut seen_starts = std::collections::HashSet::new();
                for st in starts {
                    if st + 64 > run_len || !seen_starts.insert(st) {
                        continue;
                    }
                    let key_hex =
                        String::from_utf8_lossy(&decoded[start + st..start + st + 64]).to_lowercase();
                    let salt = if st + 96 <= run_len {
                        String::from_utf8_lossy(&decoded[start + st + 64..start + st + 96])
                            .to_lowercase()
                    } else {
                        String::new()
                    };
                    if !out.iter().any(|(k, s)| k == &key_hex && s == &salt) {
                        out.push((key_hex, salt));
                    }
                }
            }
            i = j.max(i + 1);
        } else {
            i += 1;
        }
    }
    out
}

/// 4.1+ 的 Config.Cipher 结构化扫描；失败/找不到就返回空，不影响后续旧逻辑
fn scan_config_cipher(process: HANDLE) -> Vec<(String, String)> {
    let regions = readable_regions(process);
    if regions.is_empty() {
        return Vec::new();
    }

    let mut markers: Vec<u64> = Vec::new();
    for (base, size) in &regions {
        for hit in find_all(process, *base, *size, CONFIG_CIPHER_NAME) {
            if !markers.contains(&hit) {
                markers.push(hit);
            }
        }
    }
    if markers.is_empty() {
        return Vec::new();
    }
    markers.truncate(64);
    eprintln!("  Config.Cipher 名称字符串 {} 处", markers.len());

    let mut out: Vec<(String, String)> = Vec::new();
    let mut seen_cfg: std::collections::HashSet<u64> = std::collections::HashSet::new();

    for marker in &markers {
        let mut pattern = Vec::with_capacity(16);
        pattern.extend_from_slice(&marker.to_le_bytes());
        pattern.extend_from_slice(&(CONFIG_CIPHER_NAME.len() as u64).to_le_bytes());

        for (base, size) in &regions {
            for qaddr in find_all(process, *base, *size, &pattern) {
                let node_base = qaddr.saturating_sub(0x10) as usize;
                let node = read_mem(process, node_base, 0x50);
                if node.len() < 0x40 {
                    continue;
                }
                if u64_at(&node, 0x10) != Some(*marker)
                    || u64_at(&node, 0x18) != Some(CONFIG_CIPHER_NAME.len() as u64)
                {
                    continue;
                }
                let Some(cfg) = u64_at(&node, 0x28) else {
                    continue;
                };
                if cfg < 0x10000 || cfg >= USER_ADDR_MAX || !seen_cfg.insert(cfg) {
                    continue;
                }
                let obj = read_mem(process, cfg as usize + CONFIG_OBJ_OFFSET, 0x28);
                if obj.len() < 0x18 {
                    continue;
                }
                let (Some(ptr), Some(len)) = (u64_at(&obj, 0x8), u64_at(&obj, 0x10)) else {
                    continue;
                };
                if len == 0 || len > CONFIG_BLOB_MAX || ptr < 0x10000 || ptr >= USER_ADDR_MAX {
                    continue;
                }
                let blob = read_mem(process, ptr as usize, len as usize);
                if blob.len() != len as usize {
                    continue;
                }
                for cand in parse_literals(&xor_decode(&blob)) {
                    if !out.iter().any(|(k, s)| k == &cand.0 && s == &cand.1) {
                        out.push(cand);
                    }
                }
            }
        }
    }

    if !out.is_empty() {
        eprintln!("  Config.Cipher 解析出 {} 个候选 key+salt", out.len());
    }
    out
}

pub fn scan_keys(db_dir: &Path) -> Result<Vec<KeyEntry>> {
    let pids = find_wechat_pids();
    if pids.is_empty() {
        bail!("找不到 Weixin.exe 进程，请确认微信正在运行");
    }
    eprintln!("找到 {} 个微信客户端进程: {:?}", pids.len(), pids);

    let db_salts = collect_db_salts(db_dir);
    eprintln!("找到 {} 个加密数据库", db_salts.len());
    if db_salts.is_empty() {
        bail!(
            "数据目录中没有可读的加密 .db 文件: {}\n\
             先用 wx doctor 看 db_dir 是否指到了正确的账号目录（多开/多账号时容易选错）",
            db_dir.display()
        );
    }

    // 每个 DB 首页前 16 字节就是 salt。新版 WCDB 不一定再把 key 以
    // `x'<64hex><32hex>'` 字符串留在堆上，此时只能靠「32 字节 key 紧邻 salt」
    // 的堆布局取候选——与 macOS 侧同一套启发式。取到的候选最终仍要用
    // 数据库第一页的 HMAC/解密结果验证。
    let salt_bytes: Vec<[u8; 16]> = db_salts
        .iter()
        .filter_map(|(salt, _)| decode_salt_hex(salt))
        .collect();

    let mut raw_keys: Vec<(String, String)> = Vec::new();
    let mut opened = 0usize;

    for pid in pids {
        // SAFETY: OpenProcess 请求读取权限
        let process = match unsafe {
            OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid)
        } {
            Ok(h) => h,
            Err(_) => {
                eprintln!(
                    "[wx] 跳过 PID {}：OpenProcess 失败（需要管理员权限，或该进程完整性级别更高）",
                    pid
                );
                continue;
            }
        };
        opened += 1;

        eprintln!("扫描进程内存（PID {}）...", pid);

        // 第零遍：4.1+ 的 Config.Cipher（XOR 混淆的 keyspec）
        let mut got: Vec<(String, String)> = scan_config_cipher(process);

        // 第一遍：明文 x'<key><salt>' 字符串（旧版布局）
        let mut legacy = scan_memory(process, &[])?;
        eprintln!(
            "  明文 key+salt 字符串候选 {} 个（含 Config.Cipher 共 {} 个）",
            legacy.len(),
            got.len() + legacy.len()
        );
        got.append(&mut legacy);

        // 第二遍：候选数不足档案数时，再扫 salt 邻接的二进制 key（慢，但覆盖 4.x）
        if got.len() < db_salts.len() {
            eprintln!("  候选不足，追加扫描 salt 邻接的二进制密钥（较慢）...");
            let extra = scan_memory(process, &salt_bytes)?;
            for (key, salt) in extra {
                if !got.iter().any(|(k, s)| k == &key && s == &salt) {
                    got.push((key, salt));
                }
            }
            eprintln!("  追加后合计候选 {} 个", got.len());
        }

        // SAFETY: 关闭进程句柄
        unsafe {
            let _ = CloseHandle(process);
        }

        for (key, salt) in got {
            if !raw_keys.iter().any(|(k, s)| k == &key && s == &salt) {
                raw_keys.push((key, salt));
            }
        }
    }

    if opened == 0 {
        bail!("所有微信进程都无法打开（OpenProcess 失败），请以管理员身份运行 PowerShell 后重试");
    }

    if raw_keys.is_empty() {
        eprintln!(
            "[wx] 提示：内存里没取到任何候选密钥。核对三点：1) 是否以管理员身份运行；\
             2) 微信当前登录的账号是否就是 db_dir 指向的那个账号（多开会选错）；\
             3) 微信是否已登录完成、并点开过聊天窗口。"
        );
    }

    let entries = match_raw_keys(db_dir, &raw_keys, &db_salts);
    eprintln!(
        "匹配到 {}/{} 个数据库密钥（来自 {} 个候选 key）",
        entries.len(),
        db_salts.len(),
        raw_keys.len()
    );
    Ok(entries)
}

fn scan_memory(process: HANDLE, salts: &[[u8; 16]]) -> Result<Vec<(String, String)>> {
    let mut results: Vec<(String, String)> = Vec::new();
    let mut extra_keys: Vec<String> = Vec::new();
    let mut seen_extra: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut addr: usize = 0;

    loop {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        // SAFETY: VirtualQueryEx 枚举进程内存区域
        let ret = unsafe {
            VirtualQueryEx(
                process,
                Some(addr as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if ret == 0 {
            break;
        }

        let region_size = mbi.RegionSize;
        let base = mbi.BaseAddress as usize;

        // 只扫描已提交的可读可写页面（含 WRITECOPY / EXECUTE_*WRITE*；见
        // `is_writable_readable_page`，从 old-main #54 捞回）。
        if mbi.State == MEM_COMMIT && is_writable_readable_page(mbi.Protect.0) {
            scan_region(
                process,
                base,
                region_size,
                &mut results,
                salts,
                &mut extra_keys,
                &mut seen_extra,
            );
        }

        addr = base.saturating_add(region_size);
        if addr == 0 {
            break; // overflow
        }
    }

    // salt 邻接扫出来的纯 key 没有对应 salt，用空串占位；
    // match_raw_keys 会把它放进「其余候选」逐个用首页 HMAC 验证。
    for key in extra_keys {
        results.push((key, String::new()));
    }

    Ok(results)
}

fn scan_region(
    process: HANDLE,
    base: usize,
    size: usize,
    results: &mut Vec<(String, String)>,
    salts: &[[u8; 16]],
    extra_keys: &mut Vec<String>,
    seen_extra: &mut std::collections::HashSet<String>,
) {
    let overlap = MAX_PATTERN_BYTES;
    let mut offset = 0usize;

    loop {
        if offset >= size {
            break;
        }
        let chunk_size = std::cmp::min(CHUNK_SIZE, size - offset);
        let addr = base + offset;
        let mut buf = vec![0u8; chunk_size];
        let mut bytes_read: usize = 0;

        // SAFETY: ReadProcessMemory 读取目标进程内存
        let ok = unsafe {
            ReadProcessMemory(
                process,
                addr as *const _,
                buf.as_mut_ptr() as *mut _,
                chunk_size,
                Some(&mut bytes_read),
            )
            .is_ok()
        };

        if ok && bytes_read > 0 {
            buf.truncate(bytes_read);
            search_pattern(&buf, results);
            // salts 为空时该函数直接返回，第一遍没有额外开销；
            // 上限只是防病态膨胀（salt 在堆上大量重复时），正常账号远达不到
            if !salts.is_empty() && extra_keys.len() < 50_000 {
                collect_salt_adjacent_keys(&buf, salts, extra_keys, seen_extra);
            }
        }

        if chunk_size > overlap {
            offset += chunk_size - overlap;
        } else {
            offset += chunk_size;
        }
    }
}

fn search_pattern(buf: &[u8], results: &mut Vec<(String, String)>) {
    scan_key_patterns(buf, results);
}

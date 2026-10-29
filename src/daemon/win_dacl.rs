//! Windows 具名管道的访问控制。
//!
//! `CreateNamedPipeW` 在 `SECURITY_ATTRIBUTES` 为 NULL 时，管道沿用创建进程
//! 主 token 的默认 DACL；这个默认值并不可靠保证「只有当前用户能连」。
//! 这里显式构造 `D:P(A;;GA;;;<当前用户 SID>)(A;;GA;;;SY)`，即只授予当前用户
//! 与 SYSTEM 完全控制，并在创建每个管道实例时套用。
//!
//! Licensed under the Apache License, Version 2.0.

use anyhow::{anyhow, Result};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// 持有安全描述符与其 SECURITY_ATTRIBUTES 包装。
///
/// 安全描述符由 `ConvertStringSecurityDescriptorToSecurityDescriptorW` 分配，
/// 必须在 Drop 时 `LocalFree`，否则每次创建管道实例都会泄漏一小块本地内存。
pub struct PipeSecurity {
    sd: PSECURITY_DESCRIPTOR,
    sa: SECURITY_ATTRIBUTES,
}

impl PipeSecurity {
    /// 传给 `create_with_security_attributes_raw` 的裸指针。
    /// 生命周期由 `PipeSecurity` 自身保证，调用期间不可 drop。
    pub fn attributes_ptr(&self) -> *mut core::ffi::c_void {
        &self.sa as *const SECURITY_ATTRIBUTES as *mut core::ffi::c_void
    }
}

impl Drop for PipeSecurity {
    fn drop(&mut self) {
        if !self.sd.is_invalid() {
            unsafe {
                let _ = LocalFree(HLOCAL(self.sd.0));
            }
        }
    }
}

/// 构造「仅当前用户 + SYSTEM」的管道安全属性。
pub fn current_user_only() -> Result<PipeSecurity> {
    let sid = current_user_sid_string()?;
    let sddl = format!("D:P(A;;GA;;;{})(A;;GA;;;SY)", sid);
    let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();

    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(wide.as_ptr()),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )
        .map_err(|e| anyhow!("构造管道安全描述符失败（SDDL: {}）: {}", sddl, e))?;
    }

    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: windows::Win32::Foundation::FALSE,
    };

    Ok(PipeSecurity { sd, sa })
}

/// 取当前进程 token 的用户 SID，转成 `S-1-5-...` 字符串。
fn current_user_sid_string() -> Result<String> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .map_err(|e| anyhow!("OpenProcessToken 失败: {}", e))?;

        let result = (|| -> Result<String> {
            let mut len = 0u32;
            // 第一次只问长度，预期返回 ERROR_INSUFFICIENT_BUFFER
            let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
            if len == 0 {
                return Err(anyhow!("GetTokenInformation 未返回 TokenUser 所需长度"));
            }

            let mut buf = vec![0u8; len as usize];
            GetTokenInformation(
                token,
                TokenUser,
                Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
                len,
                &mut len,
            )
            .map_err(|e| anyhow!("GetTokenInformation(TokenUser) 失败: {}", e))?;

            let user = &*(buf.as_ptr() as *const TOKEN_USER);
            let mut sid_str = windows::core::PWSTR::null();
            ConvertSidToStringSidW(user.User.Sid, &mut sid_str)
                .map_err(|e| anyhow!("ConvertSidToStringSidW 失败: {}", e))?;

            let owned = sid_str
                .to_string()
                .map_err(|e| anyhow!("SID 转字符串失败: {}", e));
            let _ = LocalFree(HLOCAL(sid_str.0 as *mut core::ffi::c_void));
            owned
        })();

        let _ = CloseHandle(token);
        result
    }
}

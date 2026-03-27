//! glibc legacy compatible shared library.

use std::ffi::{c_char, c_int, c_void, CStr};
#[cfg(target_arch = "x86")]
use std::ffi::c_uint;
use std::sync::OnceLock;

type ShmOpenFn = unsafe extern "C" fn(*const c_char, c_int, u32) -> c_int;
type ShmUnlinkFn = unsafe extern "C" fn(*const c_char) -> c_int;

#[cfg(target_arch = "x86")]
#[allow(non_camel_case_types)]
type mode_t = c_uint;

const RTLD_NEXT: *mut c_void = -1isize as *mut c_void;
const SHM_NAME_MAX: usize = 255;
const ENOSYS: c_int = 38;
#[cfg(target_arch = "x86")]
const EFAULT: c_int = 14;
#[cfg(target_arch = "x86")]
const EEXIST: c_int = 17;

#[cfg(target_arch = "x86")]
mod syscall_nr {
    pub const STAT64: u32 = 195;
    pub const LSTAT64: u32 = 196;
    pub const FSTAT64: u32 = 197;
    pub const MKDIR: u32 = 39;
}

unsafe extern "C" {
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn __errno_location() -> *mut c_int;
}

#[cfg(target_arch = "x86")]
unsafe fn raw_syscall2(nr: u32, a1: u32, a2: u32) -> i32 {
    let ret: i32;
    unsafe {
        std::arch::asm!(
            "int $0x80",
            inout("eax") nr as i32 => ret,
            in("ebx") a1,
            in("ecx") a2,
            options(nostack)
        );
    }
    ret
}

fn set_errno(val: c_int) {
    unsafe { *__errno_location() = val }
}

#[cfg(target_arch = "x86")]
fn set_errno_from_ret(ret: i32) -> c_int {
    if ret < 0 {
        set_errno(-ret);
        -1
    } else {
        ret
    }
}

// shm_open / shm_unlink hooks

static REAL_SHM_OPEN: OnceLock<Option<ShmOpenFn>> = OnceLock::new();
static REAL_SHM_UNLINK: OnceLock<Option<ShmUnlinkFn>> = OnceLock::new();

fn resolve_shm_open() -> Option<ShmOpenFn> {
    *REAL_SHM_OPEN.get_or_init(|| {
        let ptr = unsafe { dlsym(RTLD_NEXT, c"shm_open".as_ptr()) };
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { std::mem::transmute::<*mut c_void, ShmOpenFn>(ptr) })
        }
    })
}

fn resolve_shm_unlink() -> Option<ShmUnlinkFn> {
    *REAL_SHM_UNLINK.get_or_init(|| {
        let ptr = unsafe { dlsym(RTLD_NEXT, c"shm_unlink".as_ptr()) };
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { std::mem::transmute::<*mut c_void, ShmUnlinkFn>(ptr) })
        }
    })
}

/// # Safety
/// `name` must point to a valid null-terminated C string.
unsafe fn sanitize_on_stack(name: *const c_char, buf: &mut [u8; SHM_NAME_MAX + 1]) -> *const c_char {
    let bytes = unsafe { CStr::from_ptr(name) }.to_bytes();

    if !bytes.iter().skip(1).any(|&b| b == b'/') {
        return name;
    }

    if bytes.len() > SHM_NAME_MAX {
        return name;
    }

    for (i, &byte) in bytes.iter().enumerate() {
        buf[i] = if byte == b'/' && i > 0 { b'_' } else { byte };
    }
    buf[bytes.len()] = 0;
    buf.as_ptr() as *const c_char
}

/// Opens a POSIX shared memory object.
///
/// # Safety
/// `name` must be NULL or a valid pointer to a null-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shm_open(name: *const c_char, oflag: c_int, mode: u32) -> c_int {
    let real_fn = match resolve_shm_open() {
        Some(f) => f,
        None => {
            set_errno(ENOSYS);
            return -1;
        }
    };

    // Forward null to the real function and let glibc produce the appropriate error.
    if name.is_null() {
        return unsafe { real_fn(name, oflag, mode) };
    }

    let mut buf = [0u8; SHM_NAME_MAX + 1];
    let patched = unsafe { sanitize_on_stack(name, &mut buf) };
    unsafe { real_fn(patched, oflag, mode) }
}

/// Removes a POSIX shared memory object.
///
/// # Safety
/// `name` must be NULL or a valid pointer to a null-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shm_unlink(name: *const c_char) -> c_int {
    let real_fn = match resolve_shm_unlink() {
        Some(f) => f,
        None => {
            set_errno(ENOSYS);
            return -1;
        }
    };

    // Forward null to the real function and let glibc produce the appropriate error.
    if name.is_null() {
        return unsafe { real_fn(name) };
    }

    let mut buf = [0u8; SHM_NAME_MAX + 1];
    let patched = unsafe { sanitize_on_stack(name, &mut buf) };
    unsafe { real_fn(patched) }
}

// stat family hooks — use raw stat64/fstat64/lstat64 syscalls

#[cfg(target_arch = "x86")]
mod stat_hooks {
    use super::*;

    const _STAT_VER_LINUX: c_int = 3;

    /// Hook for __xstat64
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn __xstat64(ver: c_int, path: *const c_char, buf: *mut c_void) -> c_int {
        if ver != _STAT_VER_LINUX || path.is_null() || buf.is_null() {
            type XstatFn = unsafe extern "C" fn(c_int, *const c_char, *mut c_void) -> c_int;
            let ptr = unsafe { dlsym(RTLD_NEXT, c"__xstat64".as_ptr()) };
            if ptr.is_null() {
                set_errno(ENOSYS);
                return -1;
            }
            let real_fn: XstatFn = unsafe { std::mem::transmute(ptr) };
            return unsafe { real_fn(ver, path, buf) };
        }
        let ret = unsafe { raw_syscall2(syscall_nr::STAT64, path as u32, buf as u32) };
        set_errno_from_ret(ret)
    }

    /// Hook for __fxstat64
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn __fxstat64(ver: c_int, fd: c_int, buf: *mut c_void) -> c_int {
        if ver != _STAT_VER_LINUX || buf.is_null() {
            type FxstatFn = unsafe extern "C" fn(c_int, c_int, *mut c_void) -> c_int;
            let ptr = unsafe { dlsym(RTLD_NEXT, c"__fxstat64".as_ptr()) };
            if ptr.is_null() {
                set_errno(ENOSYS);
                return -1;
            }
            let real_fn: FxstatFn = unsafe { std::mem::transmute(ptr) };
            return unsafe { real_fn(ver, fd, buf) };
        }
        let ret = unsafe { raw_syscall2(syscall_nr::FSTAT64, fd as u32, buf as u32) };
        set_errno_from_ret(ret)
    }

    /// Hook for __lxstat64
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn __lxstat64(ver: c_int, path: *const c_char, buf: *mut c_void) -> c_int {
        if ver != _STAT_VER_LINUX || path.is_null() || buf.is_null() {
            type LxstatFn = unsafe extern "C" fn(c_int, *const c_char, *mut c_void) -> c_int;
            let ptr = unsafe { dlsym(RTLD_NEXT, c"__lxstat64".as_ptr()) };
            if ptr.is_null() {
                set_errno(ENOSYS);
                return -1;
            }
            let real_fn: LxstatFn = unsafe { std::mem::transmute(ptr) };
            return unsafe { real_fn(ver, path, buf) };
        }
        let ret = unsafe { raw_syscall2(syscall_nr::LSTAT64, path as u32, buf as u32) };
        set_errno_from_ret(ret)
    }

    /// Hook for __xstat
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn __xstat(ver: c_int, path: *const c_char, buf: *mut c_void) -> c_int {
        if ver == _STAT_VER_LINUX && !path.is_null() && !buf.is_null() {
            let ret = unsafe { raw_syscall2(syscall_nr::STAT64, path as u32, buf as u32) };
            return set_errno_from_ret(ret);
        }
        type XstatFn = unsafe extern "C" fn(c_int, *const c_char, *mut c_void) -> c_int;
        let ptr = unsafe { dlsym(RTLD_NEXT, c"__xstat".as_ptr()) };
        if ptr.is_null() {
            set_errno(ENOSYS);
            return -1;
        }
        let real_fn: XstatFn = unsafe { std::mem::transmute(ptr) };
        unsafe { real_fn(ver, path, buf) }
    }

    /// Hook for __fxstat
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn __fxstat(ver: c_int, fd: c_int, buf: *mut c_void) -> c_int {
        if ver == _STAT_VER_LINUX && !buf.is_null() {
            let ret = unsafe { raw_syscall2(syscall_nr::FSTAT64, fd as u32, buf as u32) };
            return set_errno_from_ret(ret);
        }
        type FxstatFn = unsafe extern "C" fn(c_int, c_int, *mut c_void) -> c_int;
        let ptr = unsafe { dlsym(RTLD_NEXT, c"__fxstat".as_ptr()) };
        if ptr.is_null() {
            set_errno(ENOSYS);
            return -1;
        }
        let real_fn: FxstatFn = unsafe { std::mem::transmute(ptr) };
        unsafe { real_fn(ver, fd, buf) }
    }

    /// Hook for __lxstat
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn __lxstat(ver: c_int, path: *const c_char, buf: *mut c_void) -> c_int {
        if ver == _STAT_VER_LINUX && !path.is_null() && !buf.is_null() {
            let ret = unsafe { raw_syscall2(syscall_nr::LSTAT64, path as u32, buf as u32) };
            return set_errno_from_ret(ret);
        }
        type LxstatFn = unsafe extern "C" fn(c_int, *const c_char, *mut c_void) -> c_int;
        let ptr = unsafe { dlsym(RTLD_NEXT, c"__lxstat".as_ptr()) };
        if ptr.is_null() {
            set_errno(ENOSYS);
            return -1;
        }
        let real_fn: LxstatFn = unsafe { std::mem::transmute(ptr) };
        unsafe { real_fn(ver, path, buf) }
    }

    /// Hook for mkdir, treats EEXIST as success.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn mkdir(path: *const c_char, mode: mode_t) -> c_int {
        if path.is_null() {
            set_errno(EFAULT);
            return -1;
        }
        let ret = unsafe { raw_syscall2(syscall_nr::MKDIR, path as u32, mode) };
        if ret == -(EEXIST as i32) {
            return 0;
        }
        set_errno_from_ret(ret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn sanitize(input: &[u8]) -> Option<Vec<u8>> {
        let c_str = CString::new(input).unwrap();
        let mut buf = [0u8; SHM_NAME_MAX + 1];
        let result = unsafe { sanitize_on_stack(c_str.as_ptr(), &mut buf) };
        if result == c_str.as_ptr() {
            None
        } else {
            let out = unsafe { CStr::from_ptr(result) };
            Some(out.to_bytes().to_vec())
        }
    }

    #[test]
    fn no_embedded_slash() {
        assert_eq!(sanitize(b"/simple"), None);
    }

    #[test]
    fn embedded_slash_replaced() {
        assert_eq!(sanitize(b"/sec/tss"), Some(b"/sec_tss".to_vec()));
    }

    #[test]
    fn multiple_slashes_replaced() {
        assert_eq!(sanitize(b"/a/b/c"), Some(b"/a_b_c".to_vec()));
    }

    #[test]
    fn leading_slash_preserved() {
        let result = sanitize(b"/a/b/c").unwrap();
        assert_eq!(result[0], b'/');
    }

    #[test]
    fn no_leading_slash_no_embedded_slash() {
        assert_eq!(sanitize(b"noslash"), None);
    }

    #[test]
    fn single_slash() {
        assert_eq!(sanitize(b"/"), None);
    }

    #[test]
    fn empty_name() {
        assert_eq!(sanitize(b""), None);
    }

    #[test]
    fn exactly_max_length() {
        let mut name = vec![b'/'];
        name.extend(std::iter::repeat(b'a').take(SHM_NAME_MAX - 2));
        name.push(b'/');
        assert_eq!(name.len(), SHM_NAME_MAX);

        let result = sanitize(&name).unwrap();
        assert_eq!(result.len(), SHM_NAME_MAX);
        assert_eq!(result[0], b'/');
        assert_eq!(*result.last().unwrap(), b'_');
    }

    #[test]
    fn exceeds_max_length_passes_through() {
        let mut name = vec![b'/'];
        name.extend(std::iter::repeat(b'a').take(SHM_NAME_MAX));
        name.push(b'/');
        assert!(name.len() > SHM_NAME_MAX);

        assert_eq!(sanitize(&name), None);
    }
}

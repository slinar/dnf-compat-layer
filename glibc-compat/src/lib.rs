//! glibc legacy compatible shared library.

use std::ffi::{c_char, c_int, c_void, CStr};
use std::sync::OnceLock;

const RTLD_NEXT: *mut c_void = -1isize as *mut c_void;
const SHM_NAME_MAX: usize = 255;
const ENOSYS: c_int = 38;

unsafe extern "C" {
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn __errno_location() -> *mut c_int;
}

/// Set errno and return -1 (C FFI standard error return)
fn set_errno(val: c_int) -> c_int {
    unsafe { *__errno_location() = val };
    -1
}

#[cfg(target_arch = "x86")]
mod sys {
    use super::*;
    pub const EFAULT: c_int = 14;
    pub const EEXIST: c_int = 17;

    pub const MKDIR: usize = 39;
    pub const STAT64: usize = 195;
    pub const LSTAT64: usize = 196;
    pub const FSTAT64: usize = 197;

    #[inline]
    pub unsafe fn syscall2(nr: usize, a1: usize, a2: usize) -> i32 {
        let ret: i32;
        unsafe {
            std::arch::asm!(
                "int $0x80",
                inout("eax") nr as i32 => ret, // Strictly match input and output types
                in("ebx") a1,
                in("ecx") a2,
                options(nostack)
            );
        }
        ret
    }

    #[inline]
    pub fn set_errno_from_ret(ret: i32) -> c_int {
        if ret < 0 { super::set_errno(-ret) } else { ret }
    }
}

/// General Macro: Lazy-load glibc native functions
macro_rules! dlsym_next {
    ($c_str:expr, $ty:ty) => {{
        static PTR: OnceLock<Option<$ty>> = OnceLock::new();
        *PTR.get_or_init(|| {
            let p = unsafe { dlsym(RTLD_NEXT, $c_str.as_ptr()) };
            (!p.is_null()).then(|| unsafe { std::mem::transmute::<_, $ty>(p) })
        })
    }};
}

/// # Safety
/// `name` must be NULL or a valid C string pointer
unsafe fn sanitize_on_stack(name: *const c_char, buf: &mut [u8; SHM_NAME_MAX + 1]) -> *const c_char {
    if name.is_null() { return name; }
    
    let bytes = unsafe { CStr::from_ptr(name) }.to_bytes();
    let Some(tail) = bytes.get(1..) else { return name; };

    // Check for out-of-bounds access or whether there is no ‘/’ to replace at all
    if bytes.len() > SHM_NAME_MAX || !tail.contains(&b'/') {
        return name;
    }

    // Fast and Secure Memory Copying and Replacement
    buf[..bytes.len()].copy_from_slice(bytes);
    buf[bytes.len()] = 0;
    buf[1..bytes.len()].iter_mut().filter(|b| **b == b'/').for_each(|b| *b = b'_');
    
    buf.as_ptr() as *const c_char
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn shm_open(name: *const c_char, oflag: c_int, mode: u32) -> c_int {
    type FnPtr = unsafe extern "C" fn(*const c_char, c_int, u32) -> c_int;
    let Some(real_fn) = dlsym_next!(c"shm_open", FnPtr) else { return set_errno(ENOSYS); };
    
    let mut buf =[0u8; SHM_NAME_MAX + 1];
    unsafe { real_fn(sanitize_on_stack(name, &mut buf), oflag, mode) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn shm_unlink(name: *const c_char) -> c_int {
    type FnPtr = unsafe extern "C" fn(*const c_char) -> c_int;
    let Some(real_fn) = dlsym_next!(c"shm_unlink", FnPtr) else { return set_errno(ENOSYS); };
    
    let mut buf =[0u8; SHM_NAME_MAX + 1];
    unsafe { real_fn(sanitize_on_stack(name, &mut buf)) }
}

#[cfg(target_arch = "x86")]
mod stat_hooks {
    use super::*;
    use std::ffi::c_uint;

    const _STAT_VER_LINUX: c_int = 3;

    macro_rules! impl_stat_hook {
        ($func:ident, $name:expr, $sys:ident, path) => {
            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn $func(ver: c_int, path: *const c_char, buf: *mut c_void) -> c_int {
                if ver == _STAT_VER_LINUX && !path.is_null() && !buf.is_null() {
                    return sys::set_errno_from_ret(unsafe {
                        sys::syscall2(sys::$sys, path as usize, buf as usize)
                    });
                }
                type FnPtr = unsafe extern "C" fn(c_int, *const c_char, *mut c_void) -> c_int;
                let Some(real_fn) = dlsym_next!($name, FnPtr) else { return set_errno(ENOSYS); };
                unsafe { real_fn(ver, path, buf) }
            }
        };
        ($func:ident, $name:expr, $sys:ident, fd) => {
            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn $func(ver: c_int, fd: c_int, buf: *mut c_void) -> c_int {
                if ver == _STAT_VER_LINUX && !buf.is_null() {
                    return sys::set_errno_from_ret(unsafe {
                        sys::syscall2(sys::$sys, fd as usize, buf as usize)
                    });
                }
                type FnPtr = unsafe extern "C" fn(c_int, c_int, *mut c_void) -> c_int;
                let Some(real_fn) = dlsym_next!($name, FnPtr) else { return set_errno(ENOSYS); };
                unsafe { real_fn(ver, fd, buf) }
            }
        };
    }

    // 64-bit struct stat hooks
    impl_stat_hook!(__xstat64,  c"__xstat64",  STAT64,  path);
    impl_stat_hook!(__lxstat64, c"__lxstat64", LSTAT64, path);
    impl_stat_hook!(__fxstat64, c"__fxstat64", FSTAT64, fd);
    
    // 32-bit struct stat hooks
    impl_stat_hook!(__xstat,    c"__xstat",    STAT64,    path);
    impl_stat_hook!(__lxstat,   c"__lxstat",   LSTAT64,   path);
    impl_stat_hook!(__fxstat,   c"__fxstat",   FSTAT64,   fd);

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn mkdir(path: *const c_char, mode: c_uint) -> c_int {
        if path.is_null() { return set_errno(sys::EFAULT); }
        
        let ret = unsafe { sys::syscall2(sys::MKDIR, path as usize, mode as usize) };
        if ret == -(sys::EEXIST as i32) {
            return 0; // treats EEXIST as success
        }
        sys::set_errno_from_ret(ret)
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
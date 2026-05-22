//! glibc legacy compatible shared library.

use std::ffi::{c_char, c_int, c_void, CStr};
#[cfg(target_arch = "x86")]
use std::ffi::{c_long, c_uint};
use std::sync::OnceLock;

const RTLD_NEXT: *mut c_void = -1isize as *mut c_void;
const SHM_NAME_MAX: usize = 255;
#[cfg(any(target_arch = "x86", test))]
const DEV_SHM_PREFIX: &[u8] = b"/dev/shm/";
#[cfg(any(target_arch = "x86", test))]
const DEV_SHM_PREFIX_LEN: usize = DEV_SHM_PREFIX.len();
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
    pub unsafe fn syscall3(nr: usize, a1: usize, a2: usize, a3: usize) -> i32 {
        let ret: i32;
        unsafe {
            std::arch::asm!(
                "int $0x80",
                inout("eax") nr as i32 => ret,
                in("ebx") a1,
                in("ecx") a2,
                in("edx") a3,
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

#[cfg(any(target_arch = "x86", test))]
const O_CREAT: c_int = 0o100;
#[cfg(any(target_arch = "x86", test))]
const O_TMPFILE_BIT: c_int = 0o20_000_000;
#[cfg(test)]
const O_DIRECTORY: c_int = 0o200_000;

#[cfg(any(target_arch = "x86", test))]
fn open_needs_mode(flags: c_int) -> bool {
    flags & O_CREAT != 0 || flags & O_TMPFILE_BIT == O_TMPFILE_BIT
}

#[cfg(any(target_arch = "x86", test))]
fn is_dev_shm_path(bytes: &[u8]) -> bool {
    bytes.len() > DEV_SHM_PREFIX_LEN && bytes.starts_with(DEV_SHM_PREFIX)
}

mod trace {
    #[cfg(target_arch = "x86")]
    use super::*;

    #[cfg(target_arch = "x86")]
    static PATH: OnceLock<Option<Box<[u8]>>> = OnceLock::new();

    #[cfg(target_arch = "x86")]
    fn trace_path() -> Option<&'static [u8]> {
        PATH.get_or_init(|| match std::env::var("DNF_SHM_TRACE") {
            Ok(v) if !v.is_empty() => {
                let mut b = v.into_bytes();
                b.push(0);
                Some(b.into_boxed_slice())
            }
            _ => None,
        })
        .as_deref()
    }

    #[cfg(target_arch = "x86")]
    pub fn emit(tag: &[u8], path_ptr: *const std::ffi::c_char, flags: i32, ret: i32) {
        let Some(file) = trace_path() else { return };
        
        let mut tv = [0i32; 2];
        unsafe { sys::syscall2(78, tv.as_mut_ptr() as usize, 0) };
        let pid = unsafe { sys::syscall2(20, 0, 0) } as u32;
        let pbytes: &[u8] = if path_ptr.is_null() {
            b"(null)"
        } else {
            unsafe { std::ffi::CStr::from_ptr(path_ptr) }.to_bytes()
        };
        
        let mut line = [0u8; 512];

        use std::io::Write;
        let mut w = &mut line[..];
        let _ = write!(w, "{}.{:06} {} {} fl=0x{:x} r={} ", 
            tv[0], tv[1], pid, std::str::from_utf8(tag).unwrap_or("?"), flags, ret);
        let _ = w.write_all(pbytes);
        let _ = w.write_all(b"\n");
        let mut n = 512 - w.len();
        if n == 512 {
            line[511] = b'\n';
        } else if n > 0 && line[n - 1] != b'\n' {
            line[n] = b'\n';
            n += 1;
        }

        let fd = unsafe { sys::syscall3(5, file.as_ptr() as usize, 1089, 0o644) };
        if fd >= 0 {
            unsafe { sys::syscall3(4, fd as usize, line.as_ptr() as usize, n) };
            unsafe { sys::syscall2(6, fd as usize, 0) };
        }
    }

    #[cfg(not(target_arch = "x86"))]
    pub fn emit(_tag: &[u8], _path: *const std::ffi::c_char, _flags: i32, _ret: i32) {}
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

/// # Safety
/// `path` must be NULL or a valid C string pointer
#[cfg(any(target_arch = "x86", test))]
unsafe fn sanitize_dev_shm_path(
    path: *const c_char,
    buf: &mut [u8; DEV_SHM_PREFIX_LEN + SHM_NAME_MAX + 1],
) -> *const c_char {
    if path.is_null() { return path; }

    let bytes = unsafe { CStr::from_ptr(path) }.to_bytes();
    let Some(name) = bytes.strip_prefix(DEV_SHM_PREFIX) else { return path; };

    if name.len() > SHM_NAME_MAX - 1 || !name.contains(&b'/') {
        return path;
    }

    buf[..bytes.len()].copy_from_slice(bytes);
    buf[bytes.len()] = 0;

    buf[DEV_SHM_PREFIX_LEN..bytes.len()]
        .iter_mut()
        .filter(|b| **b == b'/')
        .for_each(|b| *b = b'_');

    buf.as_ptr() as *const c_char
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn shm_open(name: *const c_char, oflag: c_int, mode: u32) -> c_int {
    type FnPtr = unsafe extern "C" fn(*const c_char, c_int, u32) -> c_int;
    let Some(real_fn) = dlsym_next!(c"shm_open", FnPtr) else { return set_errno(ENOSYS); };
    
    let mut buf =[0u8; SHM_NAME_MAX + 1];
    
    let patched = unsafe { sanitize_on_stack(name, &mut buf) };
    let r = unsafe { real_fn(patched, oflag, mode) };
    trace::emit(b"shm_open", patched, oflag, r);
    r
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn shm_unlink(name: *const c_char) -> c_int {
    type FnPtr = unsafe extern "C" fn(*const c_char) -> c_int;
    let Some(real_fn) = dlsym_next!(c"shm_unlink", FnPtr) else { return set_errno(ENOSYS); };
    
    let mut buf =[0u8; SHM_NAME_MAX + 1];
    
    let patched = unsafe { sanitize_on_stack(name, &mut buf) };
    let r = unsafe { real_fn(patched) };
    trace::emit(b"shm_unlink", patched, 0, r);
    r
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
                    let mut pbuf = [0u8; DEV_SHM_PREFIX_LEN + SHM_NAME_MAX + 1];
                    let patched_path = unsafe { sanitize_dev_shm_path(path, &mut pbuf) };
                    
                    let ret = unsafe { sys::syscall2(sys::$sys, patched_path as usize, buf as usize) };
                    trace::emit(b"stat", patched_path, 0, ret);
                    return sys::set_errno_from_ret(ret);
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
        
        let bytes = unsafe { CStr::from_ptr(path) }.to_bytes();
        if is_dev_shm_path(bytes) {
            return 0;
        }

        let ret = unsafe { sys::syscall2(sys::MKDIR, path as usize, mode as usize) };
        if ret == -(sys::EEXIST as i32) {
            return 0;
        }
        sys::set_errno_from_ret(ret)
    }
}

#[cfg(target_arch = "x86")]
mod path_hooks {
    use super::*;
    use std::sync::atomic::{AtomicPtr, Ordering};

    #[inline]
    unsafe fn resolve(slot: &AtomicPtr<c_void>, sym: *const c_char) -> *mut c_void {
        let cached = slot.load(Ordering::Relaxed);
        if !cached.is_null() { return cached; }
        let r = unsafe { dlsym(RTLD_NEXT, sym) };
        slot.store(r, Ordering::Relaxed);
        r
    }

    #[inline]
    unsafe fn patch(path: *const c_char, buf: &mut [u8; DEV_SHM_PREFIX_LEN + SHM_NAME_MAX + 1]) -> *const c_char {
        if path.is_null() { path } else { unsafe { sanitize_dev_shm_path(path, buf) } }
    }

    macro_rules! impl_open_hook {
        ($name:ident, $sym:literal $(, $dirfd:ident)?) => {
            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn $name($($dirfd: c_int,)? path: *const c_char, flags: c_int, mode: c_uint) -> c_int {
                type Fn = unsafe extern "C" fn($($dirfd: c_int,)? *const c_char, c_int, c_uint) -> c_int;
                static REAL: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
                let ptr = unsafe { resolve(&REAL, $sym.as_ptr()) };
                if ptr.is_null() { return set_errno(ENOSYS); }
                
                let mut buf = [0u8; DEV_SHM_PREFIX_LEN + SHM_NAME_MAX + 1];
                let p = unsafe { patch(path, &mut buf) };
                let m = if open_needs_mode(flags) { mode } else { 0 };
                unsafe { std::mem::transmute::<_, Fn>(ptr)($($dirfd,)? p, flags, m) }
            }
        };
    }

    impl_open_hook!(open, c"open");
    impl_open_hook!(open64, c"open64");
    impl_open_hook!(openat, c"openat", dirfd);
    impl_open_hook!(openat64, c"openat64", dirfd);

    macro_rules! path_int_hook {
        ($name:ident, $sym:literal, ($($an:ident: $at:ty),*)) => {
            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn $name(path: *const c_char $(, $an: $at)*) -> c_int {
                type Fn = unsafe extern "C" fn(*const c_char $(, $at)*) -> c_int;
                static REAL: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
                let ptr = unsafe { resolve(&REAL, $sym.as_ptr()) };
                if ptr.is_null() { return set_errno(ENOSYS); }
                
                let mut buf = [0u8; DEV_SHM_PREFIX_LEN + SHM_NAME_MAX + 1];
                let p = unsafe { patch(path, &mut buf) };
                unsafe { std::mem::transmute::<_, Fn>(ptr)(p $(, $an)*) }
            }
        };
    }

    path_int_hook!(access, c"access", (mode: c_int));
    path_int_hook!(euidaccess, c"euidaccess", (mode: c_int));
    path_int_hook!(eaccess, c"eaccess", (mode: c_int));
    path_int_hook!(unlink, c"unlink", ());
    path_int_hook!(truncate, c"truncate", (length: c_long));
    path_int_hook!(truncate64, c"truncate64", (length: i64));
    path_int_hook!(creat, c"creat", (mode: c_uint));
    path_int_hook!(creat64, c"creat64", (mode: c_uint));
    path_int_hook!(__open_2, c"__open_2", (oflag: c_int));
    path_int_hook!(__open64_2, c"__open64_2", (oflag: c_int));

    macro_rules! fd_path_int_hook {
        ($name:ident, $sym:literal, ($($an:ident: $at:ty),*)) => {
            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn $name(dirfd: c_int, path: *const c_char $(, $an: $at)*) -> c_int {
                type Fn = unsafe extern "C" fn(c_int, *const c_char $(, $at)*) -> c_int;
                static REAL: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
                let ptr = unsafe { resolve(&REAL, $sym.as_ptr()) };
                if ptr.is_null() { return set_errno(ENOSYS); }
                
                let mut buf = [0u8; DEV_SHM_PREFIX_LEN + SHM_NAME_MAX + 1];
                let p = unsafe { patch(path, &mut buf) };
                unsafe { std::mem::transmute::<_, Fn>(ptr)(dirfd, p $(, $an)*) }
            }
        };
    }

    fd_path_int_hook!(faccessat, c"faccessat", (mode: c_int, flags: c_int));
    fd_path_int_hook!(unlinkat, c"unlinkat", (flags: c_int));
    fd_path_int_hook!(__openat_2, c"__openat_2", (oflag: c_int));
    fd_path_int_hook!(__openat64_2, c"__openat64_2", (oflag: c_int));

    macro_rules! path_ptr_hook {
        ($name:ident, $sym:literal, ($($an:ident: $at:ty),*)) => {
            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn $name(path: *const c_char $(, $an: $at)*) -> *mut c_void {
                type Fn = unsafe extern "C" fn(*const c_char $(, $at)*) -> *mut c_void;
                static REAL: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
                let ptr = unsafe { resolve(&REAL, $sym.as_ptr()) };
                if ptr.is_null() {
                    set_errno(ENOSYS);
                    return std::ptr::null_mut();
                }
                
                let mut buf = [0u8; DEV_SHM_PREFIX_LEN + SHM_NAME_MAX + 1];
                let p = unsafe { patch(path, &mut buf) };
                unsafe { std::mem::transmute::<_, Fn>(ptr)(p $(, $an)*) }
            }
        };
    }

    path_ptr_hook!(fopen, c"fopen", (mode: *const c_char));
    path_ptr_hook!(fopen64, c"fopen64", (mode: *const c_char));
    path_ptr_hook!(opendir, c"opendir", ());

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn statx(dirfd: c_int, path: *const c_char, flags: c_int, mask: c_uint, stat_buf: *mut c_void) -> c_int {
        type Fn = unsafe extern "C" fn(c_int, *const c_char, c_int, c_uint, *mut c_void) -> c_int;
        static REAL: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
        let ptr = unsafe { resolve(&REAL, c"statx".as_ptr()) };
        if ptr.is_null() { return set_errno(ENOSYS); }
        
        let mut buf = [0u8; DEV_SHM_PREFIX_LEN + SHM_NAME_MAX + 1];
        let p = unsafe { patch(path, &mut buf) };
        unsafe { std::mem::transmute::<_, Fn>(ptr)(dirfd, p, flags, mask, stat_buf) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn mkdirat(dirfd: c_int, path: *const c_char, mode: c_uint) -> c_int {
        if path.is_null() { return set_errno(sys::EFAULT); }
        let bytes = unsafe { CStr::from_ptr(path) }.to_bytes();
        if is_dev_shm_path(bytes) { return 0; }
        
        type Fn = unsafe extern "C" fn(c_int, *const c_char, c_uint) -> c_int;
        static REAL: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
        let ptr = unsafe { resolve(&REAL, c"mkdirat".as_ptr()) };
        if ptr.is_null() { return set_errno(ENOSYS); }
        unsafe { std::mem::transmute::<_, Fn>(ptr)(dirfd, path, mode) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn rename(old: *const c_char, new: *const c_char) -> c_int {
        type Fn = unsafe extern "C" fn(*const c_char, *const c_char) -> c_int;
        static REAL: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
        let ptr = unsafe { resolve(&REAL, c"rename".as_ptr()) };
        if ptr.is_null() { return set_errno(ENOSYS); }
        
        let mut ob = [0u8; DEV_SHM_PREFIX_LEN + SHM_NAME_MAX + 1];
        let mut nb = [0u8; DEV_SHM_PREFIX_LEN + SHM_NAME_MAX + 1];
        let op = unsafe { patch(old, &mut ob) };
        let np = unsafe { patch(new, &mut nb) };
        unsafe { std::mem::transmute::<_, Fn>(ptr)(op, np) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn renameat(olddirfd: c_int, old: *const c_char, newdirfd: c_int, new: *const c_char) -> c_int {
        type Fn = unsafe extern "C" fn(c_int, *const c_char, c_int, *const c_char) -> c_int;
        static REAL: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
        let ptr = unsafe { resolve(&REAL, c"renameat".as_ptr()) };
        if ptr.is_null() { return set_errno(ENOSYS); }
        
        let mut ob = [0u8; DEV_SHM_PREFIX_LEN + SHM_NAME_MAX + 1];
        let mut nb = [0u8; DEV_SHM_PREFIX_LEN + SHM_NAME_MAX + 1];
        let op = unsafe { patch(old, &mut ob) };
        let np = unsafe { patch(new, &mut nb) };
        unsafe { std::mem::transmute::<_, Fn>(ptr)(olddirfd, op, newdirfd, np) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn renameat2(olddirfd: c_int, old: *const c_char, newdirfd: c_int, new: *const c_char, flags: c_uint) -> c_int {
        type Fn = unsafe extern "C" fn(c_int, *const c_char, c_int, *const c_char, c_uint) -> c_int;
        static REAL: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
        let ptr = unsafe { resolve(&REAL, c"renameat2".as_ptr()) };
        if ptr.is_null() { return set_errno(ENOSYS); }
        
        let mut ob = [0u8; DEV_SHM_PREFIX_LEN + SHM_NAME_MAX + 1];
        let mut nb = [0u8; DEV_SHM_PREFIX_LEN + SHM_NAME_MAX + 1];
        let op = unsafe { patch(old, &mut ob) };
        let np = unsafe { patch(new, &mut nb) };
        unsafe { std::mem::transmute::<_, Fn>(ptr)(olddirfd, op, newdirfd, np, flags) }
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

    fn sanitize_path(input: &[u8]) -> Option<Vec<u8>> {
        let c_str = CString::new(input).unwrap();
        let mut buf = [0u8; DEV_SHM_PREFIX_LEN + SHM_NAME_MAX + 1];
        let result = unsafe { sanitize_dev_shm_path(c_str.as_ptr(), &mut buf) };
        if result == c_str.as_ptr() {
            None
        } else {
            let out = unsafe { CStr::from_ptr(result) };
            Some(out.to_bytes().to_vec())
        }
    }

    #[test]
    fn dev_shm_embedded_slash_rewritten() {
        assert_eq!(
            sanitize_path(b"/dev/shm/sec/tss_sdk_bus_1"),
            Some(b"/dev/shm/sec_tss_sdk_bus_1".to_vec())
        );
    }

    #[test]
    fn dev_shm_multiple_slashes_rewritten() {
        assert_eq!(
            sanitize_path(b"/dev/shm/a/b/c"),
            Some(b"/dev/shm/a_b_c".to_vec())
        );
    }

    #[test]
    fn dev_shm_no_embedded_slash_passes_through() {
        assert_eq!(sanitize_path(b"/dev/shm/simple"), None);
    }

    #[test]
    fn non_dev_shm_path_passes_through() {
        assert_eq!(sanitize_path(b"/etc/passwd"), None);
        assert_eq!(sanitize_path(b"/home/neople/secsvr/zergsvr/zergsvr.pid"), None);
        assert_eq!(sanitize_path(b"/home/dxf/secsvr/zergsvr/zergsvr.pid"), None);
    }

    #[test]
    fn dev_shm_empty_suffix_passes_through() {
        assert_eq!(sanitize_path(b"/dev/shm/"), None);
    }

    #[test]
    fn dev_shm_prefix_only_passes_through() {
        assert_eq!(sanitize_path(b"/dev/shm"), None);
    }

    #[test]
    fn dev_shm_exceeds_max_length_passes_through() {
        let mut path = DEV_SHM_PREFIX.to_vec();
        path.push(b'a');
        path.push(b'/');
        path.extend(std::iter::repeat(b'b').take(SHM_NAME_MAX));
        assert!(path.len() - DEV_SHM_PREFIX_LEN > SHM_NAME_MAX);

        assert_eq!(sanitize_path(&path), None);
    }

    #[test]
    fn dev_shm_name_at_max_minus_one_rewritten() {
        let mut path = DEV_SHM_PREFIX.to_vec();
        path.push(b'a');
        path.push(b'/');
        path.extend(std::iter::repeat(b'b').take(SHM_NAME_MAX - 3));
        assert_eq!(path.len() - DEV_SHM_PREFIX_LEN, SHM_NAME_MAX - 1);

        let mut expected = DEV_SHM_PREFIX.to_vec();
        expected.push(b'a');
        expected.push(b'_');
        expected.extend(std::iter::repeat(b'b').take(SHM_NAME_MAX - 3));

        assert_eq!(sanitize_path(&path), Some(expected));
    }

    #[test]
    fn dev_shm_name_at_max_passes_through() {
        let mut path = DEV_SHM_PREFIX.to_vec();
        path.push(b'a');
        path.push(b'/');
        path.extend(std::iter::repeat(b'b').take(SHM_NAME_MAX - 2));
        assert_eq!(path.len() - DEV_SHM_PREFIX_LEN, SHM_NAME_MAX);

        assert_eq!(sanitize_path(&path), None);
    }

     #[test]
    fn dev_shm_multiple_slashes_at_max_minus_one_rewritten() {
        let mut name = vec![b'a', b'/', b'b', b'/', b'c', b'/'];
        name.extend(std::iter::repeat(b'd').take(SHM_NAME_MAX - 1 - name.len()));
        assert_eq!(name.len(), SHM_NAME_MAX - 1);

        let mut path = DEV_SHM_PREFIX.to_vec();
        path.extend_from_slice(&name);

        let mut expected = DEV_SHM_PREFIX.to_vec();
        expected.extend(name.iter().map(|&b| if b == b'/' { b'_' } else { b }));

        assert_eq!(sanitize_path(&path), Some(expected));
    }

    #[test]
    fn open_rdonly_needs_no_mode() {
        assert!(!open_needs_mode(0));
    }

    #[test]
    fn open_creat_needs_mode() {
        assert!(open_needs_mode(O_CREAT));
    }

    #[test]
    fn open_wronly_creat_needs_mode() {
        assert!(open_needs_mode(1 | O_CREAT));
    }

    #[test]
    fn open_tmpfile_needs_mode() {
        assert!(open_needs_mode(O_TMPFILE_BIT | O_DIRECTORY));
    }

    #[test]
    fn open_directory_only_needs_no_mode() {
        assert!(!open_needs_mode(O_DIRECTORY));
    }

    #[test]
    fn dev_shm_dir_is_dev_shm_path() {
        assert!(is_dev_shm_path(b"/dev/shm/sec"));
    }

    #[test]
    fn dev_shm_file_is_dev_shm_path() {
        assert!(is_dev_shm_path(b"/dev/shm/sec/tss_sdk_bus_1"));
    }

    #[test]
    fn non_dev_shm_is_not_dev_shm_path() {
        assert!(!is_dev_shm_path(b"/etc/passwd"));
    }

    #[test]
    fn dev_shm_prefix_only_is_not_dev_shm_path() {
        assert!(!is_dev_shm_path(b"/dev/shm/"));
        assert!(!is_dev_shm_path(b"/dev/shm"));
    }

    #[test]
    fn dev_shm_lookalike_is_not_dev_shm_path() {
        assert!(!is_dev_shm_path(b"/dev/shmfoo"));
    }
}
// Linux ABIs from the vendored Keystone and Unicorn headers.
use std::ffi::{c_char, c_int, c_void};

pub(super) type Handle = *mut c_void;

unsafe extern "C" {
    pub(super) fn ks_open(arch: c_int, mode: c_int, engine: *mut Handle) -> c_int;
    pub(super) fn ks_close(engine: Handle) -> c_int;
    pub(super) fn ks_asm(
        engine: Handle,
        source: *const c_char,
        address: u64,
        bytes: *mut *mut u8,
        size: *mut usize,
        statements: *mut usize,
    ) -> c_int;
    pub(super) fn ks_free(bytes: *mut u8);
    pub(super) fn ks_errno(engine: Handle) -> c_int;
    pub(super) fn ks_strerror(code: c_int) -> *const c_char;

    pub(super) fn uc_open(arch: c_int, mode: c_int, engine: *mut Handle) -> c_int;
    pub(super) fn uc_close(engine: Handle) -> c_int;
    pub(super) fn uc_strerror(code: c_int) -> *const c_char;
    pub(super) fn uc_mem_map(engine: Handle, address: u64, size: u64, perms: u32) -> c_int;
    pub(super) fn uc_mem_write(
        engine: Handle,
        address: u64,
        bytes: *const c_void,
        size: u64,
    ) -> c_int;
    pub(super) fn uc_mem_read(engine: Handle, address: u64, bytes: *mut c_void, size: u64)
    -> c_int;
    pub(super) fn uc_reg_write(engine: Handle, register: c_int, value: *const c_void) -> c_int;
    pub(super) fn uc_reg_read(engine: Handle, register: c_int, value: *mut c_void) -> c_int;
    pub(super) fn uc_emu_start(
        engine: Handle,
        begin: u64,
        end: u64,
        timeout: u64,
        count: usize,
    ) -> c_int;
    pub(super) fn uc_emu_stop(engine: Handle) -> c_int;
    pub(super) fn uc_query(engine: Handle, kind: c_int, value: *mut usize) -> c_int;
    pub(super) fn uc_hook_add(
        engine: Handle,
        hook: *mut usize,
        kind: c_int,
        callback: *mut c_void,
        data: *mut c_void,
        begin: u64,
        end: u64,
        ...
    ) -> c_int;
}

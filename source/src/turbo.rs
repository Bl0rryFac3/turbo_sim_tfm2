use crate::platform::{FlushInstructionCache, GetCurrentProcess, GetModuleHandleW, VirtualProtect};
use mod_api_stable::{StableServerCtx, StableServerExtension};
use std::arch::global_asm;
use std::ffi::c_void;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::ptr;
use std::slice;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

global_asm!(include_str!("draft.s"));

#[no_mangle]
static TFM2_TURBO_ORIGINAL_COPY: AtomicUsize = AtomicUsize::new(0);
#[no_mangle]
static TFM2_TURBO_ORIGINAL_DISPATCH: AtomicUsize = AtomicUsize::new(0);
#[no_mangle]
static TFM2_TURBO_DRAFT_JOBS: AtomicU64 = AtomicU64::new(0);

const COPY_RVA: usize = 0x03f5_14b3;
const DISPATCH_RVA: usize = 0x0272_3ec0;
const FIRST_RELAY_RVA: usize = 0x05a4_0000;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const COMMIT_AND_RESERVE: u32 = 0x3000;
const MEM_RELEASE: u32 = 0x8000;
const CALL_SITES: [(usize, [u8; 5]); 3] = [
    (0x02f5_1968, [0xe8, 0x46, 0xfb, 0xff, 0x00]),
    (0x02f5_5cff, [0xe8, 0xbc, 0xe1, 0x7c, 0xff]),
    (0x02f5_b8c2, [0xe8, 0xf9, 0x85, 0x7c, 0xff]),
];

static STATUS: OnceLock<Result<(), &'static str>> = OnceLock::new();

unsafe extern "C" {
    fn tfm2_faster_days_draft();
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn VirtualAlloc(address: *mut c_void, size: usize, allocation: u32, protection: u32) -> *mut c_void;
    fn VirtualFree(address: *mut c_void, size: usize, free_type: u32) -> i32;
}

struct Relay(*mut c_void);

impl Drop for Relay {
    fn drop(&mut self) {
        unsafe { VirtualFree(self.0, 0, MEM_RELEASE) };
    }
}

struct WritableCode {
    address: *mut c_void,
    old_protection: u32,
}

impl Drop for WritableCode {
    fn drop(&mut self) {
        let mut ignored = 0;
        unsafe {
            VirtualProtect(self.address, 5, self.old_protection, &mut ignored);
        }
    }
}

unsafe fn allocate_relay(image: *mut u8) -> Result<Relay, &'static str> {
    // The game CALL sites use rel32. Search available 64 KiB allocation
    // boundaries outside the image, within easy reach of all three.
    for distance in (FIRST_RELAY_RVA..FIRST_RELAY_RVA + 0x0800_0000).step_by(0x1_0000) {
        let Some(address) = (image as usize).checked_add(distance) else { break };
        let memory = VirtualAlloc(address as *mut c_void, 4096, COMMIT_AND_RESERVE, PAGE_READWRITE);
        if memory.is_null() {
            continue;
        }
        let relay = Relay(memory);
        if memory as usize != address {
            continue;
        }

        // RIP-relative indirect JMP to the DLL's leaf assembly.
        let mut bytes = [0u8; 14];
        bytes[..2].copy_from_slice(&[0xff, 0x25]);
        bytes[6..].copy_from_slice(&(tfm2_faster_days_draft as *const () as usize).to_le_bytes());
        ptr::copy_nonoverlapping(bytes.as_ptr(), memory.cast(), bytes.len());
        let mut old = 0;
        if VirtualProtect(memory, bytes.len(), PAGE_EXECUTE_READ, &mut old) == 0
            || FlushInstructionCache(GetCurrentProcess(), memory, bytes.len()) == 0
        {
            return Err("Windows rejected the executable relay.");
        }
        return Ok(relay);
    }
    Err("No nearby code memory was available.")
}

unsafe fn install() -> Result<(), &'static str> {
    let image = GetModuleHandleW(ptr::null());
    if image.is_null() {
        return Err("The game image could not be located.");
    }
    for (rva, original) in CALL_SITES {
        if slice::from_raw_parts(image.add(rva), original.len()) != original {
            return Err("A draft call site differs from the verified 0.7.4 build.");
        }
    }

    let relay = allocate_relay(image)?;
    let mut replacements = [[0xe8, 0, 0, 0, 0]; CALL_SITES.len()];
    let mut writable = Vec::with_capacity(CALL_SITES.len());
    for (index, (rva, original)) in CALL_SITES.into_iter().enumerate() {
        let address = image.add(rva);
        let delta = (relay.0 as isize) - (address.add(original.len()) as isize);
        let relative = i32::try_from(delta).map_err(|_| "The relay is outside CALL range.")?;
        replacements[index][1..].copy_from_slice(&relative.to_le_bytes());
        let mut old_protection = 0;
        if VirtualProtect(address.cast(), original.len(), PAGE_EXECUTE_READWRITE, &mut old_protection) == 0 {
            return Err("Windows rejected a temporary change to page protection.");
        }
        writable.push(WritableCode { address: address.cast(), old_protection });
    }

    TFM2_TURBO_ORIGINAL_COPY.store(image.add(COPY_RVA) as usize, Ordering::Release);
    TFM2_TURBO_ORIGINAL_DISPATCH.store(image.add(DISPATCH_RVA) as usize, Ordering::Release);
    for (code, replacement) in writable.iter().zip(replacements.iter()) {
        ptr::copy_nonoverlapping(replacement.as_ptr(), code.address.cast(), replacement.len());
    }
    let process = GetCurrentProcess();
    if writable.iter().any(|code| FlushInstructionCache(process, code.address, 5) == 0) {
        for (code, (_, original)) in writable.iter().zip(CALL_SITES) {
            ptr::copy_nonoverlapping(original.as_ptr(), code.address.cast(), original.len());
            FlushInstructionCache(process, code.address, original.len());
        }
        return Err("Windows rejected the instruction cache flush.");
    }
    // Sites are in different pages. Restore every page before returning.
    drop(writable);
    // The patched calls reference this relay until process exit.
    std::mem::forget(relay);
    Ok(())
}

pub(crate) fn configure(executable: &Path) {
    let Some(directory) = executable.parent() else { return };
    let config = directory.join("mods").join(crate::MOD_ID).join("turbo.txt");
    match fs::read_to_string(config) {
        Ok(text) => match text.trim_start_matches('\u{feff}').trim() {
            "off" => {}
            "on" => { STATUS.get_or_init(|| unsafe { install() }); }
            _ => { let _ = STATUS.set(Err("Set turbo.txt to on or off.")); }
        },
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(_) => { let _ = STATUS.set(Err("Could not read turbo.txt.")); }
    }
}

pub(crate) fn status() -> Option<Result<(), &'static str>> {
    STATUS.get().copied()
}

#[derive(Default)]
pub(crate) struct DraftCounter(Mutex<Option<CounterReport>>);

struct CounterReport {
    start_count: u64,
    last_count: u64,
    last_report: Instant,
}

fn counter_path() -> Option<PathBuf> {
    Some(PathBuf::from(std::env::var_os("APPDATA")?)
        .join("TeamSamoyed").join("TeamfightManager2").join("data")
        .join("faster_days_turbo.log"))
}

fn write_count(message: &str) {
    let Some(path) = counter_path() else { return };
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{message}");
    }
}

impl StableServerExtension for DraftCounter {
    fn on_server_start(&self, _ctx: &mut StableServerCtx<'_>) {
        if let Ok(mut start) = self.0.lock() {
            let count = TFM2_TURBO_DRAFT_JOBS.load(Ordering::Relaxed);
            *start = Some(CounterReport {
                start_count: count,
                last_count: count,
                last_report: Instant::now(),
            });
        }
        if let Some(directory) = counter_path().as_deref().and_then(Path::parent) {
            let _ = fs::create_dir_all(directory);
        }
        write_count(concat!("Turbo Sim ", env!("CARGO_PKG_VERSION"), " server started"));
    }

    fn after_management_tick(&self, _ctx: &mut StableServerCtx<'_>) {
        let Ok(mut state) = self.0.lock() else { return };
        let Some(report) = state.as_mut() else { return };
        let count = TFM2_TURBO_DRAFT_JOBS.load(Ordering::Relaxed);
        if count != report.last_count && report.last_report.elapsed() >= Duration::from_secs(5) {
            report.last_count = count;
            report.last_report = Instant::now();
            let since_start = count.saturating_sub(report.start_count);
            write_count(&format!("Fast AI draft jobs since server start={since_start}"));
        }
    }
}

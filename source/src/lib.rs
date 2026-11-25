use mod_api_stable::{declare_stable_mod, GameVersionV1, LogLevel, StableHost, StableMod};

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod turbo;

const MOD_ID: &str = "Turbo_Sim";
const SUPPORTED_VERSION: GameVersionV1 = GameVersionV1 {
    major: 0,
    minor: 7,
    patch: 4,
};

fn init(host: &StableHost) -> StableMod {
    #[allow(unused_mut)]
    let mut module = StableMod::new(MOD_ID);
    if host.game_version() != SUPPORTED_VERSION {
        host.log(LogLevel::Warn, "Turbo Sim requires Teamfight Manager 2 version 0.7.4.");
        return module;
    }
    match platform::apply() {
        Ok(message) => host.log(LogLevel::Info, message),
        Err(reason) => host.log(
            LogLevel::Warn,
            &format!("Turbo Sim left the game unchanged. {reason}"),
        ),
    }
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    if let Some(result) = turbo::status() {
        match result {
            Ok(()) => {
                host.log(LogLevel::Info, "Turbo Sim is active for eligible AI-only drafts in Simple mode.");
                module.set_server_extension(turbo::DraftCounter::default());
            }
            Err(reason) => host.log(LogLevel::Warn, &format!("Turbo Sim kept its original speed mode. Turbo: {reason}")),
        }
    }
    module
}

// Match the ABI level in the SDK's export structure. The mod uses the ABI 10 interface.
declare_stable_mod!(init, requires = mod_api_stable::ABI_LEVEL);

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
mod platform {
    pub fn apply() -> Result<&'static str, &'static str> {
        Err("The patch requires the Windows x64 release.")
    }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod platform {
    use std::ffi::c_void;
    use std::fs;
    use std::io::ErrorKind;
    use std::path::Path;
    use std::ptr;
    use std::slice;
    use std::sync::atomic::{AtomicU16, Ordering};

    const EXECUTABLE_LENGTH: usize = 94_511_104;
    const EXECUTABLE_SHA256: [u8; 32] = [
        0xc7, 0x49, 0x55, 0xe1, 0x1f, 0x48, 0x45, 0xf9, 0x3d, 0xcb, 0x73, 0xf9, 0x0c, 0x5c,
        0xdd, 0x44, 0x26, 0x15, 0xac, 0x72, 0xf4, 0x0e, 0xd6, 0x42, 0xa1, 0xfd, 0xeb, 0x5f,
        0x41, 0xde, 0xf0, 0x1e,
    ];
    const REGION_BRANCH_RVA: usize = 0x02f7_52d8;
    const ORIGINAL_BRANCH: [u8; 6] = [0x0f, 0x84, 0xb8, 0x01, 0x00, 0x00];
    const BRANCH_ORIGINAL_PREFIX: u16 = u16::from_le_bytes([0x0f, 0x84]);
    const BRANCH_PATCHED_PREFIX: u16 = u16::from_le_bytes([0x90, 0xe9]);
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    const SHA256_ALGORITHM: &[u16] = &[
        b'S' as u16, b'H' as u16, b'A' as u16, b'2' as u16, b'5' as u16, b'6' as u16, 0,
    ];

    #[link(name = "kernel32")]
    extern "system" {
        pub(super) fn GetModuleHandleW(name: *const u16) -> *mut u8;
        pub(super) fn GetCurrentProcess() -> *mut c_void;
        pub(super) fn VirtualProtect(address: *mut c_void, len: usize, protection: u32, old: *mut u32) -> i32;
        pub(super) fn FlushInstructionCache(process: *mut c_void, address: *const c_void, len: usize) -> i32;
    }

    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptOpenAlgorithmProvider(
            handle: *mut *mut c_void,
            algorithm: *const u16,
            implementation: *const u16,
            flags: u32,
        ) -> i32;
        fn BCryptHash(
            handle: *mut c_void,
            secret: *const u8,
            secret_len: u32,
            input: *const u8,
            input_len: u32,
            output: *mut u8,
            output_len: u32,
        ) -> i32;
        fn BCryptCloseAlgorithmProvider(handle: *mut c_void, flags: u32) -> i32;
    }

    fn enabled(executable: &Path) -> Result<bool, &'static str> {
        let directory = executable.parent().ok_or("Could not locate the game folder.")?;
        let path = directory.join("mods").join(super::MOD_ID).join("enabled.txt");
        match fs::read_to_string(path) {
            Ok(text) => match text.trim_start_matches('\u{feff}').trim() {
                "on" => Ok(true),
                "off" => Ok(false),
                _ => Err("Set enabled.txt to on or off."),
            },
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(true),
            Err(_) => Err("Could not read enabled.txt."),
        }
    }

    fn verify_executable(path: &Path) -> Result<(), &'static str> {
        let metadata = fs::metadata(path).map_err(|_| "Could not inspect the game executable.")?;
        if metadata.len() != EXECUTABLE_LENGTH as u64 {
            return Err("The executable size differs from the supported 0.7.4 build.");
        }
        let bytes = fs::read(path).map_err(|_| "Could not read the game executable.")?;
        if bytes.len() != EXECUTABLE_LENGTH {
            return Err("The executable changed while it was being checked.");
        }
        let mut provider = ptr::null_mut();
        let mut hash = [0u8; 32];
        // The file has the verified length, which fits in BCryptHash's u32 length.
        unsafe {
            if BCryptOpenAlgorithmProvider(&mut provider, SHA256_ALGORITHM.as_ptr(), ptr::null(), 0) < 0 {
                return Err("Could not open the Windows SHA-256 provider.");
            }
            let status = BCryptHash(
                provider,
                ptr::null(),
                0,
                bytes.as_ptr(),
                bytes.len() as u32,
                hash.as_mut_ptr(),
                hash.len() as u32,
            );
            BCryptCloseAlgorithmProvider(provider, 0);
            if status < 0 {
                return Err("Could not verify the executable SHA-256.");
            }
        }
        if hash != EXECUTABLE_SHA256 {
            return Err("The executable SHA-256 differs from the supported 0.7.4 build.");
        }
        Ok(())
    }

    unsafe fn patch_loaded_image() -> Result<(), &'static str> {
        let image = GetModuleHandleW(ptr::null());
        if image.is_null() {
            return Err("Could not locate the loaded game image.");
        }
        let site = image.add(REGION_BRANCH_RVA);
        if slice::from_raw_parts(site, ORIGINAL_BRANCH.len()) != ORIGINAL_BRANCH {
            return Err("The game instructions differ from the supported build.");
        }
        // The RVA is 2-byte aligned. Keep the same instruction span and destination.
        // Replace JE rel32 with NOP; JMP rel32 once Simple mode has excluded human teams.
        let prefix = AtomicU16::from_ptr(site.cast());
        let address = site.cast::<c_void>();
        let len = ORIGINAL_BRANCH.len();
        let mut old_protection = 0;
        if VirtualProtect(address, len, PAGE_EXECUTE_READWRITE, &mut old_protection) == 0 {
            return Err("Windows rejected the temporary change to code page protection.");
        }
        let changed = prefix
            .compare_exchange(
                BRANCH_ORIGINAL_PREFIX,
                BRANCH_PATCHED_PREFIX,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok();

        let process = GetCurrentProcess();
        let flushed = changed && FlushInstructionCache(process, address, len) != 0;
        if changed && !flushed {
            prefix.store(BRANCH_ORIGINAL_PREFIX, Ordering::SeqCst);
            FlushInstructionCache(process, address, len);
        }

        let mut ignored = 0;
        if VirtualProtect(address, len, old_protection, &mut ignored) == 0 {
            if flushed {
                prefix.store(BRANCH_ORIGINAL_PREFIX, Ordering::SeqCst);
                FlushInstructionCache(process, address, len);
            }
            VirtualProtect(address, len, old_protection, &mut ignored);
            return Err("Windows could not restore the original code page protection.");
        }
        if !changed {
            return Err("The game instructions changed during initialization.");
        }
        if !flushed {
            return Err("Windows rejected the instruction cache flush.");
        }
        Ok(())
    }

    pub fn apply() -> Result<&'static str, &'static str> {
        let executable = std::env::current_exe().map_err(|_| "Could not locate the game executable.")?;
        if !enabled(&executable)? {
            return Ok("Turbo Sim is off (enabled.txt).");
        }
        verify_executable(&executable)?;
        // The game loads code mods during startup. The instruction replacement is in memory only.
        unsafe { patch_loaded_image()? };
        super::turbo::configure(&executable);
        Ok("Turbo Sim is active for eligible AI-only matches in Simple mode.")
    }
}

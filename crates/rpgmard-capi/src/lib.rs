#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::missing_safety_doc)]

use core::{mem, slice};
use rpgmad_lib::{
    ArchiveEntry as InnerArchiveEntry, Decrypter as InnerDecrypter, Engine as InnerEngine, ExtractError,
};

// No allocator or heap types are used anywhere in this crate, so a no_std build needs nothing
// beyond a panic handler - never linked in when the default `std` feature (and with it, `std`'s
// own panic handler) is enabled, to avoid a duplicate lang item.
#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe extern "C" {
        fn abort() -> !;
    }
    unsafe { abort() }
}

/// Target/source RPG Maker engine of an archive.
#[repr(C)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Engine {
    /// RPG Maker XP / VX (`.rgssad` / `.rgss2a`).
    Older = 1,
    /// RPG Maker VX Ace (`.rgss3a`).
    VXAce = 3,
}

impl From<Engine> for InnerEngine {
    fn from(engine: Engine) -> Self {
        match engine {
            Engine::Older => InnerEngine::Older,
            Engine::VXAce => InnerEngine::VXAce,
        }
    }
}

/// Status code returned by every fallible `rpgmard_*` function. `RPGMARD_STATUS_OK` is the only success value.
#[repr(C)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Status {
    Ok = 0,
    InvalidHeader = 1,
    InvalidEngine = 2,
    /// A pointer argument that must not be null (`decrypter`, `data`, `entries`, `out_buffer`) was null.
    NullArgument = 3,
    /// `scratch_len` was smaller than `entries_len * rpgmard_archive_entry_size()`, or `scratch` wasn't
    /// aligned to `rpgmard_archive_entry_align()`.
    ScratchTooSmall = 4,
    /// `out_buffer_len` was smaller than the size returned by `rpgmard_encrypted_buffer_size` for the same
    /// `entries`/`engine`.
    BufferTooSmall = 5,
}

impl From<ExtractError> for Status {
    fn from(error: ExtractError) -> Self {
        match error {
            ExtractError::InvalidHeader(_) => Self::InvalidHeader,
            ExtractError::InvalidEngine(_) => Self::InvalidEngine,
        }
    }
}

/// A single archive entry, as passed to/from the FFI boundary. `path`/`data` point to `path_len`/`data_len`
/// bytes respectively.
#[repr(C)]
pub struct ArchiveEntry {
    pub path: *const u8,
    pub path_len: usize,
    pub data: *const u8,
    pub data_len: usize,
}

/// Opaque `Decrypter` instance. This type carries no heap allocation - it is a fixed-size,
/// fixed-alignment value the caller owns directly. Reserve storage for it (e.g. a local variable,
/// or a buffer sized/aligned per `rpgmard_decrypter_size`/`rpgmard_decrypter_align`) and initialize
/// it with `rpgmard_decrypter_init`; there is no corresponding free function; once you are done
/// with the storage, simply reclaim it (e.g. let it go out of scope).
pub struct Decrypter(InnerDecrypter<'static>);

/// The size, in bytes, of a `Decrypter` instance - the minimum size of the storage passed to
/// `rpgmard_decrypter_init`.
#[no_mangle]
pub extern "C" fn rpgmard_decrypter_size() -> usize {
    mem::size_of::<Decrypter>()
}

/// The required alignment, in bytes, of the storage passed to `rpgmard_decrypter_init`.
#[no_mangle]
pub extern "C" fn rpgmard_decrypter_align() -> usize {
    mem::align_of::<Decrypter>()
}

/// Initializes a `Decrypter` into caller-provided storage. `out` must point to at least
/// `rpgmard_decrypter_size()` writable bytes, aligned to `rpgmard_decrypter_align()`.
///
/// Returns `RPGMARD_STATUS_OK` on success, or `RPGMARD_STATUS_NULL_ARGUMENT` if `out` is null.
#[no_mangle]
pub unsafe extern "C" fn rpgmard_decrypter_init(out: *mut Decrypter) -> Status {
    if out.is_null() {
        return Status::NullArgument;
    }

    // SAFETY: caller guarantees `out` points to writable storage of at least `rpgmard_decrypter_size()`
    // bytes, aligned to `rpgmard_decrypter_align()`.
    unsafe { out.write(Decrypter(InnerDecrypter::new())) };

    Status::Ok
}

/// Parses `data`'s archive header and resets `decrypter`'s decryption state, without producing any entries
/// yet. Call `rpgmard_decrypter_next_entry` repeatedly afterwards to pull entries one at a time.
///
/// `data` is modified in-place by the decryption process, and must stay alive and exclusively accessible for
/// as long as `decrypter` is used afterwards (until the next `rpgmard_decrypter_start` call, or `decrypter`'s
/// storage is reclaimed).
///
/// Returns `RPGMARD_STATUS_OK` on success, or an error status if `data` has an invalid header or engine byte.
#[no_mangle]
pub unsafe extern "C" fn rpgmard_decrypter_start(decrypter: *mut Decrypter, data: *mut u8, data_len: usize) -> Status {
    if decrypter.is_null() || data.is_null() {
        return Status::NullArgument;
    }

    // SAFETY: caller guarantees `data` points to `data_len` readable and writable, initialized bytes, and
    // that it stays alive and exclusively accessible for as long as `decrypter` is used afterwards.
    let data = unsafe { slice::from_raw_parts_mut(data, data_len) };
    // SAFETY: `Decrypter`'s inner lifetime is an FFI-erased stand-in for `data`'s actual lifetime, which the
    // caller guarantees per this function's documented contract.
    let data: &'static mut [u8] = unsafe { mem::transmute(data) };

    // SAFETY: caller guarantees `decrypter` points to a live `Decrypter` from `rpgmard_decrypter_init`.
    match unsafe { &mut *decrypter }.0.start(data) {
        Ok(()) => Status::Ok,
        Err(error) => error.into(),
    }
}

/// Pulls the next decrypted entry out of `decrypter` into `*out_entry`.
///
/// Returns `true` and writes the entry if one was available, `false` (leaving `*out_entry` untouched) once
/// the archive is exhausted. `out_entry`'s `path`/`data` point into the buffer passed to the preceding
/// `rpgmard_decrypter_start` call, and are valid for as long as that buffer is.
#[no_mangle]
pub unsafe extern "C" fn rpgmard_decrypter_next_entry(decrypter: *mut Decrypter, out_entry: *mut ArchiveEntry) -> bool {
    if decrypter.is_null() || out_entry.is_null() {
        return false;
    }

    // SAFETY: caller guarantees `decrypter` points to a live `Decrypter` that had `rpgmard_decrypter_start`
    // called on it.
    let Some(entry) = unsafe { &mut *decrypter }.0.next_entry() else {
        return false;
    };

    // SAFETY: caller guarantees `out_entry` points to a writable `ArchiveEntry`.
    unsafe {
        out_entry.write(ArchiveEntry {
            path: entry.path.as_ptr(),
            path_len: entry.path.len(),
            data: entry.data.as_ptr(),
            data_len: entry.data.len(),
        });
    }

    true
}

/// The size, in bytes, of a single scratch slot used by `rpgmard_encrypted_buffer_size`/`rpgmard_encrypt` to
/// stage archive entries for the underlying library call. Multiply by `entries_len` to size the `scratch`
/// buffer passed to those functions.
#[no_mangle]
pub extern "C" fn rpgmard_archive_entry_size() -> usize {
    mem::size_of::<InnerArchiveEntry>()
}

/// The required alignment, in bytes, of the `scratch` buffer passed to `rpgmard_encrypted_buffer_size`/
/// `rpgmard_encrypt`.
#[no_mangle]
pub extern "C" fn rpgmard_archive_entry_align() -> usize {
    mem::align_of::<InnerArchiveEntry>()
}

/// Builds a `&[InnerArchiveEntry]` view over caller-provided `scratch` storage, referencing the caller's own
/// `path`/`data` buffers (no copying). Returns `None` if `scratch` is too small or misaligned.
///
/// # Safety
/// `entries` must point to `entries_len` readable, initialized `ArchiveEntry` values, each of whose
/// `path`/`data` pointers must be valid for their respective `path_len`/`data_len` for lifetime `'a`.
/// `scratch` must point to `scratch_len` writable bytes, valid for lifetime `'a`.
unsafe fn build_entries<'a>(
    entries: *const ArchiveEntry,
    entries_len: usize,
    scratch: *mut u8,
    scratch_len: usize,
) -> Option<&'a [InnerArchiveEntry<'a>]> {
    let required_len = entries_len * mem::size_of::<InnerArchiveEntry>();

    if scratch.is_null()
        || scratch_len < required_len
        || (scratch as usize) % mem::align_of::<InnerArchiveEntry>() != 0
    {
        return None;
    }

    // SAFETY: caller guarantees `entries` points to `entries_len` readable, initialized `ArchiveEntry`
    // values.
    let raw_entries = unsafe { slice::from_raw_parts(entries, entries_len) };
    let scratch = scratch.cast::<InnerArchiveEntry>();

    for (index, entry) in raw_entries.iter().enumerate() {
        let inner_entry = InnerArchiveEntry {
            // SAFETY: caller guarantees `path`/`data` are valid for `path_len`/`data_len`.
            path: unsafe { slice::from_raw_parts(entry.path, entry.path_len) },
            data: unsafe { slice::from_raw_parts(entry.data, entry.data_len) },
        };

        // SAFETY: `index < entries_len` and we just checked `scratch` has room for `entries_len` slots,
        // aligned to `InnerArchiveEntry`.
        unsafe { scratch.add(index).write(inner_entry) };
    }

    // SAFETY: the loop above initialized all `entries_len` slots.
    Some(unsafe { slice::from_raw_parts(scratch.cast_const(), entries_len) })
}

/// Returns the size, in bytes, of the encrypted archive buffer that `rpgmard_encrypt` would produce for
/// `entries`/`engine`. Use this to size the buffer passed to `rpgmard_encrypt`.
///
/// `scratch` must point to at least `entries_len * rpgmard_archive_entry_size()` bytes, aligned to
/// `rpgmard_archive_entry_align()`; it's used only for the duration of this call.
///
/// Returns 0 if `entries` is null or `scratch` is too small/misaligned.
#[no_mangle]
pub unsafe extern "C" fn rpgmard_encrypted_buffer_size(
    entries: *const ArchiveEntry,
    entries_len: usize,
    engine: Engine,
    scratch: *mut u8,
    scratch_len: usize,
) -> usize {
    if entries.is_null() {
        return 0;
    }

    // SAFETY: caller guarantees `entries`/`scratch` uphold `build_entries`'s safety contract for the
    // duration of this call.
    let Some(inner_entries) = (unsafe { build_entries(entries, entries_len, scratch, scratch_len) }) else {
        return 0;
    };

    InnerDecrypter::encrypted_buffer_size(inner_entries, engine.into())
}

/// Writes an encrypted archive built from `entries` into `out_buffer`.
///
/// `scratch` must point to at least `entries_len * rpgmard_archive_entry_size()` bytes, aligned to
/// `rpgmard_archive_entry_align()`; it's used only for the duration of this call.
///
/// `out_buffer_len` must be at least the size returned by `rpgmard_encrypted_buffer_size` for the same
/// `entries`/`engine`, or the call fails with `RPGMARD_STATUS_BUFFER_TOO_SMALL`.
#[no_mangle]
pub unsafe extern "C" fn rpgmard_encrypt(
    entries: *const ArchiveEntry,
    entries_len: usize,
    engine: Engine,
    scratch: *mut u8,
    scratch_len: usize,
    out_buffer: *mut u8,
    out_buffer_len: usize,
) -> Status {
    if entries.is_null() || out_buffer.is_null() {
        return Status::NullArgument;
    }

    // SAFETY: caller guarantees `entries`/`scratch` uphold `build_entries`'s safety contract for the
    // duration of this call.
    let Some(inner_entries) = (unsafe { build_entries(entries, entries_len, scratch, scratch_len) }) else {
        return Status::ScratchTooSmall;
    };

    let required_len = InnerDecrypter::encrypted_buffer_size(inner_entries, engine.into());
    if out_buffer_len < required_len {
        return Status::BufferTooSmall;
    }

    // SAFETY: caller guarantees `out_buffer` points to at least `out_buffer_len` writable bytes, which we
    // just checked is at least `required_len`.
    let out_buffer = unsafe { slice::from_raw_parts_mut(out_buffer, required_len) };

    let _ = InnerDecrypter::new().encrypt(inner_entries, engine.into(), out_buffer);

    Status::Ok
}

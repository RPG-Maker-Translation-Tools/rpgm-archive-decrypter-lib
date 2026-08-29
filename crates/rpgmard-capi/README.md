# rpgmard-capi

C bindings for [`rpgmad-lib`](https://github.com/RPG-Maker-Translation-Tools/rpgm-archive-decrypter-lib). Installable via [`cargo-c`](https://github.com/lu-zero/cargo-c). Produces a shared/static library (`librpgmard`), a C header (`rpgmard.h`), and a `pkg-config` file.

## Building / installing

```bash
cd crates/rpgmard-capi
cargo install cargo-c # or cargo binstall cargo-c
cargo cbuild --release
cargo cinstall --release --prefix=/usr/local
```

## API

This crate never allocates, on either side of the boundary.

The reference `Decrypter::decrypt` returns an iterator borrowing its input buffer, which doesn't translate across an FFI call (each call only lives for its own duration). `rpgmard-capi` exposes the library's pull-based `Decrypter::next_entry` instead: initialize a `Decrypter`, `start` it on the archive data, then pull entries one at a time.

```c
#include <rpgmard/rpgmard.h>

RpgmardDecrypter decrypter;
rpgmard_decrypter_init(&decrypter);

RpgmardStatus status = rpgmard_decrypter_start(&decrypter, archive_data, archive_data_len);
if (status != RPGMARD_STATUS_OK) {
    // handle error
}

RpgmardArchiveEntry entry;
while (rpgmard_decrypter_next_entry(&decrypter, &entry)) {
    // entry.path / entry.data point into archive_data
}
```

Every fallible function returns an `RpgmardStatus` (`RPGMARD_STATUS_OK` on success).

Encrypting mirrors `Decrypter::encrypted_buffer_size`/`Decrypter::encrypt`. The underlying library takes a `&[ArchiveEntry]` slice, which this crate has no allocator to build on the caller's behalf - so you provide the staging storage yourself as a `scratch` buffer, sized with `rpgmard_archive_entry_size()`/`rpgmard_archive_entry_align()` (a fixed-size, fixed-alignment slot per entry). `scratch` is only read/written for the duration of each call; a stack buffer (e.g. a C99 VLA) works fine.

```c
RpgmardArchiveEntry entries[] = {
    { .path = path, .path_len = path_len, .data = data, .data_len = data_len },
};
size_t entries_len = 1;

uint8_t scratch[entries_len * rpgmard_archive_entry_size()]
    __attribute__((aligned(16))); /* or however your compiler spells rpgmard_archive_entry_align() */

size_t buffer_len = rpgmard_encrypted_buffer_size(entries, entries_len, RPGMARD_ENGINE_VXACE, scratch, sizeof(scratch));
uint8_t* buffer = malloc(buffer_len);

RpgmardStatus status =
    rpgmard_encrypt(entries, entries_len, RPGMARD_ENGINE_VXACE, scratch, sizeof(scratch), buffer, buffer_len);
```

The header (`assets/rpgmard.h`) is hand-written. See [`src/lib.rs`](src/lib.rs) for the same surface with full documentation.

## `no_std`

Because this crate never allocates, disabling its default `std` feature is enough for a `no_std` build:

```bash
cargo build --release --no-default-features -p rpgmard-capi
```

With `std` off there is no other Rust code around to supply a panic handler, so the crate provides a minimal abort-on-panic one itself, gated `#[cfg(not(feature = "std"))]` to avoid a duplicate lang item when `std` (and its own panic handler) is linked in.

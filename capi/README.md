# rpgmard-capi

C bindings for `rpgmad-lib`.

## Install

```bash
cargo install cargo-c
cargo cinstall --release --prefix=/usr/local
```

Installs `librpgmard` (shared and static), `rpgmard/rpgmard.h` and a `pkg-config` file. The header documents every function.

## Usage

The library never allocates, on either side of the boundary. Every fallible function returns an `RpgmardStatus` (`RPGMARD_STATUS_OK` on success).

Decrypting: initialize a `RpgmardDecrypter`, `start` it on the archive data, then pull entries one at a time. Entry paths and data point into the archive buffer.

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

Encrypting needs staging storage for the entries, which the library has no allocator to provide: pass a `scratch` buffer of `entries_len * rpgmard_archive_entry_size()` bytes, aligned to `rpgmard_archive_entry_align()`. It is only used for the duration of each call.

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

## `no_std`

Because the library never allocates, `--no-default-features` is all a `no_std` build needs:

```bash
cargo build --release --no-default-features -p rpgmard-capi
```

#ifndef RPGMARD_H
#define RPGMARD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Target/source RPG Maker engine of an archive. */
typedef enum RpgmardEngine {
    /* RPG Maker XP / VX (.rgssad / .rgss2a). */
    RPGMARD_ENGINE_OLDER = 1,
    /* RPG Maker VX Ace (.rgss3a). */
    RPGMARD_ENGINE_VXACE = 3,
} RpgmardEngine;

/* Status code returned by every fallible rpgmard_* function.
 * RPGMARD_STATUS_OK is the only success value. */
typedef enum RpgmardStatus {
    RPGMARD_STATUS_OK = 0,
    RPGMARD_STATUS_INVALID_HEADER = 1,
    RPGMARD_STATUS_INVALID_ENGINE = 2,
    /* A pointer argument that must not be null (decrypter, data, entries,
     * out_buffer) was null. */
    RPGMARD_STATUS_NULL_ARGUMENT = 3,
    /* scratch_len was smaller than entries_len *
     * rpgmard_archive_entry_size(), or scratch wasn't aligned to
     * rpgmard_archive_entry_align(). */
    RPGMARD_STATUS_SCRATCH_TOO_SMALL = 4,
    /* out_buffer_len was smaller than the size returned by
     * rpgmard_encrypted_buffer_size for the same entries/engine. */
    RPGMARD_STATUS_BUFFER_TOO_SMALL = 5,
} RpgmardStatus;

/* A single archive entry, as passed to/from the FFI boundary. `path`/`data`
 * point to `path_len`/`data_len` bytes respectively. */
typedef struct RpgmardArchiveEntry {
    const uint8_t* path;
    size_t path_len;
    const uint8_t* data;
    size_t data_len;
} RpgmardArchiveEntry;

/* Opaque Decrypter instance. Carries no heap allocation - it is a
 * fixed-size, fixed-alignment value the caller owns directly. Reserve
 * storage for it (e.g. a local variable, or a buffer sized/aligned per
 * rpgmard_decrypter_size/rpgmard_decrypter_align) and initialize it with
 * rpgmard_decrypter_init. There is no corresponding free function - once
 * you are done with the storage, simply reclaim it. */
typedef struct RpgmardDecrypter RpgmardDecrypter;

/* The size, in bytes, of a RpgmardDecrypter instance - the minimum size of
 * the storage passed to rpgmard_decrypter_init. */
size_t rpgmard_decrypter_size(void);

/* The required alignment, in bytes, of the storage passed to
 * rpgmard_decrypter_init. */
size_t rpgmard_decrypter_align(void);

/* Initializes a RpgmardDecrypter into caller-provided storage. `out` must
 * point to at least rpgmard_decrypter_size() writable bytes, aligned to
 * rpgmard_decrypter_align(). */
RpgmardStatus rpgmard_decrypter_init(RpgmardDecrypter* out);

/* Parses `data`'s archive header and resets `decrypter`'s decryption state,
 * without producing any entries yet. Call rpgmard_decrypter_next_entry
 * repeatedly afterwards to pull entries one at a time.
 *
 * `data` is modified in-place by the decryption process, and must stay
 * alive and exclusively accessible for as long as `decrypter` is used
 * afterwards (until the next rpgmard_decrypter_start call, or `decrypter`'s
 * storage is reclaimed). */
RpgmardStatus rpgmard_decrypter_start(RpgmardDecrypter* decrypter, uint8_t* data, size_t data_len);

/* Pulls the next decrypted entry out of `decrypter` into `*out_entry`.
 *
 * Returns true and writes the entry if one was available, false (leaving
 * `*out_entry` untouched) once the archive is exhausted. `out_entry`'s
 * `path`/`data` point into the buffer passed to the preceding
 * rpgmard_decrypter_start call, and are valid for as long as that buffer
 * is. */
bool rpgmard_decrypter_next_entry(RpgmardDecrypter* decrypter, RpgmardArchiveEntry* out_entry);

/* The size, in bytes, of a single scratch slot used by
 * rpgmard_encrypted_buffer_size/rpgmard_encrypt to stage archive entries for
 * the underlying library call. Multiply by entries_len to size the
 * `scratch` buffer passed to those functions. */
size_t rpgmard_archive_entry_size(void);

/* The required alignment, in bytes, of the `scratch` buffer passed to
 * rpgmard_encrypted_buffer_size/rpgmard_encrypt. */
size_t rpgmard_archive_entry_align(void);

/* Returns the size, in bytes, of the encrypted archive buffer that
 * rpgmard_encrypt would produce for `entries`/`engine`. Use this to size the
 * buffer passed to rpgmard_encrypt.
 *
 * `scratch` must point to at least entries_len * rpgmard_archive_entry_size()
 * bytes, aligned to rpgmard_archive_entry_align(); it's used only for the
 * duration of this call.
 *
 * Returns 0 if `entries` is null or `scratch` is too small/misaligned. */
size_t rpgmard_encrypted_buffer_size(
    const RpgmardArchiveEntry* entries,
    size_t entries_len,
    RpgmardEngine engine,
    void* scratch,
    size_t scratch_len
);

/* Writes an encrypted archive built from `entries` into `out_buffer`.
 *
 * `scratch` must point to at least entries_len * rpgmard_archive_entry_size()
 * bytes, aligned to rpgmard_archive_entry_align(); it's used only for the
 * duration of this call.
 *
 * `out_buffer_len` must be at least the size returned by
 * rpgmard_encrypted_buffer_size for the same entries/engine, or the call
 * fails with RPGMARD_STATUS_BUFFER_TOO_SMALL. */
RpgmardStatus rpgmard_encrypt(
    const RpgmardArchiveEntry* entries,
    size_t entries_len,
    RpgmardEngine engine,
    void* scratch,
    size_t scratch_len,
    uint8_t* out_buffer,
    size_t out_buffer_len
);

#ifdef __cplusplus
}
#endif

#endif /* RPGMARD_H */

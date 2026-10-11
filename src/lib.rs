#![cfg_attr(not(feature = "std"), no_std)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::cast_possible_truncation)]
#![doc = include_str!("../README.md")]

use core::{
    default::Default,
    iter::{self, Iterator},
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumIs};
use thiserror::Error;

fn memcpy(dst: &mut [u8], src: &[u8]) {
    unsafe {
        core::ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), src.len());
    }
}

macro_rules! sizeof {
    ($t:ty) => {{ core::mem::size_of::<$t>() }};
}

const ARCHIVE_HEADER: &[u8; 7] = b"RGSSAD\0";

const OLDER_DECRYPTION_KEY: u32 = 0xDEAD_CAFE;
const ENCRYPTION_KEY: u32 = 0;

pub const XP_RGSSAD_EXT: &str = "rgssad";
pub const VX_RGSS2A_EXT: &str = "rgss2a";
pub const VXACE_RGSS3A_EXT: &str = "rgss3a";

#[derive(Debug, Error)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub enum ExtractError {
    #[error("Invalid archive file header: {0:?}. Expected: RGSSAD␀ ([82, 71, 83, 83, 65, 68, 0])")]
    InvalidHeader([u8; 7]),
    #[error("Invalid game engine byte: {0}. Expected `1` for XP/VX or `3` for VX Ace.")]
    InvalidEngine(u8),
    #[error("Archive ends unexpectedly.")]
    Truncated,
    #[error("Archive entries overlap or precede the entry table.")]
    Corrupt,
}

#[derive(Debug, Error)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub enum EncryptError {
    #[error("Archive would exceed 4 GiB, which the format can't represent.")]
    TooLarge,
    #[error("Archive buffer is smaller than the size `encrypted_buffer_size` returns.")]
    BufferTooSmall,
}

#[derive(Clone, Copy, Debug, Display, EnumIs, Eq, PartialEq)]
pub enum Engine {
    #[strum(to_string = "XP/VX")]
    Older = 1,
    #[strum(to_string = "VXAce")]
    VXAce = 3,
}

/// Struct representing decrypted file.
///
/// # Fields
/// - `path` - Represents path to the decrypted file. For example, graphics files are stored in Graphics/DIR, e.g. Graphics/Actors/Actor1.png.
///
/// Note, that `path` is represented by [`&[u8]`] because it may contain non-UTF-8 sequences, e.g. Japanese Shift JIS text. In that case, it's up to you how to handle the path.
///
/// - `data` - Represents content of the file.
pub struct ArchiveEntry<'a> {
    pub path: &'a [u8],
    pub data: &'a [u8],
}

/// A struct responsible for decrypting and extracting files from encrypted game archives.
pub struct Decrypter<'a> {
    engine: Engine,
    key: u32,
    key_bytes: [u8; sizeof!(u32)],

    // Decryption members
    /// Entry table not yet consumed. For the older engines it's the whole entry stream (path, size, contents, ...).
    table: &'a mut [u8],
    /// VX Ace only: file contents not yet consumed, starting at archive offset `payload_offset`.
    payload: &'a mut [u8],
    payload_offset: usize,
}

/// Splits the first `count` bytes off `buf`, or returns [`None`] (leaving `buf` untouched) if it's shorter.
fn take<'a>(buf: &mut &'a mut [u8], count: usize) -> Option<&'a mut [u8]> {
    if count > buf.len() {
        return None;
    }

    let (head, tail) = core::mem::take(buf).split_at_mut(count);
    *buf = tail;
    Some(head)
}

fn take_u32(buf: &mut &mut [u8]) -> Option<u32> {
    let bytes = take(buf, sizeof!(u32))?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u32(data: &[u8], pos: usize) -> Result<u32, ExtractError> {
    data.get(pos..)
        .and_then(<[u8]>::first_chunk::<{ sizeof!(u32) }>)
        .map(|bytes| u32::from_le_bytes(*bytes))
        .ok_or(ExtractError::Truncated)
}

/// Returns `pos + count`, failing if that's past the end of `data`.
fn skip(data: &[u8], pos: usize, count: usize) -> Result<usize, ExtractError> {
    pos.checked_add(count)
        .filter(|&end| end <= data.len())
        .ok_or(ExtractError::Truncated)
}

const fn step_older(key: u32) -> u32 {
    key.wrapping_mul(7).wrapping_add(3)
}

/// Walks the XP/VX entry stream without decrypting it, so that [`Decrypter::next_entry`] can't run out of bounds.
fn validate_older(data: &[u8]) -> Result<(), ExtractError> {
    let mut key = OLDER_DECRYPTION_KEY;
    let mut pos = ARCHIVE_HEADER.len() + 1;

    while pos != data.len() {
        let path_size = (read_u32(data, pos)? ^ key) as usize;
        key = step_older(key);
        pos = skip(data, pos + sizeof!(u32), path_size)?;

        // Each path byte advances the key.
        for _ in 0..path_size {
            key = step_older(key);
        }

        let data_size = (read_u32(data, pos)? ^ key) as usize;
        key = step_older(key);
        pos = skip(data, pos + sizeof!(u32), data_size)?;
    }

    Ok(())
}

/// Walks the VX Ace entry table without decrypting it, so that [`Decrypter::next_entry`] can't run out of
/// bounds. Returns the table's end offset.
///
/// Entry contents must follow the table in entry order without overlapping, as every archive written by
/// RPG Maker (and [`Decrypter::encrypt`]) lays them out. This is what lets `next_entry` hand out each region
/// as a separate `&mut` borrow.
fn validate_vxace(data: &[u8], key: u32) -> Result<usize, ExtractError> {
    const TABLE_START: usize = 12;
    const ENTRY_HEADER_SIZE: usize = 16;

    let mut pos = TABLE_START;
    while read_u32(data, pos)? ^ key != 0 {
        let path_size = (read_u32(data, pos + 12)? ^ key) as usize;
        pos = skip(data, pos + ENTRY_HEADER_SIZE, path_size)?;
    }

    // The zero offset terminating the table is part of the archive.
    let table_end = pos;
    let mut min_offset = skip(data, table_end, sizeof!(u32))?;

    pos = TABLE_START;
    while pos < table_end {
        // In bounds: the first pass read these fields.
        let offset = (read_u32(data, pos)? ^ key) as usize;
        let data_size = (read_u32(data, pos + 4)? ^ key) as usize;
        let path_size = (read_u32(data, pos + 12)? ^ key) as usize;

        if offset < min_offset {
            return Err(ExtractError::Corrupt);
        }

        min_offset = skip(data, offset, data_size)?;
        pos += ENTRY_HEADER_SIZE + path_size;
    }

    Ok(table_end)
}

impl<'a> Decrypter<'a> {
    /// Creates a new [`Decrypter`] with empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            engine: Engine::Older,
            key: OLDER_DECRYPTION_KEY,
            key_bytes: OLDER_DECRYPTION_KEY.to_le_bytes(),

            table: &mut [],
            payload: &mut [],
            payload_offset: 0,
        }
    }

    #[inline]
    fn update_key(&mut self, new_key: u32) {
        self.key = new_key;
        self.key_bytes = new_key.to_le_bytes();
    }

    #[inline]
    fn update_key_older(&mut self) {
        self.update_key(step_older(self.key));
    }

    #[inline]
    fn update_key_vxace(&mut self) {
        self.update_key(self.key.wrapping_mul(9).wrapping_add(3));
    }

    #[inline]
    /// Decrypts u32 if `u32` is encrypted, encrypts u32 if `u32` is decrypted.
    const fn xor_u32_vxace(&self, u32: u32) -> u32 {
        u32 ^ self.key
    }

    #[inline]
    /// Decrypts u32 if `u32` is encrypted, encrypts u32 if `u32` is decrypted.
    fn xor_u32_older(&mut self, u32: u32) -> u32 {
        let decrypted = u32 ^ self.key;

        if self.engine.is_older() {
            self.update_key_older();
        }

        decrypted
    }

    #[inline]
    /// Decrypts path if `path_data` is encrypted, encrypts path if `path_data` is decrypted.
    fn xor_path_vxace(&self, path_data: &mut [u8]) {
        for (idx, byte) in path_data.iter_mut().enumerate() {
            // Compiler is smart and can optimize this modulo into `& 0b11`.
            // Since modulo is more self-descriptive, let it be here.
            *byte ^= self.key_bytes[idx % 4];
        }
    }

    #[inline]
    /// Decrypts path if `path_data` is encrypted, encrypts path if `path_data` is decrypted.
    fn xor_path_older(&mut self, path_data: &mut [u8]) {
        for byte in path_data {
            *byte ^= self.key as u8;
            self.update_key_older();
        }
    }

    #[inline]
    /// Decrypts data if `data` is encrypted, encrypts data if `data` is decrypted.
    fn xor_data(mut key: u32, data: &mut [u8]) {
        let mut key_bytes = key.to_le_bytes();
        let mut key_byte_pos = 0;

        // Decrypting data
        for data_byte in data {
            if key_byte_pos == 4 {
                key_byte_pos = 0;
                key = step_older(key);
                key_bytes = key.to_le_bytes();
            }

            *data_byte ^= key_bytes[key_byte_pos];
            key_byte_pos += 1;
        }
    }

    /// Validates `data` and points the decryption state into it. Leaves the state dirty on error, see [`Self::start`].
    fn begin(&mut self, data: &'a mut [u8]) -> Result<(), ExtractError> {
        let Some(&[h0, h1, h2, h3, h4, h5, h6, engine_type]) = data.first_chunk::<8>() else {
            return Err(ExtractError::Truncated);
        };

        let header = [h0, h1, h2, h3, h4, h5, h6];
        if header != *ARCHIVE_HEADER {
            return Err(ExtractError::InvalidHeader(header));
        }

        self.engine = match engine_type {
            1 => Engine::Older,
            3 => Engine::VXAce,
            _ => {
                return Err(ExtractError::InvalidEngine(engine_type));
            }
        };

        if self.engine.is_vx_ace() {
            // Default key is not ever used and overwritten.
            let key = read_u32(data, 8)?;
            self.update_key(key);
            self.update_key_vxace();

            let table_end = validate_vxace(data, self.key)?;

            // The table's terminating zero offset sits between the table and the contents.
            let (head, payload) = data.split_at_mut(table_end + sizeof!(u32));
            let (_, table_and_terminator) = head.split_at_mut(12);
            let (table, _) = table_and_terminator.split_at_mut(table_end - 12);

            self.table = table;
            self.payload = payload;
            self.payload_offset = table_end + sizeof!(u32);
        } else {
            validate_older(data)?;
            self.table = data.split_at_mut(ARCHIVE_HEADER.len() + 1).1;
        }

        Ok(())
    }

    /// Returns the next decrypted [`ArchiveEntry`], or [`None`] once the archive is exhausted.
    ///
    /// This is the pull-based equivalent of the iterator returned by [`Decrypter::decrypt`] - call it
    /// repeatedly after [`Decrypter::start`] (or [`Decrypter::decrypt`], which calls [`Decrypter::start`]
    /// internally) until it returns [`None`]. Useful when you don't want to hold an [`Iterator`], e.g. across
    /// an FFI boundary.
    pub fn next_entry(&mut self) -> Option<ArchiveEntry<'a>> {
        // `start` validated the whole archive, so none of the `?`s below can fail after a successful one.
        // After a failed one (or none at all) the table is empty.
        if self.table.is_empty() {
            return None;
        }

        if self.engine.is_vx_ace() {
            let mut fields = [0u32; 4];
            for field in &mut fields {
                let raw = take_u32(&mut self.table)?;
                *field = self.xor_u32_vxace(raw);
            }
            let [offset, data_size, entry_key, path_size] = fields;
            let (offset, data_size, path_size) = (offset as usize, data_size as usize, path_size as usize);

            let path = take(&mut self.table, path_size)?;
            self.xor_path_vxace(path);

            take(&mut self.payload, offset.checked_sub(self.payload_offset)?)?;
            let data = take(&mut self.payload, data_size)?;
            self.payload_offset = offset + data_size;
            Self::xor_data(entry_key, data);

            Some(ArchiveEntry { path, data })
        } else {
            let raw = take_u32(&mut self.table)?;
            let path_size = self.xor_u32_older(raw) as usize;

            let path = take(&mut self.table, path_size)?;
            self.xor_path_older(path);

            let raw = take_u32(&mut self.table)?;
            let data_size = self.xor_u32_older(raw) as usize;
            let entry_key = self.key;

            let data = take(&mut self.table, data_size)?;
            Self::xor_data(entry_key, data);

            Some(ArchiveEntry { path, data })
        }
    }

    fn encrypt_entries(&mut self, entries: &[ArchiveEntry], archive_buffer: &mut [u8]) {
        let mut offset = 8;

        if self.engine.is_vx_ace() {
            self.update_key(ENCRYPTION_KEY);

            memcpy(&mut archive_buffer[offset..], &self.key_bytes);
            offset += 4;

            self.update_key_vxace();
        }

        if self.engine.is_vx_ace() {
            // First we write metadata: content size, key, path size and path itself
            for entry in entries {
                // Placeholder offset, we'll modify it later
                memcpy(&mut archive_buffer[offset..], &0u32.to_le_bytes());
                offset += 4;

                let data_size = entry.data.len() as u32;
                let encoded_data_size = self.xor_u32_vxace(data_size);
                memcpy(&mut archive_buffer[offset..], &encoded_data_size.to_le_bytes());
                offset += 4;

                // self.key ^ self.key = 0
                memcpy(&mut archive_buffer[offset..], &ENCRYPTION_KEY.to_le_bytes());
                offset += 4;

                let path_size = entry.path.len() as u32;
                let encoded_path_size = self.xor_u32_vxace(path_size);
                memcpy(&mut archive_buffer[offset..], &encoded_path_size.to_le_bytes());
                offset += 4;

                memcpy(&mut archive_buffer[offset..], entry.path);
                self.xor_path_vxace(&mut archive_buffer[offset..offset + entry.path.len()]);
                offset += entry.path.len();
            }

            // Write the key, when decrypthing it will be xor'd against itself which will produce 0, and decryption will stop.
            memcpy(&mut archive_buffer[offset..], &self.key.to_le_bytes());
            offset += 4;

            let mut placeholder_offset = 12;

            // Write the actual contents and modify the offsets with the offsets of the contents
            for entry in entries {
                let data_offset = offset as u32;
                let encrypted_data_offset = self.xor_u32_vxace(data_offset);

                archive_buffer[placeholder_offset..placeholder_offset + 4]
                    .copy_from_slice(&encrypted_data_offset.to_le_bytes());

                placeholder_offset += 16 + entry.path.len();

                memcpy(&mut archive_buffer[offset..], entry.data);
                Self::xor_data(self.key, &mut archive_buffer[offset..offset + entry.data.len()]);
                offset += entry.data.len();
            }
        } else {
            for entry in entries {
                let path_size = entry.path.len() as u32;

                let encoded_path_size = self.xor_u32_older(path_size);
                memcpy(&mut archive_buffer[offset..], &encoded_path_size.to_le_bytes());
                offset += 4;

                memcpy(&mut archive_buffer[offset..], entry.path);
                self.xor_path_older(&mut archive_buffer[offset..offset + entry.path.len()]);
                offset += entry.path.len();

                let data_size = entry.data.len() as u32;
                let encoded_data_size = self.xor_u32_older(data_size);
                memcpy(&mut archive_buffer[offset..], &encoded_data_size.to_le_bytes());
                offset += 4;

                memcpy(&mut archive_buffer[offset..], entry.data);
                Self::xor_data(self.key, &mut archive_buffer[offset..offset + entry.data.len()]);
                offset += entry.data.len();
            }
        }
    }

    fn reset(&mut self) {
        self.table = &mut [];
        self.payload = &mut [];
        self.payload_offset = 0;

        self.engine = Engine::Older;
        self.key = OLDER_DECRYPTION_KEY;
        self.key_bytes = OLDER_DECRYPTION_KEY.to_le_bytes();
    }

    /// Returns an iterator over decrypted [`ArchiveEntry`] entries.
    ///
    /// # Parameters
    /// - `archive_data`: The content of the archive file. This data is modified in-place, and requires to be a mutable reference.
    ///
    /// # Returns
    /// - [`Iterator<Item = ArchiveEntry>`] if files were successfully decrypted.
    /// - [`ExtractError`] otherwise.
    ///
    /// # Errors
    ///
    /// - [`ExtractError::InvalidHeader`] for invalid header.
    /// - [`ExtractError::InvalidEngine`] for invalid header engine type byte.
    ///
    /// # Example
    /// ```no_run
    /// use rpgmad_lib::Decrypter;
    /// use std::{path::PathBuf, fs::{read, write, create_dir_all}};
    ///
    /// let mut data = read("C:/Game/Game.rgss3a").unwrap();
    /// let mut decrypter = Decrypter::new();
    /// let decrypted_entries = decrypter.decrypt(&mut data).unwrap();
    ///
    /// for entry in decrypted_entries {
    ///     let path = String::from_utf8_lossy(&entry.path);
    ///     let output_path = PathBuf::from("C:/Game").join(path.as_ref());
    ///
    ///     if let Some(parent) = output_path.parent() {
    ///         create_dir_all(parent).unwrap();
    ///     }
    ///
    ///     write(output_path, entry.data).unwrap();
    /// }
    /// ```
    #[inline]
    pub fn decrypt(
        &'a mut self,
        archive_data: &'a mut [u8],
    ) -> Result<impl Iterator<Item = ArchiveEntry<'a>>, ExtractError> {
        self.start(archive_data)?;
        Ok(iter::from_fn(move || self.next_entry()))
    }

    /// Resets decryption state from `archive_data` and parses the archive header, without producing any
    /// entries yet.
    ///
    /// This is the pull-based equivalent of [`Decrypter::decrypt`] - call [`Decrypter::next_entry`]
    /// repeatedly afterwards to pull entries one at a time, instead of holding an [`Iterator`]. Useful across
    /// an FFI boundary, where a borrowing iterator can't be returned.
    ///
    /// # Parameters
    /// - `archive_data`: The content of the archive file. This data is modified in-place, and requires to be a mutable reference.
    ///
    /// # Errors
    ///
    /// - [`ExtractError::InvalidHeader`] for invalid header.
    /// - [`ExtractError::InvalidEngine`] for invalid header engine type byte.
    ///
    /// # Example
    /// ```no_run
    /// use rpgmad_lib::Decrypter;
    /// use std::fs::read;
    ///
    /// let mut data = read("C:/Game/Game.rgss3a").unwrap();
    /// let mut decrypter = Decrypter::new();
    /// decrypter.start(&mut data).unwrap();
    ///
    /// while let Some(entry) = decrypter.next_entry() {
    ///     let path = String::from_utf8_lossy(entry.path);
    ///     println!("{path}");
    /// }
    /// ```
    #[inline]
    pub fn start(&mut self, archive_data: &'a mut [u8]) -> Result<(), ExtractError> {
        self.reset();

        let result = self.begin(archive_data);
        if result.is_err() {
            // Nothing is yielded from a rejected archive.
            self.reset();
        }

        result
    }

    /// Returns the size for the encrypted buffer of archive entries in bytes.
    ///
    /// It's necessary to use this function to get the buffer size for the encrypted buffer before actually encrypting the data with [`Decrypter::encrypt`].
    ///
    /// # Parameters
    ///
    /// - `archive_entries`: Archive entries to encrypt.
    /// - `engine`: Target archive engine.
    ///
    /// # Example
    /// See [`Decrypter::encrypt`].
    ///
    #[must_use]
    pub fn encrypted_buffer_size(archive_entries: &[ArchiveEntry], engine: Engine) -> usize {
        let mut buf_size: usize = ARCHIVE_HEADER.len();

        // Engine byte
        buf_size += 1;

        if engine.is_vx_ace() {
            buf_size += 4;
        }

        for entry in archive_entries {
            if engine.is_vx_ace() {
                // Offset
                buf_size += sizeof!(u32);

                // Data size
                buf_size += sizeof!(u32);

                // Key
                buf_size += sizeof!(u32);

                // Path size
                buf_size += sizeof!(u32);
            } else {
                // Path size
                buf_size += sizeof!(u32);

                // Data size
                buf_size += sizeof!(u32);
            }

            buf_size += entry.data.len();
            buf_size += entry.path.len();
        }

        if engine.is_vx_ace() {
            // Stop offset int
            buf_size += sizeof!(u32);

            // VX Ace actually writes the full entry before the stop offset, although this data is not ever used when decrypting and discarded.
            buf_size += sizeof!(u32) * 3;
        }

        buf_size
    }

    /// Writes encrypted archive data to `archive_buffer`.
    ///
    /// `archive_buffer` must be manually pre-allocated by you. You must use the size that [`Decrypter::encrypted_buffer_size`] function returns. This is done this way for `no_std` compatibility.
    ///
    /// # Parameters
    /// - `archive_entries`: Archive entries to encrypt.
    /// - `engine`: Target archive engine.
    /// - `archive_buffer`: Buffer to write encrypted data into.
    ///
    /// # Example
    /// ```no_run
    /// use rpgmad_lib::{Decrypter, Engine, ArchiveEntry};
    /// use std::{fs::{read, write}, borrow::Cow};
    ///
    /// let data = read("Graphics/Tilesets/Tileset1.png").unwrap();
    /// let archive_entries = [ArchiveEntry {
    ///     path: b"Graphics/Tilesets/Tileset1.png",
    ///     data: &data,
    /// }];
    ///
    /// let encrypted_buffer_size = Decrypter::encrypted_buffer_size(&archive_entries, Engine::VXAce);
    /// let mut archive_buffer = Vec::new();
    /// archive_buffer.resize(encrypted_buffer_size, 0);
    ///
    /// Decrypter::new().encrypt(&archive_entries, Engine::VXAce, &mut archive_buffer).unwrap();
    /// write("./Game.rgss3a", archive_buffer).unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// - [`EncryptError::TooLarge`] if the archive would not fit the format's 32-bit sizes and offsets.
    /// - [`EncryptError::BufferTooSmall`] if `archive_buffer` is smaller than [`Decrypter::encrypted_buffer_size`].
    #[inline]
    pub fn encrypt(
        &mut self,
        archive_entries: &[ArchiveEntry],
        engine: Engine,
        archive_buffer: &mut [u8],
    ) -> Result<(), EncryptError> {
        let size = Self::encrypted_buffer_size(archive_entries, engine);

        // Every size and offset written below is at most the total size, so this covers all of the `as u32` casts.
        if u32::try_from(size).is_err() {
            return Err(EncryptError::TooLarge);
        }

        if archive_buffer.len() < size {
            return Err(EncryptError::BufferTooSmall);
        }

        memcpy(archive_buffer, ARCHIVE_HEADER);
        archive_buffer[7] = engine as u8;

        self.engine = engine;
        self.encrypt_entries(archive_entries, archive_buffer);
        Ok(())
    }
}

impl Default for Decrypter<'_> {
    /// Returns a new [`Decrypter`] with default parameters.
    ///
    /// Equivalent to calling [`Decrypter::new`].
    fn default() -> Self {
        Self::new()
    }
}

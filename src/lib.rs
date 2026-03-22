#![cfg_attr(not(feature = "std"), no_std)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::needless_doctest_main)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::deref_addrof)]
#![allow(invalid_reference_casting)]
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
        core::ptr::copy_nonoverlapping(
            src.as_ptr(),
            dst.as_mut_ptr(),
            src.len(),
        );
    }
}

enum SeekFrom {
    Start(u64),
    Current(i64),
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
    #[error(
        "Invalid archive file header: {0:?}. Expected: RGSSAD␀ ([82, 71, 83, 83, 65, 68, 0])"
    )]
    InvalidHeader([u8; 7]),
    #[error(
        "Invalid game engine byte: {0}. Expected `1` for XP/VX or `3` for VX Ace."
    )]
    InvalidEngine(u8),
}

#[derive(Debug, Display, EnumIs, Clone, Copy, PartialEq)]
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
    data: &'a mut [u8],
    pos: usize,
    len: usize,
}

impl<'a> Decrypter<'a> {
    /// Creates a new [`Decrypter`] with empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            engine: Engine::Older,
            key: OLDER_DECRYPTION_KEY,
            key_bytes: OLDER_DECRYPTION_KEY.to_le_bytes(),

            data: &mut [],
            pos: 0,
            len: 0,
        }
    }

    #[inline]
    fn update_key(&mut self, new_key: u32) {
        self.key = new_key;
        self.key_bytes = new_key.to_le_bytes();
    }

    #[inline]
    fn update_key_older(&mut self) {
        self.update_key(self.key.wrapping_mul(7).wrapping_add(3));
    }

    #[inline]
    fn update_key_vxace(&mut self) {
        self.update_key(self.key.wrapping_mul(9).wrapping_add(3));
    }

    #[inline]
    #[track_caller]
    fn read_bytes(&mut self, count: usize) -> &[u8] {
        self.pos += count;
        &self.data[self.pos - count..self.pos]
    }

    #[inline]
    fn read_u32(&mut self) -> u32 {
        let chunk = self.read_bytes(sizeof!(u32));
        u32::from_le_bytes(unsafe {
            *chunk.as_ptr().cast::<[u8; sizeof!(u32)]>()
        })
    }

    #[inline]
    fn read_byte(&mut self) -> u8 {
        self.pos += 1;
        self.data[self.pos - 1]
    }

    #[inline]
    fn seek_byte(&mut self, from: SeekFrom) {
        self.pos = match from {
            SeekFrom::Start(offset) => offset as usize,
            SeekFrom::Current(offset) => self.pos + offset as usize,
        };
    }

    #[inline]
    /// Decrypts u32 if `u32` is encrypted, encrypts u32 if `u32` is decrypted.
    fn xor_u32_vxace(&self, u32: u32) -> u32 {
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
    fn xor_path_vxace(&mut self, path_data: &mut [u8]) {
        for (idx, byte) in
            (unsafe { &*(path_data as *mut [u8]) }).iter().enumerate()
        {
            // Compiler is smart and can optimize this modulo into `& 0b11`.
            // Since modulo is more self-descriptive, let it be here.
            path_data[idx] = byte ^ self.key_bytes[idx % 4];
        }
    }

    #[inline]
    /// Decrypts path if `path_data` is encrypted, encrypts path if `path_data` is decrypted.
    fn xor_path_older(&mut self, path_data: &mut [u8]) {
        for (idx, byte) in
            (unsafe { &*(path_data as *mut [u8]) }).iter().enumerate()
        {
            path_data[idx] = byte ^ self.key as u8;
            self.update_key_older();
        }
    }

    #[inline]
    /// Decrypts data if `data` is encrypted, encrypts data if `data` is decrypted.
    fn xor_data(mut key: u32, data: &mut [u8]) {
        let mut key_bytes = key.to_le_bytes();
        let mut key_byte_pos = 0;

        // Decrypting data
        for (idx, data_byte) in
            (unsafe { &*(data as *mut [u8]) }).iter().enumerate()
        {
            if key_byte_pos == 4 {
                key_byte_pos = 0;
                key = key.wrapping_mul(7).wrapping_add(3);
                key_bytes = key.to_le_bytes();
            }

            data[idx] = data_byte ^ key_bytes[key_byte_pos];
            key_byte_pos += 1;
        }
    }

    #[inline]
    fn parse_header(&mut self) -> Result<(), ExtractError> {
        let header = self.read_bytes(ARCHIVE_HEADER.len());

        if header != ARCHIVE_HEADER {
            return Err(ExtractError::InvalidHeader(unsafe {
                *header.as_ptr().cast::<[u8; 7]>()
            }));
        }

        let engine_type = self.read_byte();

        self.engine = match engine_type {
            1 => Engine::Older,
            3 => Engine::VXAce,
            _ => {
                return Err(ExtractError::InvalidEngine(engine_type));
            }
        };

        Ok(())
    }

    #[inline]
    #[track_caller]
    fn decrypt_entries(&'a mut self) -> impl Iterator<Item = ArchiveEntry<'a>> {
        if self.engine.is_vx_ace() {
            // Default key is not ever used and overwritten.
            let key = self.read_u32();
            self.update_key(key);
            self.update_key_vxace();
        }

        iter::from_fn(move  || {
            let mut u32: u32;

            if self.engine.is_vx_ace() {
                u32 = self.read_u32();
                let data_offset = self.xor_u32_vxace(u32) as u64;

                // End of data
                if data_offset == 0 {
                    return None;
                }

                u32 = self.read_u32();
                let data_size = self.xor_u32_vxace(u32) as usize;

                u32 = self.read_u32();
                let entry_key = self.xor_u32_vxace(u32);

                u32 = self.read_u32();
                let path_size = self.xor_u32_vxace(u32) as usize;

                let path_data = unsafe {
                    &mut *(self.read_bytes(path_size) as *const [u8]
                        as *mut [u8])
                };

                self.xor_path_vxace(path_data);

                // Store current position
                let prev_pos = self.pos;

                // Read data
                self.seek_byte(SeekFrom::Start(data_offset));

                let entry_data = unsafe {
                    &mut *(self.read_bytes(data_size) as *const [u8]
                        as *mut [u8])
                };
                Self::xor_data(entry_key, entry_data);

                let entry = ArchiveEntry {
                    path: path_data,
                    data: entry_data,
                };

                // Restore position
                self.seek_byte(SeekFrom::Start(prev_pos as u64));

                Some(entry)
            } else {
                // End of data
                if self.pos == self.len {
                    return None;
                }

                u32 = self.read_u32();
                let path_size = self.xor_u32_older(u32) as usize;

                let path_data = unsafe {
                    &mut *(self.read_bytes(path_size) as *const [u8]
                        as *mut [u8])
                };

                self.xor_path_older(path_data);

                u32 = self.read_u32();
                let data_size = self.xor_u32_older(u32) as usize;
                let data_offset = self.pos as u64;
                let entry_key = self.key;

                // Skip data block
                self.seek_byte(SeekFrom::Current(data_size as i64));

                // Store current position
                let prev_pos = self.pos;

                // Seek back to the data and read it
                self.seek_byte(SeekFrom::Start(data_offset));

                let entry_data = unsafe {
                    &mut *(self.read_bytes(data_size) as *const [u8]
                        as *mut [u8])
                };
                Self::xor_data(entry_key, entry_data);

                let entry = ArchiveEntry {
                    path: path_data,
                    data: entry_data,
                };

                // Restore position
                self.seek_byte(SeekFrom::Start(prev_pos as u64));

                Some(entry)
            }
        })
    }

    fn encrypt_entries(
        &mut self,
        entries: &[ArchiveEntry],
        archive_buffer: &mut [u8],
    ) {
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
                memcpy(
                    &mut archive_buffer[offset..],
                    &encoded_data_size.to_le_bytes(),
                );
                offset += 4;

                // self.key ^ self.key = 0
                memcpy(
                    &mut archive_buffer[offset..],
                    &ENCRYPTION_KEY.to_le_bytes(),
                );
                offset += 4;

                let path_size = entry.path.len() as u32;
                let encoded_path_size = self.xor_u32_vxace(path_size);
                memcpy(
                    &mut archive_buffer[offset..],
                    &encoded_path_size.to_le_bytes(),
                );
                offset += 4;

                memcpy(&mut archive_buffer[offset..], entry.path);
                self.xor_path_vxace(&mut archive_buffer[offset..]);
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
                Self::xor_data(self.key, &mut archive_buffer[offset..]);
                offset += entry.data.len();
            }
        } else {
            for entry in entries {
                let path_size = entry.path.len() as u32;

                let encoded_path_size = self.xor_u32_older(path_size);
                memcpy(
                    &mut archive_buffer[offset..],
                    &encoded_path_size.to_le_bytes(),
                );

                memcpy(&mut archive_buffer[offset..], entry.path);
                offset += entry.path.len();

                self.xor_path_older(&mut archive_buffer[offset..]);

                let data_size = entry.data.len() as u32;
                let encoded_data_size = self.xor_u32_older(data_size);
                memcpy(
                    &mut archive_buffer[offset..],
                    &encoded_data_size.to_le_bytes(),
                );
                offset += 4;

                memcpy(&mut archive_buffer[offset..], entry.data);
                Self::xor_data(self.key, &mut archive_buffer[offset..]);
                offset += entry.data.len();
            }
        }
    }

    fn reset(&mut self, data: &'a mut [u8]) {
        self.len = data.len();
        self.data = data;
        self.pos = 0;

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
        self.reset(archive_data);
        self.parse_header()?;
        Ok(self.decrypt_entries())
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
    pub fn encrypted_buffer_size(
        archive_entries: &[ArchiveEntry],
        engine: Engine,
    ) -> usize {
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
    /// Decrypter::new().encrypt(&archive_entries, Engine::VXAce, &mut archive_buffer);
    /// write("./Game.rgss3a", archive_buffer).unwrap();
    /// ```
    #[must_use]
    #[inline]
    pub fn encrypt(
        &mut self,
        archive_entries: &[ArchiveEntry],
        engine: Engine,
        archive_buffer: &mut [u8],
    ) {
        memcpy(archive_buffer, ARCHIVE_HEADER);
        archive_buffer[7] = engine as u8;

        self.engine = engine;
        self.encrypt_entries(archive_entries, archive_buffer);
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

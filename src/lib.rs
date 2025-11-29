#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::needless_doctest_main)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::deref_addrof)]
#![doc = include_str!("../README.md")]

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, io::SeekFrom};
use strum_macros::{Display, EnumIs};
use thiserror::Error;

macro_rules! sizeof {
    ($t:ty) => {{ size_of::<$t>() }};
}

const ARCHIVE_HEADER: &[u8; 7] = b"RGSSAD\0";

const OLDER_DECRYPTION_KEY: u32 = 0xDEAD_CAFE;
const ENCRYPTION_KEY: u32 = 0;

// Archives probably may contains more entries, but even the largest games will have less or around 16384.
// We allocate the memory in a vector, so if this is not enough vector will reallocate to twice the size anyways.
const MAX_ENTRY_AMOUNT: usize = 16384;

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

#[derive(PartialEq, Debug, Display, EnumIs, Clone, Copy)]
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
/// Note, that `path` is represented by [`Vec<u8>`] because it may contain non-UTF-8 sequences, e.g. Japanese Shift JIS text. In that case, it's up to you how to handle the path.
///
/// - `data` - Represents content of the file.
pub struct ArchiveEntry {
    pub path: Cow<'static, [u8]>,
    pub data: Vec<u8>,
}

/// A struct responsible for decrypting and extracting files from encrypted game archives.
pub struct Decrypter<'a> {
    engine: Engine,
    key: u32,
    key_bytes: [u8; sizeof!(u32)],

    // Decryption members
    data: &'a [u8],
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

            data: &[],
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
            SeekFrom::End(_) => unreachable!(),
        };
    }

    #[inline]
    /// Decrypts u32 if `u32` is encrypted, encrypts u32 if `u32` is decrypted.
    fn xor_u32_vxace(&mut self, u32: u32) -> u32 {
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
    fn xor_path_vxace(&mut self, path_data: &[u8], output: &mut Vec<u8>) {
        for (idx, byte) in path_data.iter().enumerate() {
            // Compiler is smart and can optimize this modulo into `& 0b11`.
            // Since modulo is more self-descriptive, let it be here.
            output.push(byte ^ self.key_bytes[idx % 4]);
        }
    }

    #[inline]
    /// Decrypts path if `path_data` is encrypted, encrypts path if `path_data` is decrypted.
    fn xor_path_older(&mut self, path_data: &[u8], output: &mut Vec<u8>) {
        for byte in path_data {
            output.push(byte ^ self.key as u8);
            self.update_key_older();
        }
    }

    #[inline]
    /// Decrypts data if `data` is encrypted, encrypts data if `data` is decrypted.
    fn xor_data(mut key: u32, data: &[u8], output: &mut Vec<u8>) {
        let mut key_bytes = key.to_le_bytes();
        let mut key_byte_pos = 0;

        // Decrypting data
        for data_byte in data {
            if key_byte_pos == 4 {
                key_byte_pos = 0;
                key = key.wrapping_mul(7).wrapping_add(3);
                key_bytes = key.to_le_bytes();
            }

            output.push(data_byte ^ key_bytes[key_byte_pos]);
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
    fn decrypt_entries(&mut self) -> Vec<ArchiveEntry> {
        if self.engine.is_vx_ace() {
            // Default key is not ever used and overwritten.
            let key = self.read_u32();
            self.update_key(key);
            self.update_key_vxace();
        }

        let mut entries = Vec::with_capacity(MAX_ENTRY_AMOUNT);
        let mut u32: u32;

        if self.engine.is_vx_ace() {
            loop {
                u32 = self.read_u32();
                let data_offset = u64::from(self.xor_u32_vxace(u32));

                // End of data
                if data_offset == 0 {
                    break;
                }

                u32 = self.read_u32();
                let data_size = self.xor_u32_vxace(u32);

                u32 = self.read_u32();
                let entry_key = self.xor_u32_vxace(u32);

                u32 = self.read_u32();
                let path_size = self.xor_u32_vxace(u32) as usize;
                let mut decrypted_path = Vec::with_capacity(path_size);

                let path_data =
                    unsafe { &*(self.read_bytes(path_size) as *const [u8]) };

                self.xor_path_vxace(path_data, &mut decrypted_path);

                // Store current position
                let prev_pos = self.pos;

                // Read data
                self.seek_byte(SeekFrom::Start(data_offset));

                let entry_data = self.read_bytes(data_size as usize);
                let mut decrypted_data = Vec::with_capacity(data_size as usize);
                Self::xor_data(entry_key, entry_data, &mut decrypted_data);

                entries.push(ArchiveEntry {
                    path: Cow::Owned(decrypted_path),
                    data: decrypted_data,
                });

                // Restore position
                self.seek_byte(SeekFrom::Start(prev_pos as u64));
            }
        } else {
            loop {
                // End of data
                if self.pos == self.len {
                    break;
                }

                u32 = self.read_u32();
                let path_size = self.xor_u32_older(u32) as usize;
                let mut decrypted_path = Vec::with_capacity(path_size);

                let path_data =
                    unsafe { &*(self.read_bytes(path_size) as *const [u8]) };

                self.xor_path_older(path_data, &mut decrypted_path);

                u32 = self.read_u32();
                let data_size = self.xor_u32_older(u32);
                let data_offset = self.pos as u64;
                let entry_key = self.key;

                // Skip data block
                self.seek_byte(SeekFrom::Current(i64::from(data_size)));

                // Store current position
                let prev_pos = self.pos;

                // Seek back to the data and read it
                self.seek_byte(SeekFrom::Start(data_offset));

                let entry_data = self.read_bytes(data_size as usize);
                let mut decrypted_data = Vec::with_capacity(data_size as usize);
                Self::xor_data(entry_key, entry_data, &mut decrypted_data);

                entries.push(ArchiveEntry {
                    path: Cow::Owned(decrypted_path),
                    data: decrypted_data,
                });

                // Restore position
                self.seek_byte(SeekFrom::Start(prev_pos as u64));
            }
        }

        entries
    }

    fn encrypt_entries(
        &mut self,
        entries: &[ArchiveEntry],
        archive_buffer: &mut Vec<u8>,
    ) {
        if self.engine.is_vx_ace() {
            self.update_key(ENCRYPTION_KEY);

            archive_buffer.extend_from_slice(&self.key_bytes);
            self.update_key_vxace();
        }

        // We'll store the position of the file offsets to later modify it
        let mut data_offsets_indices = Vec::with_capacity(entries.len());

        if self.engine.is_vx_ace() {
            // First we write metadata: content size, key, path size and path itself
            for entry in entries {
                // Placeholder offset, we'll modify it later
                data_offsets_indices.push(archive_buffer.len());
                archive_buffer.extend_from_slice(&0u32.to_le_bytes());

                let data_size = entry.data.len() as u32;
                let encoded_data_size = self.xor_u32_vxace(data_size);
                archive_buffer
                    .extend_from_slice(&encoded_data_size.to_le_bytes());

                // self.key ^ self.key = 0
                archive_buffer.extend_from_slice(&ENCRYPTION_KEY.to_le_bytes());

                let path_size = entry.path.len() as u32;
                let encoded_path_size = self.xor_u32_vxace(path_size);
                archive_buffer
                    .extend_from_slice(&encoded_path_size.to_le_bytes());

                self.xor_path_vxace(&entry.path, archive_buffer);
            }

            // Write the key, when decrypthing it will be xor'd against itself which will produce 0, and decryption will stop.
            archive_buffer.extend_from_slice(&self.key.to_le_bytes());

            // Write the actual contents and modify the offsets with the offsets of the contents
            for (idx, entry) in entries.iter().enumerate() {
                let data_offset = archive_buffer.len() as u32;
                let encrypted_data_offset = self.xor_u32_vxace(data_offset);
                let offset_slice_mut = &mut archive_buffer[data_offsets_indices
                    [idx]
                    ..data_offsets_indices[idx] + sizeof!(u32)];

                offset_slice_mut
                    .copy_from_slice(&encrypted_data_offset.to_le_bytes());
                Self::xor_data(self.key, &entry.data, archive_buffer);
            }
        } else {
            for entry in entries {
                let path_size = entry.path.len() as u32;

                let encoded_path_size = self.xor_u32_older(path_size);
                archive_buffer
                    .extend_from_slice(&encoded_path_size.to_le_bytes());

                self.xor_path_older(&entry.path, archive_buffer);

                let data_size = entry.data.len() as u32;
                let encoded_data_size = self.xor_u32_older(data_size);
                archive_buffer
                    .extend_from_slice(&encoded_data_size.to_le_bytes());

                Self::xor_data(self.key, &entry.data, archive_buffer);
            }
        }
    }

    fn reset(&mut self, data: &'a [u8]) {
        self.data = data;
        self.len = data.len();
        self.pos = 0;

        self.engine = Engine::Older;
        self.key = OLDER_DECRYPTION_KEY;
        self.key_bytes = OLDER_DECRYPTION_KEY.to_le_bytes();
    }

    /// Returns [`Vec`] of decrypted [`ArchiveEntry`] entries.
    ///
    /// # Parameters
    /// - `archive_data`: The content of the archive file.
    ///
    /// # Returns
    /// - [`Vec<ArchiveEntry>`] if files were successfully decrypted.
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
    /// let data = read("C:/Game/Game.rgss3a").unwrap();
    /// let decrypted_entries = Decrypter::new().decrypt(&data).unwrap();
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
        &mut self,
        archive_data: &'a [u8],
    ) -> Result<Vec<ArchiveEntry>, ExtractError> {
        self.reset(archive_data);
        self.parse_header()?;
        Ok(self.decrypt_entries())
    }

    /// Returns encrypted archive data as [`Vec<u8>`].
    ///
    /// # Parameters
    /// - `entries`: Archive entries to encrypt.
    /// - `engine`: Target archive engine.
    ///
    /// # Returns
    /// - [`Vec<u8>`] representing encrypted archive data.
    ///
    /// # Example
    /// ```no_run
    /// use rpgmad_lib::{Decrypter, Engine, ArchiveEntry};
    /// use std::{fs::{read, write}, borrow::Cow};
    ///
    /// let archive_entries = [ArchiveEntry {
    ///     path: Cow::Borrowed(b"Graphics/Tilesets/Tileset1.png"),
    ///     data: read("Graphics/Tilesets/Tileset1.png").unwrap()
    /// }];
    /// let archive_data = Decrypter::new().encrypt(&archive_entries, Engine::VXAce);
    /// write("./Game.rgss3a", archive_data).unwrap();
    /// ```
    #[must_use]
    #[inline]
    pub fn encrypt(
        &mut self,
        archive_entries: &[ArchiveEntry],
        engine: Engine,
    ) -> Vec<u8> {
        let mut buf_size: usize = ARCHIVE_HEADER.len();

        // Engine byte
        buf_size += 1;

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
        }

        let mut archive_buffer = Vec::with_capacity(buf_size);

        archive_buffer.extend_from_slice(ARCHIVE_HEADER);
        archive_buffer.push(engine as u8);

        self.engine = engine;
        self.encrypt_entries(archive_entries, &mut archive_buffer);

        archive_buffer
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

/// A convenience function to decrypt an archive in a single call.
///
/// This is a wrapper around [`Decrypter::decrypt`] with automatic initialization.
///
/// # Parameters
/// - `archive_data`: The content of the archive file.
///
/// # Returns
/// - [`Vec<DecryptedFile>`] if files were successfully decrypted.
/// - [`ExtractError`] otherwise.
///
/// # Errors
/// - [`ExtractError::InvalidHeader`] for invalid header.
/// - [`ExtractError::InvalidEngine`] for invalid header engine type byte.
///
/// # Example
/// ```no_run
/// use rpgmad_lib::decrypt_archive;
/// use std::{path::PathBuf, fs::{read, write, create_dir_all}};
///
/// let data = read("C:/Game/Game.rgss3a").unwrap();
/// let decrypted_entries = decrypt_archive(&data).unwrap();
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
pub fn decrypt_archive(
    archive_data: &[u8],
) -> Result<Vec<ArchiveEntry>, ExtractError> {
    Decrypter::new().decrypt(archive_data)
}

/// A convenience function to encrypt an archive in a single call.
///
/// This is a wrapper around [`Decrypter::encrypt`] with automatic initialization.
///
/// # Parameters
/// - `archive_entries`: Entries to pack into the archive.
/// - `engine`: [`Engine`] that defines output archive format.
///
/// # Returns
/// - [`Vec<u8>`] representing the archive.
///
/// # Example
/// ```no_run
/// use rpgmad_lib::{encrypt_archive, ArchiveEntry, Engine};
/// use std::{fs::{read, write}, borrow::Cow};
///
/// let archive_entries = [ArchiveEntry {
///     path: Cow::Borrowed(b"Graphics/Tilesets/Tileset1.png"),
///     data: read("Graphics/Tilesets/Tileset1.png").unwrap()
/// }];
/// let archive_data = encrypt_archive(&archive_entries, Engine::VXAce);
/// write("./Game.rgss3a", archive_data).unwrap();
/// ```
#[must_use]
pub fn encrypt_archive(
    archive_entries: &[ArchiveEntry],
    engine: Engine,
) -> Vec<u8> {
    Decrypter::new().encrypt(archive_entries, engine)
}

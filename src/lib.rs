//! # rpgm-archive-decrypter-lib
//!
//! Library for decrypting RPG Maker `rgss` archives.
//!
//! Used in [rpgm-archive-decrypter](https://github.com/savannstm/rpgm-archive-decrypter).
//!
//! ## Quick example
//!
//! ```no_run
//! use rpgmad_lib::{Decrypter, extract_archive};
//!
//! // Using Decrypter struct
//! let archive_content: Vec<u8> = std::fs::read("C:/Game/Game.rgss3a").unwrap();
//! let mut decrypter = Decrypter::new();
//!
//! // You can optionally set force
//! // decrypter.set_force(true)
//!
//! decrypter.extract(&archive_content, "C:/Game").unwrap();
//!
//! // Using function
//! let force = false; // When `true`, it will overwrite existing files in the game directory.
//! extract_archive(&archive_content, "C:/Game", force).unwrap();
//! ```
//!
//! ## License
//!
//! Project is licensed under WTFPL.

use std::{
    fs::{create_dir_all, write},
    path::{Path, PathBuf},
};
use thiserror::Error;

const ARCHIVE_HEADER: &[u8; 6] = b"RGSSAD";
const OLDER_DEFAULT_KEY: u32 = 0xDEADCAFE;

#[derive(Error, Debug)]
pub enum ExtractError {
    #[error("Invalid archive file header: {found:?}. Expected: RGSSAD ([82, 71, 83, 83, 65, 68])")]
    InvalidHeader { found: [u8; 6] },
    #[error("Invalid game engine byte: {found}. Expected `1` for XP/VX or `3` for VX Ace.")]
    InvalidEngine { found: u8 },
}

pub enum ExtractOutcome {
    Extracted,
    FilesExist,
}

#[derive(PartialEq)]
enum EngineType {
    Older,
    VXAce,
}

enum SeekFrom {
    Start,
    Current,
}

impl std::fmt::Display for EngineType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EngineType::Older => write!(f, "XP/VX"),
            EngineType::VXAce => write!(f, "VXAce"),
        }
    }
}

#[derive(Default)]
struct ArchiveEntry {
    filename_bytes: Vec<u8>,
    size: i32,
    offset: usize,
    key: u32,
}

/// A struct responsible for decrypting and extracting files from encrypted game archives.
pub struct Decrypter<'a> {
    data: &'a [u8],
    pos: usize,
    len: usize,
    force: bool,
    engine_type: EngineType,
    key: u32,
    key_bytes: [u8; 4],
}

impl<'a> Decrypter<'a> {
    /// Creates a new `Decrypter` with empty buffer, and `force` set to `false`.
    pub fn new() -> Self {
        Self {
            data: &[],
            pos: 0,
            len: 0,

            force: false,

            engine_type: EngineType::Older,
            key: OLDER_DEFAULT_KEY,
            key_bytes: OLDER_DEFAULT_KEY.to_le_bytes(),
        }
    }

    /// Enables or disables forced overwrite during extraction.
    ///
    /// When `enabled` is `true`, extracted files will overwrite existing files on disk.
    ///
    /// Returns self.
    #[inline]
    pub fn force(mut self, enabled: bool) -> Self {
        self.force = enabled;
        self
    }

    /// Enables or disables forced overwrite during extraction.
    ///
    /// When `enabled` is `true`, extracted files will overwrite existing files on disk.
    #[inline]
    pub fn set_force(&mut self, enabled: bool) {
        self.force = enabled;
    }

    #[inline]
    fn update_key(&mut self, new_key: u32) {
        self.key = new_key;
        self.key_bytes = new_key.to_le_bytes();
    }

    #[inline]
    fn read_bytes(&mut self, bytes: usize) -> &[u8] {
        self.pos += bytes;
        &self.data[self.pos - bytes..self.pos]
    }

    #[inline]
    fn read_int(&mut self) -> i32 {
        let chunk: &[u8] = self.read_bytes(4);
        i32::from_le_bytes(unsafe { *(chunk.as_ptr() as *const [u8; 4]) })
    }

    #[inline]
    fn read_byte(&mut self) -> u8 {
        self.pos += 1;
        self.data[self.pos - 1]
    }

    #[inline]
    fn seek_byte(&mut self, offset: usize, seek_from: SeekFrom) {
        self.pos = match seek_from {
            SeekFrom::Start => offset,
            SeekFrom::Current => self.pos + offset,
        };
    }

    #[inline]
    fn decrypt_entry(&mut self, entry: &ArchiveEntry) -> Vec<u8> {
        let mut key = entry.key;
        let mut key_bytes: [u8; 4] = key.to_le_bytes();
        let mut key_byte_pos: usize = 0;

        self.seek_byte(entry.offset, SeekFrom::Start);

        let content = self.read_bytes(entry.size as usize);
        let mut decrypted: Vec<u8> = Vec::with_capacity(content.len());

        for item in content {
            if key_byte_pos == 4 {
                key_byte_pos = 0;
                key = key.wrapping_mul(7).wrapping_add(3);
                key_bytes = key.to_le_bytes();
            }

            decrypted.push(item ^ key_bytes[key_byte_pos]);
            key_byte_pos += 1;
        }

        decrypted
    }

    #[inline]
    fn decrypt_int(&mut self) -> i32 {
        let int: i32 = self.read_int();
        let result: i32 = int ^ self.key as i32;

        if self.engine_type == EngineType::Older {
            self.update_key(self.key.wrapping_mul(7).wrapping_add(3));
        }

        result
    }

    #[inline]
    fn decrypt_filename(&mut self, entry: &mut ArchiveEntry) {
        let filename_bytes =
            unsafe { &*(self.read_bytes(entry.filename_bytes.capacity()) as *const [u8]) };

        if self.engine_type == EngineType::VXAce {
            let mut key_byte_pos: usize = 0;

            for byte in filename_bytes {
                if key_byte_pos == 4 {
                    key_byte_pos = 0;
                }

                entry
                    .filename_bytes
                    .push(byte ^ self.key_bytes[key_byte_pos]);
                key_byte_pos += 1;
            }
        } else {
            for byte in filename_bytes {
                entry.filename_bytes.push(byte ^ self.key as u8);
                self.update_key(self.key.wrapping_mul(7).wrapping_add(3));
            }
        }
    }

    #[inline]
    fn parse_header(&mut self) -> Result<(), ExtractError> {
        let header: &[u8] = self.read_bytes(6);

        if header != ARCHIVE_HEADER {
            return Err(ExtractError::InvalidHeader {
                found: unsafe { *(header.as_ptr() as *const [u8; 6]) },
            });
        }

        self.seek_byte(1, SeekFrom::Current);
        let engine_type: u8 = self.read_byte();

        self.engine_type = match engine_type {
            1 => EngineType::Older,
            3 => EngineType::VXAce,
            _ => return Err(ExtractError::InvalidEngine { found: engine_type }),
        };

        Ok(())
    }

    #[inline]
    fn extract_entries(&mut self) -> Vec<ArchiveEntry> {
        if self.engine_type == EngineType::VXAce {
            // Default key is not ever used and overwritten.
            let key = self.read_int() as u32;
            self.update_key(key.wrapping_mul(9).wrapping_add(3));
        }

        let mut entries = Vec::with_capacity(16384);

        loop {
            let mut entry: ArchiveEntry = ArchiveEntry::default();

            match self.engine_type {
                EngineType::VXAce => {
                    entry.offset = self.decrypt_int() as usize;

                    if entry.offset == 0 {
                        break;
                    }

                    entry.size = self.decrypt_int();
                    entry.key = self.decrypt_int() as u32;

                    entry
                        .filename_bytes
                        .reserve_exact(self.decrypt_int() as usize);
                    self.decrypt_filename(&mut entry);
                }
                EngineType::Older => {
                    entry
                        .filename_bytes
                        .reserve_exact(self.decrypt_int() as usize);
                    self.decrypt_filename(&mut entry);

                    entry.size = self.decrypt_int();
                    entry.offset = self.pos;
                    entry.key = self.key;

                    self.seek_byte(entry.size as usize, SeekFrom::Current);

                    if self.pos == self.len {
                        break;
                    }
                }
            }

            entries.push(entry);
        }

        entries
    }

    fn reset(&mut self, data: &[u8]) {
        self.data = unsafe { &*(data as *const [u8]) };
        self.len = data.len();
        self.pos = 0;
        self.engine_type = EngineType::Older;
        self.key = OLDER_DEFAULT_KEY;
        self.key_bytes = OLDER_DEFAULT_KEY.to_le_bytes();
    }

    /// Extracts files from the archive data into the specified output path.
    ///
    /// # Parameters
    /// - `data`: The content of the archive file.
    /// - `output_path`: The output path for extracted files.
    ///
    /// # Returns
    /// - `Ok(ExtractOutcome::Extracted)` if files were successfully extracted.
    /// - `Ok(ExtractOutcome::FilesExist)` if files already exist and `force` is `false`.
    /// - `Err(ExtractError::InvalidHeader)` for invalid header.
    /// - `Err(ExtractError::InvalidEngine)` for invalid header engine type byte.
    /// # Example
    /// ```no_run
    /// use rpgmad_lib::Decrypter;
    ///
    /// let archive_data: Vec<u8> = std::fs::read("Game.rgss3a").unwrap();
    /// let mut decrypter = Decrypter::new();
    /// decrypter.extract(&archive_data, "output").unwrap();
    /// ```
    #[inline]
    pub fn extract<P: AsRef<Path>>(
        &mut self,
        data: &[u8],
        output_path: P,
    ) -> Result<ExtractOutcome, ExtractError> {
        self.reset(data);
        self.parse_header()?;

        let entries: Vec<ArchiveEntry> = self.extract_entries();

        for entry in entries {
            let filename = String::from_utf8_lossy(&entry.filename_bytes);
            let file_output_path: PathBuf = output_path.as_ref().join(&*filename);

            if file_output_path.exists() && !self.force {
                return Ok(ExtractOutcome::FilesExist);
            }

            if let Some(dir) = file_output_path.parent() {
                create_dir_all(dir).unwrap();
            }

            let decrypted = self.decrypt_entry(&entry);
            write(file_output_path, decrypted).unwrap();
        }

        Ok(ExtractOutcome::Extracted)
    }
}

impl<'a> Default for Decrypter<'a> {
    /// Returns a new `Decrypter` with default parameters.
    ///
    /// Equivalent to calling `Decrypter::new()`.
    fn default() -> Self {
        Self::new()
    }
}

/// A convenience function to extract an archive in a single call.
///
/// This is a wrapper around `Decrypter::extract` with automatic initialization.
///
/// # Parameters
/// - `data`: The content of the archive file.
/// - `output_path`: The output path for extracted files.
/// - `force`: If `true`, existing files will be overwritten.
///
/// # Returns
/// - `Ok(ExtractOutcome::Extracted)` if files were successfully extracted.
/// - `Ok(ExtractOutcome::FilesExist)` if files already exist and `force` is `false`.
/// - `Err(ExtractError::InvalidHeader)` for invalid header.
/// - `Err(ExtractError::InvalidEngine)` for invalid header engine type byte.
///
/// # Example
/// ```no_run
/// use rpgmad_lib::extract_archive;
///
/// let data: Vec<u8> = std::fs::read("Game.rgssad").unwrap();
/// extract_archive(&data, "output", true).unwrap();
/// ```
pub fn extract_archive<P: AsRef<Path>>(
    data: &[u8],
    output_path: P,
    force: bool,
) -> Result<ExtractOutcome, ExtractError> {
    Decrypter::new().force(force).extract(data, output_path)
}

/*!
# rpgm-archive-decrypter-lib

Library for decrypting RPG Maker `rgss` archives.

Used in [rpgm-archive-decrypter](https://github.com/savannstm/rpgm-archive-decrypter).

## Example
```no_run
use rpgmad_lib::{Decrypter, decrypt_archive};
use std::path::PathBuf;

let archive_content: Vec<u8> = std::fs::read("C:/Game/Game.rgss3a").unwrap();

// Using Decrypter struct
let mut decrypter = Decrypter::new();
let decrypted_files = decrypter.decrypt(&archive_content).unwrap();

// Using function
let decrypted_files = decrypt_archive(&archive_content).unwrap();

for file in decrypted_files {
    let path = String::from_utf8_lossy(&file.path);
    let output_path = PathBuf::from("C:/Game").join(path.as_ref());

    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }

    std::fs::write(output_path, file.content).unwrap();
}
```

## License

Project is licensed under WTFPL.
*/

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::io::SeekFrom;
use strum_macros::{Display, EnumIs};
use thiserror::Error;

const ARCHIVE_HEADER: &[u8; 6] = b"RGSSAD";
const OLDER_DEFAULT_KEY: u32 = 0xDEADCAFE;

#[derive(Debug, Error)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub enum ExtractError {
    #[error(
        "Invalid archive file header: {0:?}. Expected: RGSSAD ([82, 71, 83, 83, 65, 68])"
    )]
    InvalidHeader([u8; 6]),
    #[error(
        "Invalid game engine byte: {0}. Expected `1` for XP/VX or `3` for VX Ace."
    )]
    InvalidEngine(u8),
}

#[derive(Debug, Display, EnumIs)]
enum EngineType {
    #[strum(to_string = "XP/VX")]
    Older,
    #[strum(to_string = "VXAce")]
    VXAce,
}

/// Struct representing decrypted file.
///
/// # Fields
/// - `path` - Represents path to the decrypted file. For example, graphics files are stored in Graphics/DIR, e.g. Graphics/Actors/Actor1.png.
///
/// Note, that `path` is represented by `Vec<u8>` because it may contain non-UTF-8 sequences, e.g. Japanese Shift JIS text. In that case, it's up to you how to handle the path.
///
/// - `data` - Represents data of the file.
pub struct DecryptedFile {
    pub path: Vec<u8>,
    pub content: Vec<u8>,
}

/// A struct responsible for decrypting and extracting files from encrypted game archives.
pub struct Decrypter<'a> {
    data: &'a [u8],
    pos: usize,
    len: usize,

    engine_type: EngineType,
    key: u32,
    key_bytes: [u8; 4],
}

impl<'a> Decrypter<'a> {
    /// Creates a new `Decrypter` with empty buffer.
    pub fn new() -> Self {
        Self {
            data: &[],
            pos: 0,
            len: 0,

            engine_type: EngineType::Older,
            key: OLDER_DEFAULT_KEY,
            key_bytes: OLDER_DEFAULT_KEY.to_le_bytes(),
        }
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
        let chunk = self.read_bytes(4);
        i32::from_le_bytes(unsafe { *(chunk.as_ptr() as *const [u8; 4]) })
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
            _ => unreachable!(),
        };
    }

    #[inline]
    fn decrypt_int(&mut self) -> i32 {
        let int = self.read_int();
        let result = int ^ self.key as i32;

        if self.engine_type.is_older() {
            self.update_key(self.key.wrapping_mul(7).wrapping_add(3));
        }

        result
    }

    #[inline]
    fn decrypt_path(&mut self, path: &mut Vec<u8>, path_size: usize) {
        let filename_bytes =
            unsafe { &*(self.read_bytes(path_size) as *const [u8]) };

        if self.engine_type.is_vx_ace() {
            let mut key_byte_pos = 0;

            for byte in filename_bytes {
                if key_byte_pos == 4 {
                    key_byte_pos = 0;
                }

                path.push(byte ^ self.key_bytes[key_byte_pos]);
                key_byte_pos += 1;
            }
        } else {
            for byte in filename_bytes {
                path.push(byte ^ self.key as u8);
                self.update_key(self.key.wrapping_mul(7).wrapping_add(3));
            }
        }
    }

    #[inline]
    fn parse_header(&mut self) -> Result<(), ExtractError> {
        let header = self.read_bytes(6);

        if header != ARCHIVE_HEADER {
            return Err(ExtractError::InvalidHeader(unsafe {
                *(header.as_ptr() as *const [u8; 6])
            }));
        }

        self.seek_byte(SeekFrom::Current(1));
        let engine_type = self.read_byte();

        self.engine_type = match engine_type {
            1 => EngineType::Older,
            3 => EngineType::VXAce,
            _ => {
                return Err(ExtractError::InvalidEngine(engine_type));
            }
        };

        Ok(())
    }

    #[inline]
    fn decrypt_entries(&mut self) -> Vec<DecryptedFile> {
        if self.engine_type.is_vx_ace() {
            // Default key is not ever used and overwritten.
            let key = self.read_int() as u32;
            self.update_key(key.wrapping_mul(9).wrapping_add(3));
        }

        let mut entries = Vec::with_capacity(16384);
        let mut prev_pos: usize;

        loop {
            let (size, offset, mut key);
            let mut path;

            match self.engine_type {
                EngineType::VXAce => {
                    offset = self.decrypt_int() as u64;

                    if offset == 0 {
                        break;
                    }

                    size = self.decrypt_int();
                    key = self.decrypt_int() as u32;

                    let path_size = self.decrypt_int() as usize;
                    path = Vec::with_capacity(path_size);
                    self.decrypt_path(&mut path, path_size);
                }
                EngineType::Older => {
                    if self.pos == self.len {
                        break;
                    }

                    let path_size = self.decrypt_int() as usize;
                    path = Vec::with_capacity(path_size);
                    self.decrypt_path(&mut path, path_size);

                    size = self.decrypt_int();
                    offset = self.pos as u64;
                    key = self.key;

                    self.seek_byte(SeekFrom::Current(size as i64));
                }
            }

            prev_pos = self.pos;

            let mut key_bytes = key.to_le_bytes();
            let mut key_byte_pos = 0;

            self.seek_byte(SeekFrom::Start(offset));

            let content = self.read_bytes(size as usize);
            let mut decrypted = Vec::with_capacity(content.len());

            for byte in content {
                if key_byte_pos == 4 {
                    key_byte_pos = 0;
                    key = key.wrapping_mul(7).wrapping_add(3);
                    key_bytes = key.to_le_bytes();
                }

                decrypted.push(byte ^ key_bytes[key_byte_pos]);
                key_byte_pos += 1;
            }

            entries.push(DecryptedFile {
                content: decrypted,
                path,
            });

            self.seek_byte(SeekFrom::Start(prev_pos as u64));
        }

        entries
    }

    fn reset(&mut self, data: &'a [u8]) {
        *self = Self::new();
        self.data = data;
        self.len = data.len();
    }

    /// Returns `Vec` of decrypted files.
    ///
    /// # Parameters
    /// - `data`: The content of the archive file.
    ///
    /// # Returns
    /// - `Ok(Vec<DecryptedFile>)` if files were successfully decrypted.
    /// - `Err(ExtractError::InvalidHeader)` for invalid header.
    /// - `Err(ExtractError::InvalidEngine)` for invalid header engine type byte.
    ///
    /// # Example
    /// ```no_run
    /// use rpgmad_lib::Decrypter;
    /// use std::path::PathBuf;
    ///
    /// let data: Vec<u8> = std::fs::read("C:/Game/Game.rgss3a").unwrap();
    /// let decrypted_files = Decrypter::new().decrypt(&data).unwrap();
    ///
    /// for file in decrypted_files {
    ///     let path = String::from_utf8_lossy(&file.path);
    ///     let output_path = PathBuf::from("C:/Game").join(path.as_ref());
    ///
    ///     if let Some(parent) = output_path.parent() {
    ///         std::fs::create_dir_all(parent).unwrap();
    ///     }
    ///
    ///     std::fs::write(output_path, file.content).unwrap();
    /// }
    /// ```
    #[inline]
    pub fn decrypt(
        &mut self,
        data: &'a [u8],
    ) -> Result<Vec<DecryptedFile>, ExtractError> {
        self.reset(data);
        self.parse_header()?;
        Ok(self.decrypt_entries())
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

/// A convenience function to decrypt an archive in a single call.
///
/// This is a wrapper around `Decrypter::decrypt` with automatic initialization.
///
/// # Parameters
/// - `data`: The content of the archive file.
///
/// # Returns
/// - `Ok(Vec<DecryptedFile>)` if files were successfully decrypted.
/// - `Err(ExtractError::InvalidHeader)` for invalid header.
/// - `Err(ExtractError::InvalidEngine)` for invalid header engine type byte.
///
/// # Example
/// ```no_run
/// use rpgmad_lib::decrypt_archive;
/// use std::path::PathBuf;
///
///
/// let data: Vec<u8> = std::fs::read("C:/Game/Game.rgss3a").unwrap();
/// let decrypted_files = decrypt_archive(&data).unwrap();
///
/// for file in decrypted_files {
///     let path = String::from_utf8_lossy(&file.path);
///     let output_path = PathBuf::from("C:/Game").join(path.as_ref());
///
///     if let Some(parent) = output_path.parent() {
///         std::fs::create_dir_all(parent).unwrap();
///     }
///
///     std::fs::write(output_path, file.content).unwrap();
/// }
/// ```
pub fn decrypt_archive(
    data: &[u8],
) -> Result<Vec<DecryptedFile>, ExtractError> {
    Decrypter::new().decrypt(data)
}

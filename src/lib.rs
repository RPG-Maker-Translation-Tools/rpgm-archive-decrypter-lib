//!A decrypter implementation for rpgm-archive-decrypter. Not intended for use in other applications; but can be.

#[cfg(feature = "rayon")]
use rayon::prelude::*;
#[cfg(feature = "rayon")]
use std::sync::{Arc, Mutex};
use std::{
    cell::UnsafeCell,
    fs::{create_dir_all, write},
    path::{Path, PathBuf},
};

#[derive(PartialEq)]
enum Engine {
    Older,
    VXAce,
}

enum SeekFrom {
    Start,
    Current,
}

impl std::fmt::Display for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let variant_name: &str = match self {
            Engine::Older => "XP/VX",
            Engine::VXAce => "VXAce",
        };

        write!(f, "{}", variant_name)
    }
}

struct VecWalker {
    data: Vec<u8>,
    pos: usize,
    len: usize,
}

impl VecWalker {
    pub fn new(data: Vec<u8>) -> Self {
        let len: usize = data.len();
        VecWalker { data, pos: 0, len }
    }

    pub fn advance(&mut self, bytes: usize) -> &[u8] {
        self.pos += bytes;
        &self.data[self.pos - bytes..self.pos]
    }

    pub fn read_chunk(&mut self) -> [u8; 4] {
        let chunk: &[u8] = self.advance(4);
        unsafe { *(chunk.as_ptr() as *const [u8; 4]) }
    }

    pub fn read_byte(&mut self) -> u8 {
        self.pos += 1;
        self.data[self.pos - 1]
    }

    pub fn seek(&mut self, offset: usize, seek_from: SeekFrom) {
        self.pos = match seek_from {
            SeekFrom::Start => offset,
            SeekFrom::Current => self.pos + offset,
        };
    }
}

struct Archive {
    filename: String,
    size: i32,
    offset: usize,
    key: u32,
}

pub struct Decrypter {
    walker: UnsafeCell<VecWalker>,
    key: u32,
    engine: Engine,
}

impl Decrypter {
    /// Creates a new decrypter for specified archive binary data.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            walker: UnsafeCell::new(VecWalker::new(bytes)),
            key: 0xDEADCAFE,
            engine: Engine::Older,
        }
    }

    /// Extracts archive to `output_path`. Does nothing if extracted files already exist and `force` is set to `false`.
    pub fn extract<P: AsRef<Path>>(&mut self, output_path: P, force: bool) -> Result<(), &str> {
        let walker: &mut VecWalker = unsafe { &mut *self.walker.get() };

        let version: u8 = {
            let header: &[u8] = walker.advance(6);

            if header != b"RGSSAD" {
                return Err("Unknown archive header. Expected: RGSSAD.");
            }

            walker.seek(1, SeekFrom::Current);
            walker.read_byte()
        };

        self.engine = if version == 1 {
            Engine::Older
        } else if version == 3 {
            Engine::VXAce
        } else {
            return Err("Unknown archive game engine. Archive is possibly corrupted.");
        };

        let archives: Vec<Archive> = self.read_archive();

        #[cfg(feature = "rayon")]
        let arc: Arc<Mutex<&mut VecWalker>> = Arc::new(Mutex::new(walker));

        #[cfg(feature = "rayon")]
        let archives = archives.into_par_iter();

        #[cfg(not(feature = "rayon"))]
        let archives = archives.into_iter();

        let output_path: &Path = output_path.as_ref();

        archives.for_each(|archive: Archive| {
            let output_path: PathBuf = output_path.join(archive.filename);

            if output_path.exists() && !force {
                println!("Output files already exist. Use --force to forcefully overwrite them.");
                return;
            }

            #[cfg(feature = "rayon")]
            let mut walker = arc.lock().unwrap();

            walker.seek(archive.offset, SeekFrom::Start);
            let data: Vec<u8> = Vec::from(walker.advance(archive.size as usize));

            #[cfg(feature = "rayon")]
            drop(walker);

            let parent_directory: &Path = unsafe { output_path.parent().unwrap_unchecked() };

            if !parent_directory.exists() {
                create_dir_all(parent_directory).unwrap();
            }

            let decrypted: Vec<u8> = Self::decrypt_archive(&data, archive.key);
            write(output_path, decrypted).unwrap();
        });

        Ok(())
    }

    fn decrypt_archive(data: &[u8], mut key: u32) -> Vec<u8> {
        let mut decrypted: Vec<u8> = Vec::with_capacity(data.len());

        let mut key_bytes: [u8; 4] = key.to_le_bytes();
        let mut j: usize = 0;

        for item in data {
            if j == 4 {
                j = 0;
                key = key.wrapping_mul(7).wrapping_add(3);
                key_bytes = key.to_le_bytes();
            }

            decrypted.push(item ^ key_bytes[j]);
            j += 1;
        }

        decrypted
    }

    fn decrypt_integer(&mut self, value: i32) -> i32 {
        let result: i32 = value ^ self.key as i32;

        if self.engine == Engine::Older {
            self.key = self.key.wrapping_mul(7).wrapping_add(3);
        }

        result
    }

    fn decrypt_filename(&mut self, filename: &[u8]) -> String {
        let mut decrypted: Vec<u8> = Vec::with_capacity(filename.len());

        if self.engine == Engine::VXAce {
            let key_bytes: [u8; 4] = self.key.to_le_bytes();
            let mut j: usize = 0;

            for item in filename {
                if j == 4 {
                    j = 0;
                }

                decrypted.push(item ^ key_bytes[j]);
                j += 1;
            }
        } else {
            for item in filename {
                decrypted.push(item ^ (self.key & 0xff) as u8);
                self.key = self.key.wrapping_mul(7).wrapping_add(3);
            }
        }

        String::from_utf8(decrypted).unwrap()
    }

    fn read_archive(&mut self) -> Vec<Archive> {
        let walker: &mut VecWalker = unsafe { &mut *self.walker.get() };

        if self.engine == Engine::VXAce {
            // 0xDEADCAFE key is not ever used and overwritten.
            self.key = u32::from_le_bytes(walker.read_chunk())
                .wrapping_mul(9)
                .wrapping_add(3);
        }

        let mut archives: Vec<Archive> = Vec::with_capacity(1024);

        loop {
            let (filename, size, offset, key) = if self.engine == Engine::VXAce {
                let offset: usize =
                    self.decrypt_integer(i32::from_le_bytes(walker.read_chunk())) as usize;

                let size: i32 = self.decrypt_integer(i32::from_le_bytes(walker.read_chunk()));

                let key: u32 = self.decrypt_integer(i32::from_le_bytes(walker.read_chunk())) as u32;

                let length: i32 = self.decrypt_integer(i32::from_le_bytes(walker.read_chunk()));

                if offset == 0 {
                    break;
                }

                let filename: String = self.decrypt_filename(walker.advance(length as usize));

                (filename, size, offset, key)
            } else {
                let length: i32 = self.decrypt_integer(i32::from_le_bytes(walker.read_chunk()));

                let filename: String = self.decrypt_filename(walker.advance(length as usize));

                let size: i32 = self.decrypt_integer(i32::from_le_bytes(walker.read_chunk()));

                let offset: usize = walker.pos;

                let key: u32 = self.key;

                walker.seek(size as usize, SeekFrom::Current);

                if walker.pos == walker.len {
                    break;
                }

                (filename, size, offset, key)
            };

            archives.push(Archive {
                filename,
                size,
                offset,
                key,
            });
        }

        archives
    }
}

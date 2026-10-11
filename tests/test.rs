use marshal_rs::load;
use rpgmad_lib::{ArchiveEntry, Decrypter, Engine};
use std::{fs::read, path::PathBuf};

fn is_valid_png(buf: &[u8]) -> bool {
    buf.starts_with(b"\x89PNG\r\n\x1a\n")
}

fn is_decrypted_valid<'a>(decrypted_entries: &[ArchiveEntry<'a>]) -> Result<(), String> {
    for entry in decrypted_entries {
        let path = std::str::from_utf8(&entry.path).unwrap();
        let ext = path.rsplit_once('.').unwrap().1;

        if ["rvdata", "rxdata", "rvdata2"].contains(&ext) {
            if load(&entry.data).is_err() {
                return Err(format!(
                    "Decrypting RPG Maker data file {} failed.",
                    PathBuf::from(String::from_utf8_lossy(&entry.path).into_owned()).display()
                ));
            }
        } else if ext == "png" && !is_valid_png(&entry.data) {
            return Err(format!(
                "Decrypting RPG Maker image {} failed.",
                PathBuf::from(String::from_utf8_lossy(&entry.path).into_owned()).display()
            ));
        };
    }

    Ok(())
}

#[test]
fn decrypt_vxace() {
    let archive_path = PathBuf::from("./tests/Game.rgss3a");
    let mut archive_content = read(&archive_path).unwrap();
    let mut decrypter = Decrypter::new();
    let decrypted_files = decrypter.decrypt(&mut archive_content).unwrap();
    let decrypted_files = decrypted_files.collect::<Vec<_>>();
    is_decrypted_valid(&decrypted_files).unwrap();
}

#[test]
fn decrypt_older() {
    let archive_path = PathBuf::from("./tests/Game.rgss2a");
    let mut archive_content = read(&archive_path).unwrap();
    let mut decrypter = Decrypter::new();
    let decrypted_files = decrypter.decrypt(&mut archive_content).unwrap();
    let decrypted_files = decrypted_files.collect::<Vec<_>>();
    is_decrypted_valid(&decrypted_files).unwrap();
}

#[test]
fn encrypt_vxace() {
    let archive_path = PathBuf::from("./tests/Game.rgss3a");
    let mut archive_content = read(&archive_path).unwrap();
    let mut decrypter = Decrypter::new();
    let decrypted_files = decrypter.decrypt(&mut archive_content).unwrap();
    let decrypted_files = decrypted_files.collect::<Vec<_>>();
    is_decrypted_valid(&decrypted_files).unwrap();

    let encrypted_data_size = Decrypter::encrypted_buffer_size(&decrypted_files, Engine::VXAce);
    let mut encrypted = Vec::new();
    encrypted.resize(encrypted_data_size, 0);
    Decrypter::new().encrypt(&decrypted_files, Engine::VXAce, &mut encrypted).unwrap();

    assert!(encrypted.len() == archive_content.len());
}

const TINY_ENTRIES: [ArchiveEntry; 3] = [
    ArchiveEntry {
        path: b"Graphics/a.png",
        data: b"0123456789",
    },
    ArchiveEntry {
        path: b"Data/b.rvdata2",
        data: b"",
    },
    ArchiveEntry { path: b"c", data: b"xyz" },
];

fn tiny_archive(engine: Engine) -> Vec<u8> {
    let mut encrypted = vec![0; Decrypter::encrypted_buffer_size(&TINY_ENTRIES, engine)];
    Decrypter::new().encrypt(&TINY_ENTRIES, engine, &mut encrypted).unwrap();
    encrypted
}

// Found by fuzzing: XP/VX `encrypt` overwrote the path size with the path and left the path unencrypted.
#[test]
fn encrypt_decrypt_round_trip() {
    for engine in [Engine::Older, Engine::VXAce] {
        let mut encrypted = tiny_archive(engine);
        let mut decrypter = Decrypter::new();
        let decrypted = decrypter.decrypt(&mut encrypted).unwrap().collect::<Vec<_>>();

        assert_eq!(decrypted.len(), TINY_ENTRIES.len());
        for (got, expected) in decrypted.iter().zip(&TINY_ENTRIES) {
            assert_eq!((got.path, got.data), (expected.path, expected.data));
        }
    }
}

// Found by fuzzing: an empty or cut-off archive used to panic with an out-of-range slice.
#[test]
fn malformed_archives_do_not_panic() {
    assert!(matches!(
        Decrypter::new().start(&mut []),
        Err(rpgmad_lib::ExtractError::Truncated)
    ));

    for engine in [Engine::Older, Engine::VXAce] {
        let archive = tiny_archive(engine);

        for len in 0..archive.len() {
            let mut prefix = archive[..len].to_vec();
            let mut decrypter = Decrypter::new();
            if decrypter.start(&mut prefix).is_ok() {
                while decrypter.next_entry().is_some() {}
            }
        }

        // Every table field set to the maximum.
        for pos in 8..archive.len() {
            let mut corrupted = archive.clone();
            corrupted[pos..].iter_mut().take(4).for_each(|byte| *byte = 0xFF);
            let mut decrypter = Decrypter::new();
            if decrypter.start(&mut corrupted).is_ok() {
                while decrypter.next_entry().is_some() {}
            }
        }
    }
}

#[test]
fn encrypt_older() {
    let archive_path = PathBuf::from("./tests/Game.rgss2a");
    let mut archive_content = read(&archive_path).unwrap();
    let mut decrypter = Decrypter::new();
    let decrypted_files = decrypter.decrypt(&mut archive_content).unwrap();
    let decrypted_files = decrypted_files.collect::<Vec<_>>();
    is_decrypted_valid(&decrypted_files).unwrap();

    let encrypted_data_size = Decrypter::encrypted_buffer_size(&decrypted_files, Engine::Older);
    let mut encrypted = Vec::new();
    encrypted.resize(encrypted_data_size, 0);
    Decrypter::new().encrypt(&decrypted_files, Engine::Older, &mut encrypted).unwrap();

    assert!(archive_content.len() == encrypted.len());
}

#[test]
fn encrypt_rejects_small_buffer() {
    for engine in [Engine::Older, Engine::VXAce] {
        let mut encrypted = vec![0; Decrypter::encrypted_buffer_size(&TINY_ENTRIES, engine) - 1];

        assert!(matches!(
            Decrypter::new().encrypt(&TINY_ENTRIES, engine, &mut encrypted),
            Err(rpgmad_lib::EncryptError::BufferTooSmall)
        ));
    }
}

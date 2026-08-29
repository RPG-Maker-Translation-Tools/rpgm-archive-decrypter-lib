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
    let _ = Decrypter::new().encrypt(&decrypted_files, Engine::VXAce, &mut encrypted);

    assert!(encrypted.len() == archive_content.len());
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
    let _ = Decrypter::new().encrypt(&decrypted_files, Engine::Older, &mut encrypted);

    assert!(archive_content.len() == encrypted.len());
}

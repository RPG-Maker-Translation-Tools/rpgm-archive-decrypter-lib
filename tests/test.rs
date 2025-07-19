use marshal_rs::load;
use png::Decoder;
use rpgmad_lib::{DecryptedFile, decrypt_archive};
use std::{env::var, fs::read, path::PathBuf};

fn is_png_valid(buf: &[u8]) -> bool {
    Decoder::new(buf).read_info().is_ok()
}

fn is_decrypted_valid(decrypted_files: Vec<DecryptedFile>) -> bool {
    for file in decrypted_files {
        let path = std::str::from_utf8(&file.path).unwrap();
        let ext = path.rsplit_once('.').unwrap().1;

        if ["rvdata", "rxdata", "rvdata2"].contains(&ext) {
            if load(&file.content, None).is_err() {
                println!("failed 1");
                return false;
            }
        } else if ext == "png" && !is_png_valid(&file.content) {
            println!("failed 2");
            return false;
        };
    }

    true
}

#[test]
fn rgss3a() {
    let archive_path = PathBuf::from(var("RGSS3A_PATH").unwrap());
    let archive_content = read(&archive_path).unwrap();
    let decrypted_files = decrypt_archive(&archive_content).unwrap();
    assert!(is_decrypted_valid(decrypted_files))
}

#[test]
fn rgss2a() {
    let archive_path = PathBuf::from(var("RGSS2A_PATH").unwrap());
    let archive_content = read(&archive_path).unwrap();
    let decrypted_files = decrypt_archive(&archive_content).unwrap();
    assert!(is_decrypted_valid(decrypted_files))
}

#[test]
fn rgssad() {
    let archive_path = PathBuf::from(var("RGSSAD_PATH").unwrap());
    let archive_content = read(&archive_path).unwrap();
    let decrypted_files = decrypt_archive(&archive_content).unwrap();
    assert!(is_decrypted_valid(decrypted_files))
}

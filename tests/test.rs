use marshal_rs::load;
use png::Decoder;
use rpgmad_lib::extract_archive;
use std::{env::var, fs::read, path::PathBuf};

fn is_valid_png(buf: &[u8]) {
    let decoder = Decoder::new(buf);
    let reader = decoder.read_info();

    reader.unwrap();
}

#[test]
fn rgss3a() {
    let archive_path = PathBuf::from(var("RGSS3A_PATH").unwrap());
    let archive_dir = archive_path.parent().unwrap();
    let archive_content = read(&archive_path).unwrap();

    extract_archive(
        &archive_content,
        archive_dir.join("decrypted_archive"),
        true,
    )
    .unwrap();

    if let Some(file) = std::fs::read_dir(archive_dir.join("decrypted_archive/Data"))
        .unwrap()
        .flatten()
        .next()
    {
        let path = file.path();
        let content = std::fs::read(path).unwrap();
        load(&content, None).unwrap();
    }

    if let Some(dir) = std::fs::read_dir(archive_dir.join("decrypted_archive/Graphics"))
        .unwrap()
        .flatten()
        .next()
    {
        if let Some(image) = std::fs::read_dir(dir.path()).unwrap().flatten().next() {
            let image_content = std::fs::read(image.path()).unwrap();
            is_valid_png(&image_content);
        }
    }
}

#[test]
fn rgss2a() {
    let archive_path = PathBuf::from(var("RGSS2A_PATH").unwrap());
    let archive_dir = archive_path.parent().unwrap();
    let archive_content = read(&archive_path).unwrap();

    extract_archive(
        &archive_content,
        archive_dir.join("decrypted_archive"),
        true,
    )
    .unwrap();

    if let Some(file) = std::fs::read_dir(archive_dir.join("decrypted_archive/Data"))
        .unwrap()
        .flatten()
        .next()
    {
        let path = file.path();
        let content = std::fs::read(path).unwrap();
        load(&content, None).unwrap();
    }

    if let Some(dir) = std::fs::read_dir(archive_dir.join("decrypted_archive/Graphics"))
        .unwrap()
        .flatten()
        .next()
    {
        if let Some(image) = std::fs::read_dir(dir.path()).unwrap().flatten().next() {
            let image_content = std::fs::read(image.path()).unwrap();
            is_valid_png(&image_content);
        }
    }
}

#[test]
fn rgssad() {
    let archive_path = PathBuf::from(var("RGSSAD_PATH").unwrap());
    let archive_dir = archive_path.parent().unwrap();
    let archive_content = read(&archive_path).unwrap();

    extract_archive(
        &archive_content,
        archive_dir.join("decrypted_archive"),
        true,
    )
    .unwrap();

    if let Some(file) = std::fs::read_dir(archive_dir.join("decrypted_archive/Data"))
        .unwrap()
        .flatten()
        .next()
    {
        let path = file.path();
        let content = std::fs::read(path).unwrap();
        load(&content, None).unwrap();
    }

    if let Some(dir) = std::fs::read_dir(archive_dir.join("decrypted_archive/Graphics"))
        .unwrap()
        .flatten()
        .next()
    {
        if let Some(image) = std::fs::read_dir(dir.path()).unwrap().flatten().next() {
            let image_content = std::fs::read(image.path()).unwrap();
            is_valid_png(&image_content);
        }
    }
}

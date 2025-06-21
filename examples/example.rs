use rpgmad_lib::{extract_archive, Decrypter};

fn main() {
    // Using Decrypter struct
    let archive_content: Vec<u8> = std::fs::read("C:/Game/Game.rgss3a").unwrap();
    let mut decrypter = Decrypter::new();

    // You can optionally set force
    // decrypter.set_force(true)

    decrypter.extract(&archive_content, "C:/Game").unwrap();

    // Using function
    let force = false; // When `true`, it will overwrite existing files in the game directory.
    extract_archive(&archive_content, "C:/Game", force).unwrap();
}

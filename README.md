# rpgm-archive-decrypter-lib

**BLAZINGLY** :fire: fast and tiny library for decrypting RPG Maker XP/VX/VXAce `.rgssad`/`.rgss2a`/`.rgss3a` archives.

This project essentially is a rewrite of uuksu's [RPGMakerDecrypter](https://github.com/uuksu/RPGMakerDecrypter) in Rust as a library, but it also implements archive encryption.

And since it's implemented in Rust 🦀🦀🦀, it's also very tiny, clean, and performant.

Used in my [rpgm-archive-decrypter](https://github.com/savannstm/rpgm-archive-decrypter) CLI tool.

## Example

### Decrypt

```rust no_run
use rpgmad_lib::{Decrypter, decrypt_archive};
use std::{path::PathBuf, fs::{read, write, create_dir_all}};

let archive_content: Vec<u8> = read("C:/Game/Game.rgss3a").unwrap();

// Using Decrypter struct
let mut decrypter = Decrypter::new();
let decrypted_entries = decrypter.decrypt(&archive_content).unwrap();

// Using function
let decrypted_entries = decrypt_archive(&archive_content).unwrap();

for entry in decrypted_entries {
    let path = String::from_utf8_lossy(&entry.path);
    let output_path = PathBuf::from("C:/Game").join(path.as_ref());

    if let Some(parent) = output_path.parent() {
        create_dir_all(parent).unwrap();
    }

    write(output_path, entry.data).unwrap();
}
```

### Encrypt

```rust no_run
use rpgmad_lib::{Decrypter, encrypt_archive, ArchiveEntry, Engine};
use std::{fs::{read, write}, borrow::Cow};

let archive_entries = [ArchiveEntry {
    path: Cow::Borrowed(b"Graphics/Tilesets/Tileset1.png"),
    data: read("Graphics/Tilesets/Tileset1.png").unwrap()
}];

// Using Decrypter struct
let mut decrypter = Decrypter::new();
let archive_data = decrypter.encrypt(&archive_entries, Engine::VXAce);

// Using function
let archive_data = encrypt_archive(&archive_entries, Engine::VXAce);

write("./Game.rgss3a", archive_data).unwrap();
```

## License

Project is licensed under WTFPL.

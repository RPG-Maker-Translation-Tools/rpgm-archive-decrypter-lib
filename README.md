# rpgm-archive-decrypter-lib

Library for decrypting RPG Maker `rgss` archives.

Used in [rpgm-archive-decrypter](https://github.com/savannstm/rpgm-archive-decrypter).

## Example

```rust
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

# rpgm-archive-decrypter-lib

**BLAZINGLY** :fire: fast and tiny library for decrypting RPG Maker XP/VX/VXAce `.rgssad`/`.rgss2a`/`.rgss3a` archives.

This project essentially is a rewrite of uuksu's [RPGMakerDecrypter](https://github.com/uuksu/RPGMakerDecrypter) in Rust as a library, but it also implements archive encryption, **and** can be run in no_std environments.

And since it's implemented in Rust 🦀🦀🦀, it's also very tiny, clean, and performant.

Used in my [rpgm-archive-decrypter](https://github.com/RPG-Maker-Translation-Tools/rpgm-archive-decrypter) CLI tool and [RPGMTranslate](https://github.com/RPG-Maker-Translation-Tools/rpgmtranslate-qt).

## Example

### Decrypt

```rust no_run
use rpgmad_lib::{Decrypter};
use std::{path::PathBuf, fs::{read, write, create_dir_all}};

let mut archive_content: Vec<u8> = read("C:/Game/Game.rgss3a").unwrap();

let mut decrypter = Decrypter::new();
let decrypted_entries = decrypter.decrypt(&mut archive_content).unwrap();

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
use rpgmad_lib::{Decrypter, ArchiveEntry, Engine};
use std::{fs::{read, write}, borrow::Cow};

let data = read("Graphics/Tilesets/Tileset1.png").unwrap();
let archive_entries = [ArchiveEntry {
    path: b"Graphics/Tilesets/Tileset1.png",
    data: &data
}];

let mut decrypter = Decrypter::new();

let encrypted_buffer_size = Decrypter::encrypted_buffer_size(&archive_entries, Engine::VXAce);
let mut archive_buffer = Vec::new();
archive_buffer.resize(encrypted_buffer_size, 0);

decrypter.encrypt(&archive_entries, Engine::VXAce, &mut archive_buffer);

write("./Game.rgss3a", archive_buffer).unwrap();
```

## Features

- `default` - default feature enables the usage of `std`. If you're using this crate in a `no_std` environment for some reason, you need to disable default feature.
- `serde` - enables serde serialization/deserialization for `Error` type.

## Support

[Me](https://github.com/savannstm), the maintainer of this project, is a poor college student from Eastern Europe.

If you could, please consider supporting us through:

- [Ko-fi](https://ko-fi.com/savannstm)
- [Patreon](https://www.patreon.com/cw/savannstm)
- [Boosty](https://boosty.to/mcdeimos)

Even if you don't, it's fine. We'll continue to do as we right now.

## License

Project is licensed under WTFPL.

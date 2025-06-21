# rpgm-archive-decrypter-lib

Library for decrypting RPG Maker `rgss` archives.

Used in [rpgm-archive-decrypter](https://github.com/savannstm/rpgm-archive-decrypter).

## Example

```rust
use rpgmad_lib::{Decrypter, extract_archive};

// Using Decrypter struct
let archive_content: Vec<u8> = std::fs::read("C:/Game/Game.rgss3a").unwrap();
let mut decrypter = Decrypter::new();

// You can optionally set force
// decrypter.set_force(true)

decrypter.extract(&archive_content, "C:/Game").unwrap();

// Using function
// let force = false; // When `true`, it will overwrite existing files in the game directory.
// extract_archive(&archive_content, "C:/Game", force).unwrap();
```

## License

Project is licensed under WTFPL.

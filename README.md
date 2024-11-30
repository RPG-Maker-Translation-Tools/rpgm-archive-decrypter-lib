# rpgm-archive-decrypter-lib

A decrypter implementation for [rpgm-archive-decrypter](https://github.com/savannstm/rpgm-archive-decrypter).
Not intended for use in other applications; but can be.

## Quick example

```rust
let archive_bytes = std::fs::read("C:/Documents/Game/Game.rgssad");
let mut decrypter = rpgmad_lib::Decrypter::new();

// Writes decrypted game files to "C:/Documents/Game"
decrypter.decrypt("C:/Documents/Game", false).unwrap()
```

## License

Project is licensed under WTFPL.

//! Writes tiny valid archives of both engines into the fuzz corpus. Mutating a few dozen bytes reaches the
//! entry-table fields far faster than mutating the 400+ KB real archives.
//! Run from `fuzz/`: `cargo run --example make_seeds`
use rpgmad_lib::{ArchiveEntry, Decrypter, Engine};

fn main() {
    let entries = [
        ArchiveEntry {
            path: b"Graphics/a.png",
            data: b"0123456789",
        },
        ArchiveEntry {
            path: b"Data/b.rvdata2",
            data: b"",
        },
        ArchiveEntry {
            path: b"c",
            data: b"xyz",
        },
    ];

    std::fs::create_dir_all("corpus/decrypt").unwrap();

    for (engine, name) in [(Engine::Older, "tiny_older"), (Engine::VXAce, "tiny_vxace")] {
        let mut buffer = vec![0; Decrypter::encrypted_buffer_size(&entries, engine)];
        Decrypter::new().encrypt(&entries, engine, &mut buffer);
        std::fs::write(format!("corpus/decrypt/{name}"), buffer).unwrap();
    }
}

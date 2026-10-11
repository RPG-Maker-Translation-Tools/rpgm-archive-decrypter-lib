#![no_main]
use libfuzzer_sys::fuzz_target;
use rpgmad_lib::{ArchiveEntry, Decrypter, Engine};

fn entries_of(buffer: &mut [u8]) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut decrypter = Decrypter::new();
    decrypter.start(buffer).ok()?;

    let mut entries = Vec::new();
    while let Some(entry) = decrypter.next_entry() {
        entries.push((entry.path.to_vec(), entry.data.to_vec()));
    }
    Some(entries)
}

fuzz_target!(|data: &[u8]| {
    let mut buffer = data.to_vec();
    let Some(entries) = entries_of(&mut buffer) else {
        return;
    };

    let borrowed: Vec<_> = entries
        .iter()
        .map(|(path, data)| ArchiveEntry { path, data })
        .collect();

    for engine in [Engine::Older, Engine::VXAce] {
        let mut encrypted = vec![0; Decrypter::encrypted_buffer_size(&borrowed, engine)];
        Decrypter::new().encrypt(&borrowed, engine, &mut encrypted);

        // Printed on failure: libFuzzer can't write the crashing input on Windows, see fuzz.ps1.
        let again = entries_of(&mut encrypted.clone())
            .unwrap_or_else(|| panic!("{engine}: own output must parse.\ninput: {data:?}\nentries: {entries:?}\nencrypted: {encrypted:?}"));
        assert!(again == entries, "{engine} round trip changed the entries.\ninput: {data:?}");
    }
});

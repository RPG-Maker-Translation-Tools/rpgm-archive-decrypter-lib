#![no_main]
use libfuzzer_sys::fuzz_target;
use rpgmad_lib::Decrypter;

fuzz_target!(|data: &[u8]| {
    // The decrypter works in place, so it needs an owned mutable copy.
    let mut buf = data.to_vec();
    let mut decrypter = Decrypter::new();
    if decrypter.start(&mut buf).is_ok() {
        while let Some(entry) = decrypter.next_entry() {
            std::hint::black_box((entry.path, entry.data));
        }
    }
});

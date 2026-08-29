# rpgmard-wasm

WebAssembly bindings for [`rpgmad-lib`](https://github.com/RPG-Maker-Translation-Tools/rpgm-archive-decrypter-lib), generated via [`wasm-bindgen`](https://github.com/rustwasm/wasm-bindgen). A thin wrapper around the Rust reference implementation - useful when you want behavior guaranteed identical to the Rust crate without a second, hand-maintained implementation.

## Install

```bash
npm install rpgmard-wasm
```

## API

Two functions (see [`src/lib.rs`](https://github.com/RPG-Maker-Translation-Tools/rpgm-archive-decrypter-lib/blob/master/crates/rpgmard-wasm/src/lib.rs) for full doc comments):

```ts
function decryptArchive(archiveData: Uint8Array): ArchiveEntry[];
function encryptArchive(entries: ArchiveEntry[], engine: Engine): Uint8Array;
```

plus the `ArchiveEntry` class (`path`/`data`, both `Uint8Array`) and the `Engine` enum (`Older = 1`, `VXAce = 3`) - `Older` covers RPG Maker XP/VX's `.rgssad`/`.rgss2a`, `VXAce` covers VX Ace's `.rgss3a`.

The reference `Decrypter::decrypt` returns an iterator borrowing its input buffer - that can't cross the JS/WASM call boundary (a call only lives for the duration of the call), so these two functions copy data in and out instead: `decryptArchive` takes ownership of the input and returns independent, owned entries; `encryptArchive` returns a freshly-allocated archive buffer.

## Usage

```ts
import init, { decryptArchive, Engine } from "rpgmard-wasm";

await init(); // instantiates the wasm module - do this once, before first use

const archiveData = new Uint8Array(await Deno.readFile("Game.rgss3a"));

for (const entry of decryptArchive(archiveData)) {
    console.log(new TextDecoder().decode(entry.path));
}
```

`encryptArchive` goes the other way, packing entries back into an archive for a given engine:

```ts
import init, { encryptArchive, ArchiveEntry, Engine } from "rpgmard-wasm";

await init();

const entries = [new ArchiveEntry(new TextEncoder().encode("Data/Scripts.rvdata2"), scriptBytes)];
const archiveData = encryptArchive(entries, Engine.VXAce);
```

Under Node/Bun, `init()`'s default `fetch()`-based loading doesn't apply - pass the `.wasm` bytes explicitly instead:

```ts
import { readFile } from "node:fs/promises";
import init, { decryptArchive } from "rpgmard-wasm";

await init(
  await readFile(new URL("./rpgmard_wasm_bg.wasm", import.meta.resolve("rpgmard-wasm"))),
);
```

## Building

```bash
wasm-pack build --release --target web
```

Requires the `wasm32-unknown-unknown` rustup target (`rustup target add wasm32-unknown-unknown`) and `wasm-pack` (`cargo binstall wasm-pack`). Output goes to `pkg/` (gitignored): the compiled `.wasm`, a JS glue module, a `.d.ts`, and the `package.json` this crate publishes to npm from.

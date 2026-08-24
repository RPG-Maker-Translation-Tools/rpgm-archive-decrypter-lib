# rpgmard-wasm

WebAssembly bindings for [`rpgmad-lib`](..), generated via [`wasm-bindgen`](https://github.com/rustwasm/wasm-bindgen). A thin wrapper around the Rust reference implementation - useful when you want behavior guaranteed identical to the Rust crate without a second, hand-maintained implementation.

## API

Two functions (see [`src/lib.rs`](src/lib.rs) for full doc comments):

```ts
function decryptArchive(archiveData: Uint8Array): ArchiveEntry[];
function encryptArchive(entries: ArchiveEntry[], engine: Engine): Uint8Array;
```

plus the `ArchiveEntry` class (`path`/`data`, both `Uint8Array`) and the `Engine` enum (`Older = 1`, `VXAce = 3`).

The reference `Decrypter::decrypt` returns an iterator borrowing its input buffer - that can't cross the JS/WASM call boundary (a call only lives for the duration of the call), so these two functions copy data in and out instead: `decryptArchive` takes ownership of the input and returns independent, owned entries; `encryptArchive` returns a freshly-allocated archive buffer.

## Building

```bash
wasm-pack build --release --target web
```

Requires the `wasm32-unknown-unknown` rustup target (`rustup target add wasm32-unknown-unknown`) and `wasm-pack` (`cargo binstall wasm-pack`). Output goes to `pkg/` (gitignored): the compiled `.wasm`, a JS glue module, and a `.d.ts`.

## Usage

```ts
import init, { decryptArchive, Engine } from "./pkg/rpgmard_wasm.js";

await init(); // instantiates the wasm module - do this once, before first use

const archiveData = new Uint8Array(await Deno.readFile("Game.rgss3a"));

for (const entry of decryptArchive(archiveData)) {
    console.log(new TextDecoder().decode(entry.path));
}
```

Under Node/Bun, `init()`'s default `fetch()`-based loading doesn't apply - pass the `.wasm` bytes explicitly instead:

```ts
import { readFile } from "node:fs/promises";
await init(await readFile(new URL("./pkg/rpgmard_wasm_bg.wasm", import.meta.url)));
```

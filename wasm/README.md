# rpgmard-wasm

WebAssembly bindings for [`rpgmad-lib`](https://github.com/RPG-Maker-Translation-Tools/rpgm-archive-decrypter-lib): decrypt and encrypt RPG Maker `rgss` archives.

## Install

```bash
npm install rpgmard-wasm
```

## API

```ts
function decryptArchive(archiveData: Uint8Array): ArchiveEntry[];
function encryptArchive(entries: ArchiveEntry[], engine: Engine): Uint8Array;
```

Plus the `ArchiveEntry` class (`path` and `data`, both `Uint8Array`) and the `Engine` enum: `Older = 1` for RPG Maker XP/VX (`.rgssad`/`.rgss2a`), `VXAce = 3` for VX Ace (`.rgss3a`). Data is copied in and out, so entries are independent values.

## Usage

```ts
import init, { decryptArchive, Engine } from "rpgmard-wasm";

await init(); // instantiates the wasm module - do this once, before first use

const archiveData = new Uint8Array(await Deno.readFile("Game.rgss3a"));

for (const entry of decryptArchive(archiveData)) {
    console.log(new TextDecoder().decode(entry.path));
}
```

Packing entries back into an archive:

```ts
import init, { encryptArchive, ArchiveEntry, Engine } from "rpgmard-wasm";

await init();

const entries = [new ArchiveEntry(new TextEncoder().encode("Data/Scripts.rvdata2"), scriptBytes)];
const archiveData = encryptArchive(entries, Engine.VXAce);
```

Under Node/Bun, pass the `.wasm` bytes to `init()` explicitly:

```ts
import { readFile } from "node:fs/promises";
import init, { decryptArchive } from "rpgmard-wasm";

await init(
  await readFile(new URL("./rpgmard_wasm_bg.wasm", import.meta.resolve("rpgmard-wasm"))),
);
```

## Build from source

```bash
wasm-pack build --release --target web   # output in pkg/
```

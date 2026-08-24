# rpgmad-lib

Library for decrypting/encrypting RPG Maker XP/VX/VXAce `.rgssad`/`.rgss2a`/`.rgss3a` archives.

TypeScript port of the [`rpgmad-lib`](https://github.com/savannstm/rpgm-archive-decrypter-lib) Rust crate, kept behaviorally identical to that reference implementation. Operates on `Uint8Array` buffers in place wherever possible, mirroring the Rust crate's zero-copy design.

Used in my [rpgm-archive-decrypter](https://github.com/RPG-Maker-Translation-Tools/rpgm-archive-decrypter) CLI tool and [RPGMTranslate](https://github.com/RPG-Maker-Translation-Tools/rpgmtranslate-qt).

Pure `Uint8Array`/`DataView`, no runtime-specific APIs - works the same under Node, Bun, and Deno.

## Install

```bash
npm install rpgmad-lib
# or
bun add rpgmad-lib
# or
deno add npm:rpgmad-lib
```

## Example

### Decrypt

```ts
import { Decrypter } from "rpgmad-lib";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";

const archiveData = new Uint8Array(await readFile("C:/Game/Game.rgss3a"));
const decrypter = new Decrypter();

for (const entry of decrypter.decrypt(archiveData)) {
    const path = new TextDecoder().decode(entry.path);
    const outputPath = join("C:/Game", path);

    await mkdir(dirname(outputPath), { recursive: true });
    await writeFile(outputPath, entry.data);
}
```

### Encrypt

```ts
import { ArchiveEntry, Decrypter, Engine } from "rpgmad-lib";
import { readFile, writeFile } from "node:fs/promises";

const data = new Uint8Array(await readFile("Graphics/Tilesets/Tileset1.png"));
const archiveEntries: ArchiveEntry[] = [{ path: new TextEncoder().encode("Graphics/Tilesets/Tileset1.png"), data }];

const decrypter = new Decrypter();

const size = Decrypter.encryptedBufferSize(archiveEntries, Engine.VXAce);
const archiveBuffer = new Uint8Array(size);

decrypter.encrypt(archiveEntries, Engine.VXAce, archiveBuffer);

await writeFile("./Game.rgss3a", archiveBuffer);
```

## Support

[Me](https://github.com/savannstm), the maintainer of this project, is a poor college student from Eastern Europe.

If you could, please consider supporting us through:

- [Ko-fi](https://ko-fi.com/savannstm)
- [Patreon](https://www.patreon.com/cw/savannstm)
- [Boosty](https://boosty.to/mcdeimos)

Even if you don't, it's fine. We'll continue to do as we right now.

## License

Project is licensed under WTFPL.

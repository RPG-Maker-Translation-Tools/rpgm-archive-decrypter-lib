import assert from "node:assert/strict";
import test from "node:test";
import { Decrypter, Engine, InvalidEngineError, InvalidHeaderError } from "../src/index.ts";
import type { ArchiveEntry } from "../src/index.ts";

const encoder = new TextEncoder();

function makeEntries(): ArchiveEntry[] {
    return [
        { path: encoder.encode("Graphics/Tilesets/Tileset1.png"), data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9]) },
        { path: encoder.encode("Data/Actors.rvdata2"), data: new Uint8Array(300).map((_, i) => i % 256) },
        { path: encoder.encode("Audio/BGM/Theme.ogg"), data: new Uint8Array(0) },
    ];
}

function roundTrip(engine: Engine): void {
    const entries = makeEntries();

    const size = Decrypter.encryptedBufferSize(entries, engine);
    const buffer = new Uint8Array(size);
    new Decrypter().encrypt(entries, engine, buffer);

    const decrypted = [...new Decrypter().decrypt(buffer)];

    assert.equal(decrypted.length, entries.length);

    for (let i = 0; i < entries.length; i++) {
        assert.deepEqual(decrypted[i]!.path, entries[i]!.path);
        assert.deepEqual(decrypted[i]!.data, entries[i]!.data);
    }
}

test("round-trips VX Ace archives", () => {
    roundTrip(Engine.VXAce);
});

test("round-trips XP/VX archives", () => {
    roundTrip(Engine.Older);
});

test("produces a byte-identical XP/VX archive on re-encryption", () => {
    const entries = makeEntries();

    const size = Decrypter.encryptedBufferSize(entries, Engine.Older);
    const original = new Uint8Array(size);
    new Decrypter().encrypt(entries, Engine.Older, original);

    const roundTripBuffer = original.slice();
    const decrypted = [...new Decrypter().decrypt(roundTripBuffer)];

    const reEncrypted = new Uint8Array(size);
    new Decrypter().encrypt(decrypted, Engine.Older, reEncrypted);

    assert.deepEqual(reEncrypted, original);
});

test("rejects an invalid header", () => {
    const buffer = encoder.encode("NOTANARCHIVE");
    assert.throws(() => new Decrypter().decrypt(buffer), InvalidHeaderError);
});

test("rejects an invalid engine byte", () => {
    const buffer = new Uint8Array([...encoder.encode("RGSSAD\0"), 9]);
    assert.throws(() => new Decrypter().decrypt(buffer), InvalidEngineError);
});

test("decrypted entries are views into the source buffer (zero-copy)", () => {
    const entries = makeEntries();

    const size = Decrypter.encryptedBufferSize(entries, Engine.VXAce);
    const buffer = new Uint8Array(size);
    new Decrypter().encrypt(entries, Engine.VXAce, buffer);

    const [first] = [...new Decrypter().decrypt(buffer)];
    assert.equal(first!.data.buffer, buffer.buffer);
});

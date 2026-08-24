/**
 * Library for decrypting/encrypting RPG Maker `rgss` archives.
 *
 * TypeScript port of the `rpgmad-lib` Rust crate. Operates on `Uint8Array`
 * buffers in place wherever possible, mirroring the zero-copy design of the
 * reference implementation.
 *
 * @module
 */

const ARCHIVE_HEADER = new Uint8Array([0x52, 0x47, 0x53, 0x53, 0x41, 0x44, 0x00]); // "RGSSAD\0"

const OLDER_DECRYPTION_KEY = 0xdead_cafe;
const ENCRYPTION_KEY = 0;

const U32_SIZE = 4;

export const XP_RGSSAD_EXT = "rgssad";
export const VX_RGSS2A_EXT = "rgss2a";
export const VXACE_RGSS3A_EXT = "rgss3a";

/** Target/source RPG Maker engine of an archive. */
export const Engine = {
    /** RPG Maker XP / VX (`.rgssad` / `.rgss2a`). */
    Older: 1,
    /** RPG Maker VX Ace (`.rgss3a`). */
    VXAce: 3,
} as const;

/** Target/source RPG Maker engine of an archive. */
export type Engine = (typeof Engine)[keyof typeof Engine];

/** Thrown when an archive's header does not match the expected `RGSSAD\0` magic. */
export class InvalidHeaderError extends Error {
    /** The header bytes that were actually read from the archive. */
    readonly header: Uint8Array;

    constructor(header: Uint8Array) {
        super(`Invalid archive file header: [${header.join(", ")}]. Expected: RGSSAD\\0 ([82, 71, 83, 83, 65, 68, 0])`);
        this.name = "InvalidHeaderError";
        this.header = header;
    }
}

/** Thrown when an archive's engine byte is neither `1` (XP/VX) nor `3` (VX Ace). */
export class InvalidEngineError extends Error {
    /** The engine byte that was actually read from the archive. */
    readonly engine: number;

    constructor(engine: number) {
        super(`Invalid game engine byte: ${engine}. Expected \`1\` for XP/VX or \`3\` for VX Ace.`);
        this.name = "InvalidEngineError";
        this.engine = engine;
    }
}

/** Error thrown by {@link Decrypter.decrypt} when parsing an archive header fails. */
export type ExtractError = InvalidHeaderError | InvalidEngineError;

/** A single decrypted file extracted from an archive. */
export interface ArchiveEntry {
    /**
     * Path to the decrypted file, e.g. `Graphics/Actors/Actor1.png`.
     *
     * Represented as raw bytes because it may contain non-UTF-8 sequences (e.g. Shift-JIS text).
     * It's up to the caller to decode it appropriately.
     */
    path: Uint8Array;
    /** Content of the file. */
    data: Uint8Array;
}

function wrappingMulAdd(key: number, mul: number, add: number): number {
    return (Math.imul(key, mul) + add) >>> 0;
}

/**
 * Decrypts data in place, mirroring the reference key-rotation scheme:
 * every 4 bytes, the key is advanced by `key = key * 7 + 3 (mod 2^32)`.
 */
function xorData(key: number, data: Uint8Array): void {
    const keyBytes = new Uint8Array(4);
    new DataView(keyBytes.buffer).setUint32(0, key, true);
    let keyBytePos = 0;

    for (let idx = 0; idx < data.length; idx++) {
        if (keyBytePos === 4) {
            keyBytePos = 0;
            key = wrappingMulAdd(key, 7, 3);
            new DataView(keyBytes.buffer).setUint32(0, key, true);
        }

        data[idx]! ^= keyBytes[keyBytePos]!;
        keyBytePos++;
    }
}

/** A struct responsible for decrypting and extracting files from encrypted game archives. */
export class Decrypter {
    private engine: Engine = Engine.Older;
    private key: number = OLDER_DECRYPTION_KEY;
    private keyBytes: Uint8Array = new Uint8Array(4);

    private data: Uint8Array = new Uint8Array(0);
    private view: DataView = new DataView(new ArrayBuffer(0));
    private pos = 0;
    private len = 0;

    /** Creates a new {@link Decrypter} with an empty buffer. */
    constructor() {
        this.writeKeyBytes();
    }

    private writeKeyBytes(): void {
        new DataView(this.keyBytes.buffer).setUint32(0, this.key, true);
    }

    private updateKey(newKey: number): void {
        this.key = newKey >>> 0;
        this.writeKeyBytes();
    }

    private updateKeyOlder(): void {
        this.updateKey(wrappingMulAdd(this.key, 7, 3));
    }

    private updateKeyVxAce(): void {
        this.updateKey(wrappingMulAdd(this.key, 9, 3));
    }

    private readBytes(count: number): Uint8Array {
        const bytes = this.data.subarray(this.pos, this.pos + count);
        this.pos += count;
        return bytes;
    }

    private readU32(): number {
        const value = this.view.getUint32(this.pos, true);
        this.pos += U32_SIZE;
        return value;
    }

    private readByte(): number {
        return this.data[this.pos++]!;
    }

    private seekStart(offset: number): void {
        this.pos = offset;
    }

    private seekCurrent(offset: number): void {
        this.pos += offset;
    }

    /** Decrypts a `u32` if it's encrypted, encrypts it if it's decrypted. */
    private xorU32VxAce(value: number): number {
        return (value ^ this.key) >>> 0;
    }

    /** Decrypts a `u32` if it's encrypted, encrypts it if it's decrypted. */
    private xorU32Older(value: number): number {
        const decrypted = (value ^ this.key) >>> 0;

        if (this.engine === Engine.Older) {
            this.updateKeyOlder();
        }

        return decrypted;
    }

    /** Decrypts a path in place if it's encrypted, encrypts it in place if it's decrypted. */
    private xorPathVxAce(pathData: Uint8Array): void {
        for (let idx = 0; idx < pathData.length; idx++) {
            pathData[idx]! ^= this.keyBytes[idx % 4]!;
        }
    }

    /** Decrypts a path in place if it's encrypted, encrypts it in place if it's decrypted. */
    private xorPathOlder(pathData: Uint8Array): void {
        for (let idx = 0; idx < pathData.length; idx++) {
            pathData[idx]! ^= this.key & 0xff;
            this.updateKeyOlder();
        }
    }

    private parseHeader(): void {
        const header = this.readBytes(ARCHIVE_HEADER.length);

        for (let idx = 0; idx < ARCHIVE_HEADER.length; idx++) {
            if (header[idx] !== ARCHIVE_HEADER[idx]) {
                throw new InvalidHeaderError(header.slice());
            }
        }

        const engineByte = this.readByte();

        switch (engineByte) {
            case Engine.Older:
                this.engine = Engine.Older;
                break;
            case Engine.VXAce:
                this.engine = Engine.VXAce;
                break;
            default:
                throw new InvalidEngineError(engineByte);
        }
    }

    private *decryptEntries(): Generator<ArchiveEntry> {
        if (this.engine === Engine.VXAce) {
            // Default key is not ever used and overwritten.
            const key = this.readU32();
            this.updateKey(key);
            this.updateKeyVxAce();
        }

        for (;;) {
            if (this.engine === Engine.VXAce) {
                const dataOffset = this.xorU32VxAce(this.readU32());

                // End of data
                if (dataOffset === 0) {
                    return;
                }

                const dataSize = this.xorU32VxAce(this.readU32());
                const entryKey = this.xorU32VxAce(this.readU32());
                const pathSize = this.xorU32VxAce(this.readU32());

                const pathData = this.readBytes(pathSize);
                this.xorPathVxAce(pathData);

                // Store current position
                const prevPos = this.pos;

                // Read data
                this.seekStart(dataOffset);
                const entryData = this.readBytes(dataSize);
                xorData(entryKey, entryData);

                // Restore position
                this.seekStart(prevPos);

                yield { path: pathData, data: entryData };
            } else {
                // End of data
                if (this.pos === this.len) {
                    return;
                }

                const pathSize = this.xorU32Older(this.readU32());
                const pathData = this.readBytes(pathSize);
                this.xorPathOlder(pathData);

                const dataSize = this.xorU32Older(this.readU32());
                const dataOffset = this.pos;
                const entryKey = this.key;

                // Skip data block
                this.seekCurrent(dataSize);

                // Store current position
                const prevPos = this.pos;

                // Seek back to the data and read it
                this.seekStart(dataOffset);
                const entryData = this.readBytes(dataSize);
                xorData(entryKey, entryData);

                // Restore position
                this.seekStart(prevPos);

                yield { path: pathData, data: entryData };
            }
        }
    }

    private encryptEntries(entries: readonly ArchiveEntry[], archiveBuffer: Uint8Array): void {
        const view = new DataView(archiveBuffer.buffer, archiveBuffer.byteOffset, archiveBuffer.byteLength);
        let offset = 8;

        if (this.engine === Engine.VXAce) {
            this.updateKey(ENCRYPTION_KEY);
            view.setUint32(offset, this.key, true);
            offset += 4;

            this.updateKeyVxAce();
        }

        if (this.engine === Engine.VXAce) {
            // First we write metadata: content size, key, path size and path itself
            for (const entry of entries) {
                // Placeholder offset, we'll modify it later
                view.setUint32(offset, 0, true);
                offset += 4;

                const encodedDataSize = this.xorU32VxAce(entry.data.length);
                view.setUint32(offset, encodedDataSize, true);
                offset += 4;

                // self.key ^ self.key = 0
                view.setUint32(offset, ENCRYPTION_KEY, true);
                offset += 4;

                const encodedPathSize = this.xorU32VxAce(entry.path.length);
                view.setUint32(offset, encodedPathSize, true);
                offset += 4;

                archiveBuffer.set(entry.path, offset);
                this.xorPathVxAce(archiveBuffer.subarray(offset, offset + entry.path.length));
                offset += entry.path.length;
            }

            // Write the key; when decrypting it will be xor'd against itself which will produce 0, and decryption will stop.
            view.setUint32(offset, this.key, true);
            offset += 4;

            let placeholderOffset = 12;

            // Write the actual contents and modify the offsets with the offsets of the contents
            for (const entry of entries) {
                const dataOffset = offset;
                const encryptedDataOffset = this.xorU32VxAce(dataOffset);
                view.setUint32(placeholderOffset, encryptedDataOffset, true);

                placeholderOffset += 16 + entry.path.length;

                archiveBuffer.set(entry.data, offset);
                xorData(this.key, archiveBuffer.subarray(offset, offset + entry.data.length));
                offset += entry.data.length;
            }
        } else {
            for (const entry of entries) {
                const encodedPathSize = this.xorU32Older(entry.path.length);
                view.setUint32(offset, encodedPathSize, true);
                offset += 4;

                archiveBuffer.set(entry.path, offset);
                this.xorPathOlder(archiveBuffer.subarray(offset, offset + entry.path.length));
                offset += entry.path.length;

                const encodedDataSize = this.xorU32Older(entry.data.length);
                view.setUint32(offset, encodedDataSize, true);
                offset += 4;

                archiveBuffer.set(entry.data, offset);
                xorData(this.key, archiveBuffer.subarray(offset, offset + entry.data.length));
                offset += entry.data.length;
            }
        }
    }

    private reset(data: Uint8Array): void {
        this.data = data;
        this.view = new DataView(data.buffer, data.byteOffset, data.byteLength);
        this.len = data.length;
        this.pos = 0;

        this.engine = Engine.Older;
        this.updateKey(OLDER_DECRYPTION_KEY);
    }

    /**
     * Returns an iterator over decrypted {@link ArchiveEntry} entries.
     *
     * @param archiveData - The content of the archive file. This data is modified in place.
     * @returns A generator of decrypted entries, whose `path`/`data` are views into `archiveData`.
     * @throws {InvalidHeaderError} if the archive header doesn't match `RGSSAD\0`.
     * @throws {InvalidEngineError} if the archive's engine byte is neither `1` nor `3`.
     *
     * @example
     * ```ts
     * import { Decrypter } from "rpgmad-lib";
     * import { readFile } from "node:fs/promises";
     *
     * const archiveData = new Uint8Array(await readFile("Game.rgss3a"));
     * const decrypter = new Decrypter();
     *
     * for (const entry of decrypter.decrypt(archiveData)) {
     *     console.log(new TextDecoder().decode(entry.path));
     * }
     * ```
     */
    decrypt(archiveData: Uint8Array): Generator<ArchiveEntry> {
        this.reset(archiveData);
        this.parseHeader();
        return this.decryptEntries();
    }

    /**
     * Returns the size for the encrypted buffer of archive entries in bytes.
     *
     * It's necessary to call this before {@link Decrypter.encrypt} to allocate the target buffer.
     *
     * @param archiveEntries - Archive entries to encrypt.
     * @param engine - Target archive engine.
     */
    static encryptedBufferSize(archiveEntries: readonly ArchiveEntry[], engine: Engine): number {
        let bufSize = ARCHIVE_HEADER.length;

        // Engine byte
        bufSize += 1;

        if (engine === Engine.VXAce) {
            bufSize += 4;
        }

        for (const entry of archiveEntries) {
            if (engine === Engine.VXAce) {
                bufSize += U32_SIZE; // Offset
                bufSize += U32_SIZE; // Data size
                bufSize += U32_SIZE; // Key
                bufSize += U32_SIZE; // Path size
            } else {
                bufSize += U32_SIZE; // Path size
                bufSize += U32_SIZE; // Data size
            }

            bufSize += entry.data.length;
            bufSize += entry.path.length;
        }

        if (engine === Engine.VXAce) {
            // Stop offset int
            bufSize += U32_SIZE;

            // VX Ace actually writes the full entry before the stop offset, although this data is not ever used when decrypting and discarded.
            bufSize += U32_SIZE * 3;
        }

        return bufSize;
    }

    /**
     * Writes encrypted archive data to `archiveBuffer`.
     *
     * `archiveBuffer` must be pre-allocated by the caller, sized with {@link Decrypter.encryptedBufferSize}.
     *
     * @param archiveEntries - Archive entries to encrypt.
     * @param engine - Target archive engine.
     * @param archiveBuffer - Buffer to write encrypted data into.
     *
     * @example
     * ```ts
     * import { ArchiveEntry, Decrypter, Engine } from "rpgmad-lib";
     * import { readFile, writeFile } from "node:fs/promises";
     *
     * const data = new Uint8Array(await readFile("Graphics/Tilesets/Tileset1.png"));
     * const archiveEntries: ArchiveEntry[] = [
     *     { path: new TextEncoder().encode("Graphics/Tilesets/Tileset1.png"), data },
     * ];
     *
     * const size = Decrypter.encryptedBufferSize(archiveEntries, Engine.VXAce);
     * const archiveBuffer = new Uint8Array(size);
     *
     * new Decrypter().encrypt(archiveEntries, Engine.VXAce, archiveBuffer);
     * await writeFile("Game.rgss3a", archiveBuffer);
     * ```
     */
    encrypt(archiveEntries: readonly ArchiveEntry[], engine: Engine, archiveBuffer: Uint8Array): void {
        archiveBuffer.set(ARCHIVE_HEADER);
        archiveBuffer[7] = engine;

        this.engine = engine;
        this.encryptEntries(archiveEntries, archiveBuffer);
    }
}

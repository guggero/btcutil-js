/**
 * Storage backends for the watch-only wallet engine. Headers and filter
 * headers are stored as neutrino-headerfs-style flat files: fixed-size
 * records (80 / 32 bytes) whose file offset is pure height arithmetic. The
 * chain resume state and the wallet JSON are small blobs.
 *
 * Two implementations of the same {@link WalletStorage} shape ship with the
 * library: {@link OpfsStorage} (browser Origin-Private File System) and
 * {@link NodeStorage} (plain files, for Node CLIs and tests). Custom
 * backends only need to satisfy the interface.
 */

const HEADER_SIZE = 80;
const FILTER_HEADER_SIZE = 32;

// Every file a wallet store consists of; used by stats() and clear().
const STORE_FILES = [
  'headers.bin',
  'filter-headers.bin',
  'chain-state.bin',
  'wallet.json',
] as const;

/** Entry counts and byte sizes of a wallet store. */
export interface StorageStats {
  headerCount: number;
  filterHeaderCount: number;
  headersBytes: number;
  filterHeadersBytes: number;
  stateBytes: number;
  walletBytes: number;
  totalBytes: number;
}

/** The persistence interface the wallet engine drives. */
export interface WalletStorage {
  headerCount(): Promise<number>;
  appendHeaders(bytes: Uint8Array): Promise<void>;
  readHeaders(height: number, count: number): Promise<Uint8Array>;
  truncateHeaders(count: number): Promise<void>;

  filterHeaderCount(): Promise<number>;
  appendFilterHeaders(bytes: Uint8Array): Promise<void>;
  readFilterHeaders(height: number, count: number): Promise<Uint8Array>;
  truncateFilterHeaders(count: number): Promise<void>;

  getChainState(): Promise<Uint8Array | null>;
  setChainState(bytes: Uint8Array): Promise<void>;

  getWallet(): Promise<any | null>;
  setWallet(obj: any): Promise<void>;

  stats(): Promise<StorageStats>;
  clear(): Promise<void>;
}

// buildStats assembles the stats() result from a name→bytes size lookup.
async function buildStats(
  sizeOf: (name: string) => Promise<number>,
): Promise<StorageStats> {
  const [headersBytes, filterHeadersBytes, stateBytes, walletBytes] =
    await Promise.all(STORE_FILES.map(sizeOf));
  return {
    headerCount: Math.floor(headersBytes / HEADER_SIZE),
    filterHeaderCount: Math.floor(filterHeadersBytes / FILTER_HEADER_SIZE),
    headersBytes,
    filterHeadersBytes,
    stateBytes,
    walletBytes,
    totalBytes: headersBytes + filterHeadersBytes + stateBytes +
      walletBytes,
  };
}

/** Browser storage on the Origin Private File System (persistent, per
 *  origin). Create one per network, e.g.
 *  `await OpfsStorage.open('neutrino-mainnet')`. */
export class OpfsStorage implements WalletStorage {
  private constructor(private dir: any) {}

  static async open(dirName: string): Promise<OpfsStorage> {
    const root = await (navigator as any).storage.getDirectory();
    const dir = await root.getDirectoryHandle(dirName, { create: true });
    return new OpfsStorage(dir);
  }

  private file(name: string): Promise<any> {
    return this.dir.getFileHandle(name, { create: true });
  }

  private async readAll(name: string): Promise<Uint8Array> {
    const handle = await this.file(name);
    const file = await handle.getFile();
    return new Uint8Array(await file.arrayBuffer());
  }

  private async readSlice(
    name: string, offset: number, length: number,
  ): Promise<Uint8Array> {
    const handle = await this.file(name);
    const file = await handle.getFile();
    const slice = file.slice(offset, offset + length);
    return new Uint8Array(await slice.arrayBuffer());
  }

  private async size(name: string): Promise<number> {
    const handle = await this.file(name);
    return (await handle.getFile()).size;
  }

  private async append(name: string, bytes: Uint8Array): Promise<void> {
    const handle = await this.file(name);
    const size = (await handle.getFile()).size;
    const writable = await handle.createWritable({
      keepExistingData: true,
    });
    await writable.write({ type: 'write', position: size, data: bytes });
    await writable.close();
  }

  private async truncate(name: string, size: number): Promise<void> {
    const handle = await this.file(name);
    const writable = await handle.createWritable({
      keepExistingData: true,
    });
    await writable.truncate(size);
    await writable.close();
  }

  private async writeAll(name: string, bytes: Uint8Array): Promise<void> {
    const handle = await this.file(name);
    const writable = await handle.createWritable();
    await writable.write(bytes);
    await writable.close();
  }

  async headerCount(): Promise<number> {
    return Math.floor(await this.size('headers.bin') / HEADER_SIZE);
  }
  appendHeaders = (bytes: Uint8Array) => this.append('headers.bin', bytes);
  readHeaders = (height: number, count: number) => this.readSlice(
    'headers.bin', height * HEADER_SIZE, count * HEADER_SIZE,
  );
  truncateHeaders = (count: number) =>
    this.truncate('headers.bin', count * HEADER_SIZE);

  async filterHeaderCount(): Promise<number> {
    return Math.floor(
      await this.size('filter-headers.bin') / FILTER_HEADER_SIZE,
    );
  }
  appendFilterHeaders = (bytes: Uint8Array) =>
    this.append('filter-headers.bin', bytes);
  readFilterHeaders = (height: number, count: number) => this.readSlice(
    'filter-headers.bin', height * FILTER_HEADER_SIZE,
    count * FILTER_HEADER_SIZE,
  );
  truncateFilterHeaders = (count: number) =>
    this.truncate('filter-headers.bin', count * FILTER_HEADER_SIZE);

  async getChainState(): Promise<Uint8Array | null> {
    const bytes = await this.readAll('chain-state.bin');
    return bytes.length > 0 ? bytes : null;
  }
  setChainState = (bytes: Uint8Array) =>
    this.writeAll('chain-state.bin', bytes);

  async getWallet(): Promise<any | null> {
    const bytes = await this.readAll('wallet.json');
    if (bytes.length === 0) return null;
    return JSON.parse(new TextDecoder().decode(bytes));
  }
  setWallet = (obj: any) => this.writeAll(
    'wallet.json', new TextEncoder().encode(JSON.stringify(obj)),
  );

  /** Entry counts and byte sizes of everything stored for this wallet. */
  stats = () => buildStats((name) => this.size(name));

  /** Delete all stored chain and wallet data. */
  async clear(): Promise<void> {
    for (const name of STORE_FILES) {
      try {
        await this.dir.removeEntry(name);
      } catch {
        // A missing file is already clear.
      }
    }
  }
}

// The indirection hides the import from bundlers (same trick as the WASM
// loader in init.ts): NodeStorage is only ever constructed under Node, but
// this module is part of the browser bundle.
const nodeImport = new Function('m', 'return import(m)') as (
  m: string,
) => Promise<any>;

/** Plain-file storage for Node (CLIs, tests). Create with
 *  `await NodeStorage.open('/path/to/datadir')`. */
export class NodeStorage implements WalletStorage {
  private constructor(private fs: any, private dir: string) {}

  static async open(dirPath: string): Promise<NodeStorage> {
    const fs = await nodeImport('node:fs/promises');
    await fs.mkdir(dirPath, { recursive: true });
    return new NodeStorage(fs, dirPath);
  }

  private path(name: string): string {
    return `${this.dir}/${name}`;
  }

  private async size(name: string): Promise<number> {
    try {
      return (await this.fs.stat(this.path(name))).size;
    } catch {
      return 0;
    }
  }

  private async readSlice(
    name: string, offset: number, length: number,
  ): Promise<Uint8Array> {
    const handle = await this.fs.open(this.path(name), 'a+');
    try {
      const buf = new Uint8Array(length);
      const { bytesRead } = await handle.read(buf, 0, length, offset);
      return buf.subarray(0, bytesRead);
    } finally {
      await handle.close();
    }
  }

  async headerCount(): Promise<number> {
    return Math.floor(await this.size('headers.bin') / HEADER_SIZE);
  }
  appendHeaders = (bytes: Uint8Array) =>
    this.fs.appendFile(this.path('headers.bin'), bytes);
  readHeaders = (height: number, count: number) => this.readSlice(
    'headers.bin', height * HEADER_SIZE, count * HEADER_SIZE,
  );
  truncateHeaders = (count: number) =>
    this.fs.truncate(this.path('headers.bin'), count * HEADER_SIZE);

  async filterHeaderCount(): Promise<number> {
    return Math.floor(
      await this.size('filter-headers.bin') / FILTER_HEADER_SIZE,
    );
  }
  appendFilterHeaders = (bytes: Uint8Array) =>
    this.fs.appendFile(this.path('filter-headers.bin'), bytes);
  readFilterHeaders = (height: number, count: number) => this.readSlice(
    'filter-headers.bin', height * FILTER_HEADER_SIZE,
    count * FILTER_HEADER_SIZE,
  );
  truncateFilterHeaders = (count: number) =>
    this.fs.truncate(
      this.path('filter-headers.bin'), count * FILTER_HEADER_SIZE,
    );

  async getChainState(): Promise<Uint8Array | null> {
    try {
      return new Uint8Array(
        await this.fs.readFile(this.path('chain-state.bin')),
      );
    } catch {
      return null;
    }
  }
  setChainState = (bytes: Uint8Array) =>
    this.fs.writeFile(this.path('chain-state.bin'), bytes);

  async getWallet(): Promise<any | null> {
    try {
      return JSON.parse(
        await this.fs.readFile(this.path('wallet.json'), 'utf8'),
      );
    } catch {
      return null;
    }
  }
  setWallet = (obj: any) =>
    this.fs.writeFile(this.path('wallet.json'), JSON.stringify(obj));

  /** Entry counts and byte sizes of everything stored for this wallet. */
  stats = () => buildStats((name) => this.size(name));

  /** Delete all stored chain and wallet data. */
  async clear(): Promise<void> {
    for (const name of STORE_FILES) {
      await this.fs.rm(this.path(name), { force: true });
    }
  }
}

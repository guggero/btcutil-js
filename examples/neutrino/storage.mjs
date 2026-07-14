// Storage backends for the example wallet. Headers and filter headers are
// stored exactly like neutrino's headerfs flat files: fixed-size records
// (80 / 32 bytes) whose file offset is pure height arithmetic. The chain
// resume state and the wallet JSON are small blobs.
//
// Two implementations of the same shape:
//   - OpfsStorage: browser Origin-Private File System (persistent).
//   - NodeStorage: plain files, so the wallet core runs under Node for
//     testing and CLI use.

const HEADER_SIZE = 80;
const FILTER_HEADER_SIZE = 32;

// Every file a wallet store consists of; used by stats() and clear().
const STORE_FILES = [
  'headers.bin',
  'filter-headers.bin',
  'chain-state.bin',
  'wallet.json',
];

// buildStats assembles the stats() result from a name→bytes size lookup.
async function buildStats(sizeOf) {
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

export class OpfsStorage {
  static async open(dirName) {
    const root = await navigator.storage.getDirectory();
    const dir = await root.getDirectoryHandle(dirName, { create: true });
    return new OpfsStorage(dir);
  }

  constructor(dir) {
    this.dir = dir;
  }

  async #file(name) {
    return this.dir.getFileHandle(name, { create: true });
  }

  async #readAll(name) {
    const handle = await this.#file(name);
    const file = await handle.getFile();
    return new Uint8Array(await file.arrayBuffer());
  }

  async #readSlice(name, offset, length) {
    const handle = await this.#file(name);
    const file = await handle.getFile();
    const slice = file.slice(offset, offset + length);
    return new Uint8Array(await slice.arrayBuffer());
  }

  async #size(name) {
    const handle = await this.#file(name);
    return (await handle.getFile()).size;
  }

  async #append(name, bytes) {
    const handle = await this.#file(name);
    const size = (await handle.getFile()).size;
    const writable = await handle.createWritable({
      keepExistingData: true,
    });
    await writable.write({ type: 'write', position: size, data: bytes });
    await writable.close();
  }

  async #truncate(name, size) {
    const handle = await this.#file(name);
    const writable = await handle.createWritable({
      keepExistingData: true,
    });
    await writable.truncate(size);
    await writable.close();
  }

  async #writeAll(name, bytes) {
    const handle = await this.#file(name);
    const writable = await handle.createWritable();
    await writable.write(bytes);
    await writable.close();
  }

  headerCount = async () =>
    Math.floor(await this.#size('headers.bin') / HEADER_SIZE);
  appendHeaders = (bytes) => this.#append('headers.bin', bytes);
  readHeaders = (height, count) => this.#readSlice(
    'headers.bin', height * HEADER_SIZE, count * HEADER_SIZE,
  );
  truncateHeaders = (count) =>
    this.#truncate('headers.bin', count * HEADER_SIZE);

  filterHeaderCount = async () =>
    Math.floor(await this.#size('filter-headers.bin') / FILTER_HEADER_SIZE);
  appendFilterHeaders = (bytes) => this.#append('filter-headers.bin', bytes);
  readFilterHeaders = (height, count) => this.#readSlice(
    'filter-headers.bin', height * FILTER_HEADER_SIZE,
    count * FILTER_HEADER_SIZE,
  );
  truncateFilterHeaders = (count) =>
    this.#truncate('filter-headers.bin', count * FILTER_HEADER_SIZE);

  async getChainState() {
    const bytes = await this.#readAll('chain-state.bin');
    return bytes.length > 0 ? bytes : null;
  }
  setChainState = (bytes) => this.#writeAll('chain-state.bin', bytes);

  async getWallet() {
    const bytes = await this.#readAll('wallet.json');
    if (bytes.length === 0) return null;
    return JSON.parse(new TextDecoder().decode(bytes));
  }
  setWallet = (obj) => this.#writeAll(
    'wallet.json', new TextEncoder().encode(JSON.stringify(obj)),
  );

  /** Entry counts and byte sizes of everything stored for this wallet. */
  stats = () => buildStats((name) => this.#size(name));

  /** Delete all stored chain and wallet data. */
  async clear() {
    for (const name of STORE_FILES) {
      try {
        await this.dir.removeEntry(name);
      } catch {
        // A missing file is already clear.
      }
    }
  }
}

export class NodeStorage {
  static async open(dirPath) {
    const fs = await import('node:fs/promises');
    await fs.mkdir(dirPath, { recursive: true });
    return new NodeStorage(fs, dirPath);
  }

  constructor(fs, dir) {
    this.fs = fs;
    this.dir = dir;
  }

  #path(name) {
    return `${this.dir}/${name}`;
  }

  async #size(name) {
    try {
      return (await this.fs.stat(this.#path(name))).size;
    } catch {
      return 0;
    }
  }

  async #readSlice(name, offset, length) {
    const handle = await this.fs.open(this.#path(name), 'a+');
    try {
      const buf = new Uint8Array(length);
      const { bytesRead } = await handle.read(buf, 0, length, offset);
      return buf.subarray(0, bytesRead);
    } finally {
      await handle.close();
    }
  }

  headerCount = async () =>
    Math.floor(await this.#size('headers.bin') / HEADER_SIZE);
  appendHeaders = (bytes) =>
    this.fs.appendFile(this.#path('headers.bin'), bytes);
  readHeaders = (height, count) => this.#readSlice(
    'headers.bin', height * HEADER_SIZE, count * HEADER_SIZE,
  );
  truncateHeaders = (count) =>
    this.fs.truncate(this.#path('headers.bin'), count * HEADER_SIZE);

  filterHeaderCount = async () =>
    Math.floor(await this.#size('filter-headers.bin') / FILTER_HEADER_SIZE);
  appendFilterHeaders = (bytes) =>
    this.fs.appendFile(this.#path('filter-headers.bin'), bytes);
  readFilterHeaders = (height, count) => this.#readSlice(
    'filter-headers.bin', height * FILTER_HEADER_SIZE,
    count * FILTER_HEADER_SIZE,
  );
  truncateFilterHeaders = (count) =>
    this.fs.truncate(
      this.#path('filter-headers.bin'), count * FILTER_HEADER_SIZE,
    );

  async getChainState() {
    try {
      return new Uint8Array(
        await this.fs.readFile(this.#path('chain-state.bin')),
      );
    } catch {
      return null;
    }
  }
  setChainState = (bytes) =>
    this.fs.writeFile(this.#path('chain-state.bin'), bytes);

  async getWallet() {
    try {
      return JSON.parse(
        await this.fs.readFile(this.#path('wallet.json'), 'utf8'),
      );
    } catch {
      return null;
    }
  }
  setWallet = (obj) =>
    this.fs.writeFile(this.#path('wallet.json'), JSON.stringify(obj));

  /** Entry counts and byte sizes of everything stored for this wallet. */
  stats = () => buildStats((name) => this.#size(name));

  /** Delete all stored chain and wallet data. */
  async clear() {
    for (const name of STORE_FILES) {
      await this.fs.rm(this.#path(name), { force: true });
    }
  }
}

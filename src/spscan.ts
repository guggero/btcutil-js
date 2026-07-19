import { init, g, unwrap } from './init';
import type { Bytes, Network } from './types';

/** A silent-payment output found by the scanner. */
export interface SpFoundOutput {
  txid: string;
  vout: number;
  /** Value in satoshis. */
  value: number;
  /** 32-byte x-only taproot output key. */
  xOnlyPubKey: Uint8Array;
  /** Which address matched: the base address or the change label (m=0). */
  label: 'base' | 'change';
  /** BIP-352 output index k within the transaction. */
  k: number;
  /** 32-byte scalar to add to the spend private key to derive this
   *  output's key-path signing key (includes the label tweak for change
   *  outputs). */
  privKeyTweak: Uint8Array;
}

/** A vector-testable identification result from {@link scanOutputsSync}:
 *  like {@link SpFoundOutput} but indexing into the provided key list. */
export interface SpIdentifiedOutput {
  index: number;
  xOnlyPubKey: Uint8Array;
  label: 'base' | 'change';
  k: number;
  privKeyTweak: Uint8Array;
}

/** One matched block from {@link scanBatchSync}. */
export interface SpBatchMatch {
  height: number;
  blockHash: string;
  /** The block's record from the tweak data: concatenated 33-byte
   *  compressed tweak keys, in transaction order — the input for
   *  {@link silentpayments.scanBlock} once the block is downloaded. */
  tweaks: Uint8Array;
}

/** Per-phase timing breakdown of one batch scan pass, measured inside the
 *  WASM module. Candidate derivation (`deriveMs`) is the ECDH-heavy part
 *  and expected to dominate. */
export interface SpBatchTimings {
  /** Tweak-data JSON decode. */
  parseMs: number;
  /** Candidate output key derivation (ECDH per tweak). */
  deriveMs: number;
  /** Filter decode + commitment-chain verification. */
  verifyMs: number;
  /** GCS filter matching. */
  matchMs: number;
  /** Served tweak entries processed. */
  tweaks: number;
}

/** The result of one batch scan pass. */
export interface SpBatchResult {
  matches: SpBatchMatch[];
  /** Served tweak entries skipped because they are not valid curve points
   *  (e.g. all-zero data from an indexer that didn't skip
   *  point-at-infinity input sums). Such entries can never correspond to
   *  real payments. */
  skippedTweaks: number;
  /** WASM-side timing breakdown of this pass. */
  timings?: SpBatchTimings;
}

// Handles are released on GC or explicit free(), same pattern as
// descriptors.ts / neutrino.ts.
const spScannerFinalizers = new FinalizationRegistry<number>((handle) => {
  try {
    g()?.silentpayments?.scannerFree(handle);
  } catch {
    // Best-effort cleanup: ignore if the module is already gone.
  }
});

/** The BIP-352 receiver context: scan private key + spend public key with
 *  the pre-computed base and change (label m=0) scan addresses. */
export class SpScanner {
  /** @internal */
  readonly handle: number;

  /** The bech32m silent payment address (base, no label). */
  readonly address: string;

  /** The bech32m change address (label m=0). */
  readonly changeAddress: string;

  private freed = false;

  /** @internal Construct via {@link silentpayments.scanner}. */
  constructor(info: { handle: number; address: string;
    changeAddress: string }) {

    this.handle = info.handle;
    this.address = info.address;
    this.changeAddress = info.changeAddress;
    spScannerFinalizers.register(this, info.handle, this);
  }

  /** Release the Go-side scanner. Safe to call more than once. */
  free(): void {
    if (this.freed) {
      return;
    }
    this.freed = true;
    spScannerFinalizers.unregister(this);
    unwrap(g().silentpayments.scannerFree(this.handle));
  }
}

/** @internal Shared by the async namespace and the sync API. */
export function createSpScanner(
  scanPrivKey: Bytes,
  spendPubKey: Bytes,
  network: Network = 'mainnet',
): SpScanner {
  const info = unwrap<{ handle: number; address: string;
    changeAddress: string }>(
    g().silentpayments.scannerNew(scanPrivKey, spendPubKey, network),
  );
  return new SpScanner(info);
}

/** @internal Shared by the async namespace, the sync API and the match
 *  worker. */
export function scanBatchSync(
  scanner: SpScanner,
  startHeight: number,
  tweakData: Bytes,
  filterFile: Bytes,
  headers: Bytes,
  filterHeaders: Bytes,
  prevFilterHeader: string,
  dustLimit: number,
  onBlocks?: (blocks: number) => void,
): SpBatchResult {
  return unwrap<SpBatchResult>(
    g().silentpayments.scanBatch(
      scanner.handle, startHeight, tweakData, filterFile, headers,
      filterHeaders, prevFilterHeader, dustLimit, onBlocks,
    ),
  );
}

/** @internal Shared by the async namespace and the sync API. */
export function scanBlockSpSync(
  scanner: SpScanner,
  blockBytes: Bytes,
  tweakBytes: Bytes,
): SpFoundOutput[] {
  return unwrap<SpFoundOutput[]>(
    g().silentpayments.scanBlock(
      scanner.handle, blockBytes, tweakBytes,
    ),
  );
}

/** @internal Shared by the async namespace and the sync API. */
export function scanOutputsSync(
  scanner: SpScanner,
  tweak: Bytes,
  xOnlyKeys: Bytes[],
): SpIdentifiedOutput[] {
  return unwrap<SpIdentifiedOutput[]>(
    g().silentpayments.scanOutputs(scanner.handle, tweak, xOnlyKeys),
  );
}

/** BIP-352 Silent Payments scanning primitives (receiver side).
 *
 *  Driven by the tweak index of a block-dn server (`/sp/tweaks/<dust>/<h>`,
 *  a binary file of 33-byte `input_hash * A_sum` points per block), from
 *  which the scanner derives candidate taproot output keys — one ECDH
 *  multiplication per transaction — and matches them against the p2tr
 *  custom compact filter. The scan and spend keys never leave the browser.
 *
 *  ```ts
 *  const scanner = await silentpayments.scanner(scanPriv, spendPub, 'signet');
 *  console.log(scanner.address); // sp1q...
 *  const result = await silentpayments.scanBatch(
 *    scanner, 312000, tweakData, p2trFilterFile, headersSlice,
 *    p2trFilterHeadersSlice, prevHeaderHex, 1000,
 *  );
 *  for (const m of result.matches) {
 *    const found = await silentpayments.scanBlock(
 *      scanner, blockBytes, m.tweaks,
 *    );
 *  }
 *  ```
 *
 *  The {@link SilentPaymentScanner} engine (spscanner.ts) wraps the full
 *  fetch/verify/scan pipeline. */
export const silentpayments = {
  /** Create a scanner from a 32-byte scan private key and a 33-byte
   *  compressed spend public key. */
  async scanner(
    scanPrivKey: Bytes,
    spendPubKey: Bytes,
    network: Network = 'mainnet',
  ): Promise<SpScanner> {
    await init();
    return createSpScanner(scanPrivKey, spendPubKey, network);
  },

  /** One verify-and-match pass over a p2tr filter file range: derives the
   *  k=0 candidate output keys of every served transaction tweak (base +
   *  change addresses) and matches them against each block's p2tr filter,
   *  verifying every filter against the committed filter-header chain.
   *  `tweakData` is block-dn's raw binary /sp/tweaks response for the same
   *  range; its self-describing header is validated against the scanner's
   *  network, `startHeight` and `dustLimit`. */
  async scanBatch(
    scanner: SpScanner,
    startHeight: number,
    tweakData: Bytes,
    filterFile: Bytes,
    headers: Bytes,
    filterHeaders: Bytes,
    prevFilterHeader: string,
    dustLimit = 0,
    onBlocks?: (blocks: number) => void,
  ): Promise<SpBatchResult> {
    await init();
    return scanBatchSync(
      scanner, startHeight, tweakData, filterFile, headers,
      filterHeaders, prevFilterHeader, dustLimit, onBlocks,
    );
  },

  /** Identify the scanner's outputs in a downloaded block, across output
   *  indexes k = 0, 1, 2, ... per BIP-352 continuation semantics.
   *  `tweakBytes` is the block's concatenated 33-byte tweak keys (as
   *  returned in a {@link SpBatchMatch}). */
  async scanBlock(
    scanner: SpScanner,
    blockBytes: Bytes,
    tweakBytes: Bytes,
  ): Promise<SpFoundOutput[]> {
    await init();
    return scanBlockSpSync(scanner, blockBytes, tweakBytes);
  },

  /** Pure identification: which of the given x-only taproot output keys
   *  belong to the scanner under the given transaction tweak. */
  async scanOutputs(
    scanner: SpScanner,
    tweak: Bytes,
    xOnlyKeys: Bytes[],
  ): Promise<SpIdentifiedOutput[]> {
    await init();
    return scanOutputsSync(scanner, tweak, xOnlyKeys);
  },
};

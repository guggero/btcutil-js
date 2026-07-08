import { init, g, unwrap } from './init';
import type {
  DescType,
  DescriptorAssets,
  DescriptorSatisfier,
  Network,
  SatisfyResult,
  SemanticPolicy,
} from './types';

// The eagerly-computed, immutable fields the Go-side `new` returns alongside
// the handle, so the JS wrapper can serve them without another boundary
// crossing.
interface DescriptorInfo {
  handle: number;
  descriptor: string;
  descType: DescType;
  multipathLen: number;
  keys: string[];
}

interface PlanInfo {
  handle: number;
  satisfactionWeight: number;
  scriptSigSize: number;
  witnessSize: number;
}

// A parsed descriptor and each plan derived from it live on the Go side across
// calls (see wasm-wrapper/descriptors.go). These registries release the Go-side
// handle when the JS wrapper is garbage-collected, so a caller that forgets
// free() still doesn't leak. Freeing an unknown handle is a Go-side no-op, so
// the finalizer racing an explicit free() is harmless.
const descriptorFinalizers = new FinalizationRegistry<number>((handle) => {
  try {
    g()?.descriptors?.free(handle);
  } catch {
    // Best-effort cleanup: ignore if the module is already gone.
  }
});

const planFinalizers = new FinalizationRegistry<number>((handle) => {
  try {
    g()?.descriptors?.planFree(handle);
  } catch {
    // Best-effort cleanup: ignore if the module is already gone.
  }
});

/** A parsed BIP380 output descriptor.
 *
 *  Wraps a long-lived Go-side descriptor so the expensive parse (and the
 *  miniscript AST it caches) happens once, no matter how many addresses,
 *  scripts or plans are derived from it. Obtain one with
 *  {@link descriptors.create}. Call {@link free} when done, or rely on the
 *  garbage collector to release the Go-side handle. */
export class Descriptor {
  /** The canonical descriptor string, including the checksum. */
  readonly descriptor: string;

  private readonly handle: number;
  private readonly cachedDescType: DescType;
  private readonly cachedKeys: string[];
  private readonly cachedMultipathLen: number;
  private freed = false;

  /** @internal Construct via {@link descriptors.create}. */
  constructor(info: DescriptorInfo) {
    this.handle = info.handle;
    this.descriptor = info.descriptor;
    this.cachedDescType = info.descType;
    this.cachedKeys = info.keys;
    this.cachedMultipathLen = info.multipathLen;
    descriptorFinalizers.register(this, info.handle, this);
  }

  /** The full descriptor string, including checksum. */
  toString(): string {
    return this.descriptor;
  }

  /** The descriptor's output type classification (e.g. `"Wpkh"`, `"Tr"`). */
  descType(): DescType {
    return this.cachedDescType;
  }

  /** All keys in the descriptor, in the order they appear. */
  keys(): string[] {
    return [...this.cachedKeys];
  }

  /** The number of multipath elements (1 if the descriptor has none). */
  multipathLen(): number {
    return this.cachedMultipathLen;
  }

  /** Derive the address at the given multipath and derivation index for the
   *  given network. */
  addressAt(
    network: Network,
    multipathIndex: number,
    derivationIndex: number,
  ): string {
    return unwrap<string>(
      g().descriptors.addressAt(
        this.handle,
        network,
        multipathIndex,
        derivationIndex,
      ),
    );
  }

  /** The script code (as used for signature hashing) at the given multipath and
   *  derivation index. */
  scriptCodeAt(multipathIndex: number, derivationIndex: number): Uint8Array {
    return unwrap<Uint8Array>(
      g().descriptors.scriptCodeAt(
        this.handle,
        multipathIndex,
        derivationIndex,
      ),
    );
  }

  /** Convert the descriptor into its abstract semantic policy (BIP-style
   *  "lift"), allowing analysis such as filtering and normalization. */
  lift(): SemanticPolicy {
    return JSON.parse(unwrap<string>(g().descriptors.lift(this.handle)));
  }

  /** An upper bound on the input weight, in weight units, needed to satisfy the
   *  descriptor. Throws if the descriptor can never be satisfied. */
  maxWeightToSatisfy(): number {
    return unwrap<number>(g().descriptors.maxWeightToSatisfy(this.handle));
  }

  /** Build a spending {@link Plan} at the given multipath and derivation index
   *  from the provided assets. Throws if the assets are insufficient to produce
   *  a non-malleable satisfaction. */
  planAt(
    multipathIndex: number,
    derivationIndex: number,
    assets: DescriptorAssets = {},
  ): Plan {
    const info = unwrap<PlanInfo>(
      g().descriptors.planAt(
        this.handle,
        multipathIndex,
        derivationIndex,
        assets,
      ),
    );
    return new Plan(info);
  }

  /** Release the Go-side descriptor. Safe to call more than once; method calls
   *  after `free()` are invalid. */
  free(): void {
    if (this.freed) {
      return;
    }
    this.freed = true;
    descriptorFinalizers.unregister(this);
    unwrap(g().descriptors.free(this.handle));
  }
}

/** A chosen spending path on a descriptor, produced by
 *  {@link Descriptor.planAt}. It captures the weight of the satisfaction and
 *  knows how to complete it from a {@link DescriptorSatisfier}. */
export class Plan {
  /** The weight, in weight units, needed to satisfy this plan (scriptSig and
   *  witness combined). */
  readonly satisfactionWeight: number;

  /** The size in bytes of the scriptSig, including its var-int length prefix. */
  readonly scriptSigSize: number;

  /** The size in bytes of the witness (0 for non-segwit outputs). */
  readonly witnessSize: number;

  private readonly handle: number;
  private freed = false;

  /** @internal Construct via {@link Descriptor.planAt}. */
  constructor(info: PlanInfo) {
    this.handle = info.handle;
    this.satisfactionWeight = info.satisfactionWeight;
    this.scriptSigSize = info.scriptSigSize;
    this.witnessSize = info.witnessSize;
    planFinalizers.register(this, info.handle, this);
  }

  /** Complete the plan, producing the final witness and scriptSig. Throws if
   *  the satisfier cannot provide the required data. */
  satisfy(satisfier: DescriptorSatisfier): SatisfyResult {
    return unwrap<SatisfyResult>(
      g().descriptors.planSatisfy(this.handle, satisfier),
    );
  }

  /** Release the Go-side plan. Safe to call more than once. */
  free(): void {
    if (this.freed) {
      return;
    }
    this.freed = true;
    planFinalizers.unregister(this);
    unwrap(g().descriptors.planFree(this.handle));
  }
}

/** Build a {@link Descriptor} from an already-initialized module. Shared by the
 *  async {@link descriptors.create} and the synchronous `init()` API. */
export function createDescriptor(descriptor: string): Descriptor {
  const info = unwrap<DescriptorInfo>(g().descriptors.new(descriptor));
  return new Descriptor(info);
}

/** BIP380 output descriptor utilities.
 *
 *  Parse a descriptor once and reuse the returned {@link Descriptor} for all
 *  address/script/plan derivations:
 *
 *  ```ts
 *  const desc = await descriptors.create('wpkh(xpub.../*)');
 *  const addr = desc.addressAt('mainnet', 0, 0);
 *  desc.free();
 *  ``` */
export const descriptors = {
  /** Parse a descriptor string into a long-lived {@link Descriptor}. */
  async create(descriptor: string): Promise<Descriptor> {
    await init();
    return createDescriptor(descriptor);
  },
};

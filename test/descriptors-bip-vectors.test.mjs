import './setup.mjs';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { init } from '../dist/index.js';
import { toHex } from './util.mjs';

// The test vectors of the descriptor BIPs, copied verbatim from btcd's
// descriptors package (descriptors/testdata/). The Go harnesses these mirror
// are bip_vectors_test.go and musig_test.go.
const vectorFile = (name) => JSON.parse(readFileSync(
  new URL(`test-vectors/${name}`, import.meta.url), 'utf-8',
));

const bipVectors = vectorFile('descriptors-bip-vectors.json');
const bip328Vectors = vectorFile('descriptors-bip328.json');
const bip390Vectors = vectorFile('descriptors-bip390.json');

// The vector loops build their cases at collection time, so the module is
// initialized once here and used through its synchronous API throughout.
const lib = await init();

// The features of the descriptor BIPs this library does not implement. A
// vector needing one has to be rejected at parse time, which keeps the gaps
// explicit: closing one makes these tests fail until its case is removed
// here. Mirrors unsupportedFeature() in bip_vectors_test.go.
function unsupportedFeature(desc) {
  // BIP384: a combo() descriptor stands for two or four output scripts,
  // which the single-script API cannot represent.
  if (desc.startsWith('combo(')) {
    return 'combo() (BIP384)';
  }

  // BIP385: raw() and addr() wrap a script or an address that has no keys
  // and no satisfaction, so most of the API is meaningless for them.
  if (desc.startsWith('raw(') || desc.startsWith('addr(') ||
      desc.includes('(raw(') || desc.includes('(addr(')) {
    return 'raw() and addr() (BIP385)';
  }

  return '';
}

// The output script of a descriptor at the given indexes: the script of its
// address, or its script code if it is a bare descriptor, which has no
// address. Mirrors outputScriptAt() in bip_vectors_test.go.
function outputScriptAt(d, multipathIndex, derivationIndex) {
  let addr;
  try {
    addr = d.addressAt('mainnet', multipathIndex, derivationIndex);
  } catch {
    return toHex(d.scriptCodeAt(multipathIndex, derivationIndex));
  }

  return toHex(lib.txscript.payToAddrScript(addr, 'mainnet'));
}

// ---------------------------------------------------------------------------
// BIP380-389 vectors
// ---------------------------------------------------------------------------

describe('descriptors: BIP vectors', () => {
  // The checksum vectors exercise the checksum and character set only, since
  // the raw() descriptor they are written with is not supported.
  const checksums = bipVectors.filter((v) => v.kind === 'checksum');
  describe('checksum (BIP380)', () => {
    checksums.forEach((v) => {
      it(v.label, () => {
        // A checksum vector is valid exactly if stripping the checksum
        // succeeds, which is what parsing does first.
        const parses = (() => {
          try {
            lib.descriptors.create(v.desc).free();
            return true;
          } catch (e) {
            // Any complaint that isn't about the checksum means the
            // checksum itself was accepted.
            return !/checksum|character/i.test(e.message);
          }
        })();
        assert.equal(parses, v.valid, v.desc);
      });
    });
  });

  const rest = bipVectors.filter((v) => v.kind !== 'checksum');
  rest.forEach((v) => {
    describe(`bip${v.bip}`, () => {
      it(v.label, () => {
        const unsupported = unsupportedFeature(v.desc);

        // A vector needing an unimplemented feature has to be rejected.
        if (unsupported) {
          assert.throws(
            () => lib.descriptors.create(v.desc),
            `vector needs unsupported feature ${unsupported} but was ` +
              `accepted: ${v.desc}`,
          );
          return;
        }

        if (!v.valid) {
          assert.throws(
            () => lib.descriptors.create(v.desc),
            `invalid vector accepted: ${v.desc}`,
          );
          return;
        }

        const d = lib.descriptors.create(v.desc);
        try {
          // The output scripts the BIP lists, one per derivation index.
          (v.scripts ?? []).forEach((want, idx) => {
            assert.equal(
              outputScriptAt(d, 0, idx), want,
              `output script at ${idx} for ${v.desc}`,
            );
          });

          // A multipath descriptor has to produce the same scripts as the
          // single-path descriptors it expands into.
          if (v.expansions?.length) {
            assert.equal(d.multipathLen(), v.expansions.length);

            v.expansions.forEach((expansion, mp) => {
              const single = lib.descriptors.create(expansion);
              try {
                for (let idx = 0; idx < 2; idx++) {
                  let want;
                  try {
                    want = outputScriptAt(single, 0, idx);
                  } catch {
                    // The expansion has no script at this index, so the
                    // multipath descriptor must not have one either.
                    assert.throws(() => outputScriptAt(d, mp, idx));
                    continue;
                  }
                  assert.equal(
                    outputScriptAt(d, mp, idx), want,
                    `expansion ${mp} at index ${idx} of ${v.desc}`,
                  );
                }
              } finally {
                single.free();
              }
            });
          }
        } finally {
          d.free();
        }
      });
    });
  });
});

// ---------------------------------------------------------------------------
// BIP390: musig() in descriptors
// ---------------------------------------------------------------------------

describe('descriptors: BIP390 vectors', () => {
  bip390Vectors.valid.forEach((v, i) => {
    it(`valid/${i}`, () => {
      // rawtr() is not supported as a descriptor; the vector's aggregate
      // key derivation is still covered by the BIP328 vectors below.
      if (v.descriptor.startsWith('rawtr(')) {
        assert.throws(() => lib.descriptors.create(v.descriptor));
        return;
      }

      const d = lib.descriptors.create(v.descriptor);
      try {
        v.scripts.forEach((want, index) => {
          assert.equal(outputScriptAt(d, 0, index), want);
        });
      } finally {
        d.free();
      }
    });
  });

  bip390Vectors.invalid.forEach((v) => {
    it(`invalid/${v.reason}`, () => {
      assert.throws(
        () => lib.descriptors.create(v.descriptor),
        `invalid vector accepted: ${v.descriptor}`,
      );
    });
  });
});

// ---------------------------------------------------------------------------
// BIP328: MuSig2 key aggregation and the synthetic xpub
// ---------------------------------------------------------------------------

describe('descriptors: BIP328 vectors', () => {
  bip328Vectors.forEach((v) => {
    it(v.aggregate_pubkey, () => {
      // BIP328 does not itself prescribe sorting: its vectors supply the
      // aggregation order, unlike BIP390.
      const agg = lib.musig2.aggregateKeys(v.keys, false);
      assert.equal(toHex(agg.combinedKey), v.aggregate_pubkey);

      // The aggregate key wrapped in the synthetic extended key BIP328
      // defines for it.
      assert.equal(lib.hdkeychain.musig2Key(agg.combinedKey), v.xpub);
    });
  });

  it('sorts the keys by default, unlike BIP328', () => {
    const [v] = bip328Vectors;
    const reversed = [...v.keys].reverse();

    // Sorting makes the order irrelevant; without it the order decides, so
    // the reversed list no longer reproduces the vector's aggregate key.
    assert.equal(
      toHex(lib.musig2.aggregateKeys(reversed).combinedKey),
      toHex(lib.musig2.aggregateKeys(v.keys).combinedKey),
    );
    assert.notEqual(
      toHex(lib.musig2.aggregateKeys(reversed, false).combinedKey),
      v.aggregate_pubkey,
    );
  });
});

import './setup.mjs';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { init } from '../dist/index.js';
import { toHex } from './util.mjs';

// The planning and satisfaction vectors of btcd's descriptors package
// (descriptors/testdata/spending_vectors.json), mirroring the Go harness in
// spending_vectors_test.go. Expected bytes are never derived by the code
// under test: every witness stack, scriptSig and size is pinned by the
// fixture, and the signed cases are additionally executed through the script
// engine.
const vectors = JSON.parse(readFileSync(
  new URL('test-vectors/descriptors-spending.json', import.meta.url),
  'utf-8',
));

const lib = await init();

assert.equal(vectors.version, 1);
assert.ok(vectors.cases.length > 0);

// Translates the vector's availability tables into planning assets. Lookups
// use exact identities: availability for one key, taproot leaf or hash
// function must not accidentally make another spending path usable.
function planningAssets(v) {
  // A vector that advertises nothing omits the tables entirely, which means
  // "nothing is available" rather than "unknown".
  const ecdsa = v.assets.ecdsa ?? [];
  const tapKey = v.assets.tap_key ?? [];
  const tapLeaf = v.assets.tap_leaf ?? [];
  const preimages = v.assets.preimages ?? [];

  const assets = {
    lookupEcdsaSig: (key) => ecdsa.includes(key),
    lookupTapKeySpendSig: (key) => {
      const asset = tapKey.find((a) => a.key === key);
      return asset ? asset.size : false;
    },
    lookupTapLeafScriptSig: (key, leafHash) => {
      const asset = tapLeaf.find(
        (a) => a.key === key && a.leaf_hash === leafHash,
      );
      return asset ? asset.size : false;
    },
    lookupPreimage: (hashFunc, hash) => preimages.some(
      (a) => a.function === hashFunc && a.hash === hash,
    ),
  };

  // Missing transaction fields stay unknown, so a plan cannot rely on a
  // locktime the vector does not grant it.
  if (v.tx.version !== undefined && v.tx.version !== null) {
    assets.txVersion = v.tx.version;
  }
  if (v.tx.lock_time !== undefined && v.tx.lock_time !== null) {
    assets.txLockTime = v.tx.lock_time;
  }
  if (v.tx.sequence !== undefined && v.tx.sequence !== null) {
    assets.txInputSequence = v.tx.sequence;
  }

  return assets;
}

// Translates a completion's concrete data into a satisfier. Kept strictly
// separate from the planning assets: completion fixtures deliberately omit
// data or supply extra signatures to check that the plan cannot silently
// switch to another satisfaction.
function satisfier(data) {
  return {
    lookupEcdsaSig: (key) => (data.ecdsa ?? {})[key] ?? false,
    lookupTapKeySpendSig: () => {
      // The key-spend callback has no key argument: this map describes the
      // descriptor's single internal key.
      const sigs = Object.values(data.tap_key ?? {});
      assert.ok(sigs.length <= 1);
      return sigs[0] ?? false;
    },
    lookupTapLeafScriptSig: (key, leafHash) => {
      const sig = (data.tap_leaf ?? []).find(
        (s) => s.key === key && s.leaf_hash === leafHash,
      );
      return sig ? sig.signature : false;
    },
    lookupPreimage: (hashFunc, hash) => {
      const entry = (data.preimages ?? []).find(
        (a) => a.function === hashFunc && a.hash === hash,
      );
      return entry ? entry.preimage : false;
    },
  };
}

// The output script of the descriptor at the vector's indexes. A bare
// descriptor has no address, so its script code is the output script.
function outputScript(d, v) {
  if (d.descType() === 'Bare') {
    return toHex(d.scriptCodeAt(v.multipath_index, v.derivation_index));
  }

  const addr = d.addressAt(
    'mainnet', v.multipath_index, v.derivation_index,
  );
  return toHex(lib.txscript.payToAddrScript(addr, 'mainnet'));
}

// Executes the completed input under the standard verification flags. The
// library's own result is inserted into the transaction: using the fixture's
// expected stack here would verify the vector instead of the implementation.
function verifySpend(spend, result) {
  const tx = lib.tx.decode(spend.unsigned_tx);
  tx.inputs[spend.input_index].scriptSig = toHex(result.scriptSig);
  tx.inputs[spend.input_index].witness = result.witness.map(toHex);

  const prevOuts = spend.prevouts.map((p) => ({
    script: p.script_pubkey,
    amount: p.value,
  }));

  return lib.txscript.verifyScript(
    lib.tx.encode(tx), spend.input_index, prevOuts,
  ).valid;
}

// Repeats each completion attempt after damaging the returned bytes, which
// exercises byte ownership as well as reuse of the same plan, including
// after a failure.
function checkCompletion(plan, v, c) {
  for (let attempt = 0; attempt < 2; attempt++) {
    if (c.expected.error === 'satisfy') {
      assert.throws(
        () => plan.satisfy(satisfier(c.data)),
        `completion ${c.id} of ${v.id} should not satisfy`,
      );
      continue;
    }

    assert.ok(!c.expected.error);
    const result = plan.satisfy(satisfier(c.data));

    // Compare every assembled byte before checking signatures: correct
    // script execution alone would not detect an unexpected branch or
    // multisig subset that also happens to be spendable.
    assert.equal(toHex(result.scriptSig), c.expected.script_sig ?? '');
    assert.equal(result.witness.length, (c.expected.witness ?? []).length);
    result.witness.forEach((item, i) => {
      assert.equal(
        toHex(item), c.expected.witness[i], `witness item ${i}`,
      );
    });

    // Assembly-only fixtures may use synthetic signatures. Only the
    // explicitly signed cases are executed, and their expectation is
    // required so a missing field cannot silently weaken the test.
    if (c.verify) {
      assert.ok(v.transaction);
      assert.equal(typeof c.expected.valid, 'boolean');
      assert.equal(
        verifySpend(v.transaction, result), c.expected.valid,
        'script verification',
      );
    } else {
      assert.equal(c.expected.valid, undefined);
    }

    // A caller owns the returned bytes. Damaging them must not damage the
    // plan or the descriptor's future completions.
    result.witness.forEach((item) => item.fill(0xff));
    result.scriptSig.fill(0xff);
  }
}

describe('descriptors: spending vectors', () => {
  const seen = new Set();

  vectors.cases.forEach((v) => {
    // Stable, unique IDs keep failures attributable to the portable
    // vectors instead of letting the runner rename duplicates.
    assert.ok(!seen.has(v.id), `duplicate vector: ${v.id}`);
    seen.add(v.id);

    it(v.id, () => {
      // Parsing is checked separately: a rejection at the wrong stage must
      // not satisfy a planning or completion error vector.
      if (v.expected_plan.error === 'parse') {
        assert.throws(() => lib.descriptors.create(v.descriptor));
        return;
      }

      const d = lib.descriptors.create(v.descriptor);
      try {
        // The plan is selected from the advertised assets and locktime
        // context alone; concrete completion data must not influence it.
        if (v.expected_plan.error === 'plan') {
          assert.throws(() => d.planAt(
            v.multipath_index, v.derivation_index, planningAssets(v),
          ));
          return;
        }

        assert.ok(!v.expected_plan.error);
        const plan = d.planAt(
          v.multipath_index, v.derivation_index, planningAssets(v),
        );

        try {
          // Assert each serialized size as well as the total weight, so
          // an incorrect witness/scriptSig split cannot go unnoticed.
          assert.equal(
            plan.witnessSize, v.expected_plan.witness_size ?? 0,
            'witness size',
          );
          assert.equal(
            plan.scriptSigSize, v.expected_plan.script_sig_size ?? 0,
            'scriptSig size',
          );
          assert.equal(
            plan.satisfactionWeight, v.expected_plan.weight ?? 0,
            'weight',
          );

          assert.equal(outputScript(d, v), v.script_pubkey, 'output script');

          // Every completion reuses this exact plan, which catches a
          // fallback to a different spending path or corruption of the
          // plan by an earlier completion.
          v.completions.forEach((c) => checkCompletion(plan, v, c));
        } finally {
          plan.free();
        }
      } finally {
        d.free();
      }
    });
  });
});

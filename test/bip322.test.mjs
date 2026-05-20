import './setup.mjs';
import {describe, it} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {bip322, wif} from '../dist/index.js';

const basic = JSON.parse(readFileSync(
  new URL('test-vectors/basic-test-vectors.json', import.meta.url), 'utf-8',
));
const generated = JSON.parse(readFileSync(
  new URL('test-vectors/generated-test-vectors.json', import.meta.url), 'utf-8',
));

function runSuite(name, vectors) {
  describe(name, () => {
    for (const vec of vectors) {
      for (const sig of vec.bip322_signatures) {
        const label = `${vec.type} | ${vec.address.slice(0, 16)}… | ` +
          `"${vec.message.slice(0, 30)}"`;
        it(label, async () => {
          const result = await bip322.verifyMessage(
            vec.message,
            vec.address,
            sig,
            'mainnet',
          );
          assert.equal(
            result.valid,
            true,
            `expected valid=true, got error: ${result.error}`,
          );

          // Verify the optional time constraints.
          if (vec.lock_time > 0 || vec.sequence > 0) {
            assert.deepEqual(
              result.timeConstraints,
              {
                constrained: true,
                validAtTime: vec.lock_time,
                validAtAge: vec.sequence,
              }
            );
          } else {
            assert.equal(
              result.timeConstraints,
              undefined,
              'expected timeConstraints=undefined',
            );
          }

          await assert.rejects(async () => {
            await bip322.verifyMessage(
              vec.message + 'x',
              vec.address,
              sig,
              'mainnet',
            );
          }, 'invalid signature');
        });
      }
    }
  });
}

function runErrorSuite(name, vectors) {
  describe(name, () => {
    for (const vec of vectors) {
      it(vec.description, async () => {
        await assert.rejects(async () => {
          await bip322.verifyMessage(
            vec.message,
            vec.address,
            vec.signature,
            'mainnet',
          );
        }, vec.error_substr);
      });
    }
  });
}

runSuite('bip322: basic-test-vectors simple', basic.simple);
runErrorSuite('bip322: basic-test-vectors error', basic.error);
runSuite('bip322: generated-test-vectors simple', generated.simple);
runSuite('bip322: generated-test-vectors full', generated.full);
runErrorSuite('bip322: generated-test-vectors error', generated.error);

const signers = {
  'p2tr': bip322.signP2TR,
  'p2wpkh': bip322.signP2WPKH,
  'p2sh-p2wpkh': bip322.signNestedP2WPKH,
  'p2pkh': bip322.signP2PKH,
};

function runSignSuite(name, vectors) {
  describe(name, () => {
    for (const vec of vectors) {
      const signer = signers[vec.type];
      if (!signer || vec.private_keys.length !== 1) {
        continue;
      }
      const label = `sign ${vec.type} | ${vec.address.slice(0, 16)}… | ` +
        `"${vec.message.slice(0, 30)}"`;
      it(label, async () => {
        const decoded = await wif.decode(vec.private_keys[0]);
        const sig = await signer(vec.message, decoded.privateKey);
        const result = await bip322.verifyMessage(
          vec.message, vec.address, sig, 'mainnet',
        );
        assert.equal(result.valid, true,
          `expected valid=true, got error: ${result.error}`);
      });
    }
  });
}

runSignSuite('bip322: sign+verify roundtrip (simple)', generated.simple);
runSignSuite('bip322: sign+verify roundtrip (full)', generated.full);

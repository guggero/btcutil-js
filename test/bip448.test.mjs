import './setup.mjs';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { init } from '../dist/index.js';
import { toHex } from './util.mjs';

// The synchronous API keeps the transaction building below readable.
const lib = await init();
const { txscript, btcec, chainhash, tx } = lib;

// The flags a node enforces on blocks once the three op codes of BIP 448 are
// active.
const consensusFlags = [
  'P2SH', 'DERSIG', 'CHECKLOCKTIMEVERIFY', 'CHECKSEQUENCEVERIFY', 'WITNESS',
  'NULLDUMMY', 'TAPROOT', 'TEMPLATEHASH', 'CHECKSIGFROMSTACK', 'INTERNALKEY',
];

// The flags of the three op codes and the flags that discourage them.
const upgradeFlags = ['TEMPLATEHASH', 'CHECKSIGFROMSTACK', 'INTERNALKEY'];
const discourageFlags = upgradeFlags.map((f) => `DISCOURAGE_${f}`);

// The standard flags with the three op codes active, i.e. the mempool policy
// after activation.
const activeFlags = txscript.standardScriptFlags().filter(
  (f) => !discourageFlags.includes(f),
);

// The standard flags as if the op codes had never been defined: they are
// plain OP_SUCCESS op codes, which a consensus check accepts.
const inactiveFlags = activeFlags.filter(
  (f) => !upgradeFlags.includes(f) && f !== 'DISCOURAGE_OP_SUCCESS',
);

// Builds a transaction spending one taproot output through the given leaf
// script. The witness is whatever stack() returns for the unsigned
// transaction, followed by the script and the control block.
function tapscriptSpend(privKey, asm, stack, outputValue = 90_000) {
  const internalKey = btcec.schnorrSerializePubKey(
    btcec.privKeyFromBytes(privKey).publicKey,
  );
  const script = txscript.assembleScript(asm);
  const tree = txscript.assembleTaprootScriptTree(internalKey, [{ script }]);
  const prevOuts = [{
    script: txscript.payToTaprootScript(tree.outputKey),
    amount: 100_000,
  }];

  const data = {
    version: 2,
    locktime: 0,
    inputs: [{
      txid: '11'.repeat(32), vout: 0, scriptSig: '', sequence: 0xfffffffd,
    }],
    outputs: [{
      value: outputValue,
      scriptPubKey: '0014751e76e8199196d454941c45d1b3a323f1433bd6',
    }],
  };
  const unsigned = tx.encode(data);

  data.inputs[0].witness = [
    ...stack({ unsigned, prevOuts, script, internalKey }),
    script,
    tree.leaves[0].controlBlock,
  ].map((item) => (typeof item === 'string' ? item : toHex(item)));

  return { rawTx: tx.encode(data), prevOuts, script, internalKey, tree };
}

const privKey = '0101010101010101010101010101010101010101010101010101010101010101';
const otherPrivKey = '0202020202020202020202020202020202020202020202020202020202020202';

// A signature of the internal key over the template hash: the spend commits
// to the outputs of the transaction but to none of its inputs.
const rebindableScript = 'OP_TEMPLATEHASH OP_INTERNALKEY OP_CHECKSIGFROMSTACK';
function signTemplate(key) {
  return ({ unsigned }) => [
    btcec.schnorrSign(key, txscript.calcTemplateHash(unsigned, 0)),
  ];
}

describe('txscript: script flags', () => {
  it('lists every flag once', () => {
    const names = txscript.scriptFlagNames();
    assert.equal(new Set(names).size, names.length);
    for (const flag of [...consensusFlags, ...discourageFlags]) {
      assert.ok(names.includes(flag), flag);
    }
  });

  it('standard flags are a subset that discourages the upgrades', () => {
    const names = txscript.scriptFlagNames();
    const standard = txscript.standardScriptFlags();
    for (const flag of standard) {
      assert.ok(names.includes(flag), flag);
    }
    for (const flag of [...upgradeFlags, ...discourageFlags]) {
      assert.ok(standard.includes(flag), flag);
    }

    // Policy only flags that are not part of the standard set.
    assert.ok(!standard.includes('RESTRICT_SIGHASH'));
    assert.ok(!standard.includes('SIGPUSHONLY'));
  });

  it('rejects unknown and malformed flags', () => {
    const { rawTx, prevOuts } = tapscriptSpend(privKey, 'OP_1', () => []);
    assert.throws(
      () => txscript.verifyScript(rawTx, 0, prevOuts, ['NOPE']),
      /unknown script flag: NOPE/,
    );
    assert.throws(
      () => txscript.verifyScript(rawTx, 0, prevOuts, 'TAPROOT'),
      /array of flag names/,
    );
    assert.throws(
      () => txscript.verifyScript(rawTx, 0, prevOuts, [1]),
      /array of flag names/,
    );
  });
});

describe('txscript: assembleScript', () => {
  it('assembles op codes, numbers and data', () => {
    assert.equal(toHex(txscript.assembleScript('')), '');
    assert.equal(
      toHex(txscript.assembleScript('OP_DUP OP_HASH160 OP_EQUALVERIFY')),
      '76a988',
    );
    assert.equal(toHex(txscript.assembleScript('-1 0 1 16')), '4f005160');
    assert.equal(toHex(txscript.assembleScript('OP_0 OP_16')), '0060');
    assert.equal(toHex(txscript.assembleScript('abcd')), '02abcd');
    assert.equal(toHex(txscript.assembleScript('  abcd\n\tOP_DROP ')), '02abcd75');
  });

  it('tells numbers from data', () => {
    // 10 is the number ten, 0x10 the byte 0x10, i.e. the number sixteen.
    assert.equal(toHex(txscript.assembleScript('10')), '5a');
    assert.equal(toHex(txscript.assembleScript('0x10')), '60');
    assert.equal(toHex(txscript.assembleScript('0x11')), '0111');
    // More than two digits is always data.
    assert.equal(toHex(txscript.assembleScript('0016')), '020016');
    // Outside of -1..16 there is no op code, so it is data.
    assert.equal(toHex(txscript.assembleScript('17')), '0117');
    // Data that has an op code of its own uses it, as a minimal push must.
    assert.equal(toHex(txscript.assembleScript('0x01')), '51');
  });

  it('uses the right push op code for the size', () => {
    assert.equal(
      toHex(txscript.assembleScript('aa'.repeat(75))).slice(0, 2), '4b',
    );
    assert.equal(
      toHex(txscript.assembleScript('aa'.repeat(76))).slice(0, 4), '4c4c',
    );
    assert.equal(
      toHex(txscript.assembleScript('aa'.repeat(256))).slice(0, 6), '4d0001',
    );
  });

  it('knows the BIP 448 op codes under both names', () => {
    assert.equal(
      toHex(txscript.assembleScript(rebindableScript)), 'cecbcc',
    );
    assert.equal(
      toHex(txscript.assembleScript(
        'OP_UNKNOWN206 OP_UNKNOWN203 OP_UNKNOWN204',
      )), 'cecbcc',
    );
    assert.equal(txscript.disasmString('cecbcc'), rebindableScript);
  });

  it('round trips through disasmString', () => {
    for (const asm of [
      'OP_DUP OP_HASH160 751e76e8199196d454941c45d1b3a323f1433bd6 ' +
        'OP_EQUALVERIFY OP_CHECKSIG',
      '0 751e76e8199196d454941c45d1b3a323f1433bd6',
      '2 ' + '02'.repeat(33) + ' ' + '03'.repeat(33) + ' 2 OP_CHECKMULTISIG',
      'OP_IF OP_TEMPLATEHASH OP_ELSE -1 OP_ENDIF',
    ]) {
      assert.equal(txscript.disasmString(txscript.assembleScript(asm)), asm);
    }
  });

  it('rejects what it does not understand', () => {
    assert.throws(() => txscript.assembleScript('OP_NOPE'), /unknown op code/);
    assert.throws(() => txscript.assembleScript('OP_DATA_1'), /needs data/);
    assert.throws(() => txscript.assembleScript('OP_PUSHDATA1'), /needs data/);
    assert.throws(() => txscript.assembleScript('abc'), /invalid token/);
    assert.throws(() => txscript.assembleScript('hello'), /invalid token/);
    assert.throws(() => txscript.assembleScript('-2'), /invalid token/);
    assert.throws(() => txscript.assembleScript('aa'.repeat(521)), /assembleScript/);
    assert.throws(() => txscript.assembleScript(42), /must be a string/);
  });
});

describe('txscript: BIP 446 template hash', () => {
  const vectors = JSON.parse(readFileSync(
    new URL('./test-vectors/bip446-basics.json', import.meta.url), 'utf8',
  ));

  // A spent output is serialized as in a transaction: the value followed by
  // the length prefixed script. All scripts here are shorter than 253 bytes.
  function parsePrevOut(hex) {
    const raw = Buffer.from(hex, 'hex');
    assert.equal(raw[8], raw.length - 9);
    return {
      amount: Number(raw.readBigUInt64LE(0)),
      script: raw.subarray(9).toString('hex'),
    };
  }

  it('verifies the BIP test vectors', () => {
    assert.ok(vectors.length > 0);
    for (const v of vectors) {
      const prevOuts = v.spent_outputs.map(parsePrevOut);
      const result = txscript.verifyScript(
        v.spending_tx, v.input_index, prevOuts, consensusFlags,
      );
      assert.equal(result.valid, v.valid, `${v.comment}: ${result.error}`);

      // Before activation every one of them is a valid spend.
      const before = txscript.verifyScript(
        v.spending_tx, v.input_index, prevOuts,
        consensusFlags.filter((f) => f !== 'TEMPLATEHASH'),
      );
      assert.equal(before.valid, true, `${v.comment}: ${before.error}`);
    }
  });

  it('splits the hash into its fields', () => {
    for (const v of vectors) {
      const decoded = tx.decode(v.spending_tx);
      const witness = decoded.inputs[v.input_index].witness;
      const last = witness[witness.length - 1];
      const annex = witness.length > 1 && last.length > 0 && last[0] === 0x50
        ? last : undefined;

      const hash = txscript.calcTemplateHash(
        v.spending_tx, v.input_index, annex,
      );
      const pre = txscript.templateHashPreimage(
        v.spending_tx, v.input_index, annex,
      );

      assert.equal(hash.length, 32);
      assert.equal(toHex(pre.hash), toHex(hash));
      assert.equal(pre.tag, 'TemplateHash');
      assert.equal(
        toHex(chainhash.taggedHash(
          Buffer.from(pre.tag).toString('hex'), [pre.message],
        )),
        toHex(hash),
      );

      const fields = [
        pre.version, pre.lockTime, pre.shaSequences, pre.shaOutputs,
        pre.annexPresent, pre.inputIndex,
      ];
      if (annex) {
        assert.equal(toHex(pre.annexPresent), '01');
        assert.equal(pre.shaAnnex.length, 32);
        fields.push(pre.shaAnnex);
      } else {
        assert.equal(toHex(pre.annexPresent), '00');
        assert.equal(pre.shaAnnex, undefined);
      }
      assert.equal(fields.map(toHex).join(''), toHex(pre.message));

      const versionLE = Buffer.alloc(4);
      versionLE.writeInt32LE(decoded.version);
      assert.equal(toHex(pre.version), versionLE.toString('hex'));
      assert.equal(Buffer.from(pre.lockTime).readUInt32LE(), decoded.locktime);
      assert.equal(Buffer.from(pre.inputIndex).readUInt32LE(), v.input_index);
    }
  });

  it('commits to the outputs, sequences, index and annex only', () => {
    const data = {
      version: 2,
      locktime: 0,
      inputs: [
        { txid: '11'.repeat(32), vout: 0, scriptSig: '', sequence: 1 },
        { txid: '22'.repeat(32), vout: 1, scriptSig: '', sequence: 2 },
      ],
      outputs: [{ value: 1000, scriptPubKey: '51' }],
    };
    const base = toHex(txscript.calcTemplateHash(tx.encode(data), 0));
    const hashOf = (change, idx = 0, annex) => {
      const copy = structuredClone(data);
      change(copy);
      return toHex(txscript.calcTemplateHash(tx.encode(copy), idx, annex));
    };

    // Not committed to: which outputs are spent.
    assert.equal(hashOf((d) => { d.inputs[0].txid = '33'.repeat(32); }), base);
    assert.equal(hashOf((d) => { d.inputs[1].vout = 7; }), base);

    // Committed to.
    assert.notEqual(hashOf((d) => { d.version = 3; }), base);
    assert.notEqual(hashOf((d) => { d.locktime = 1; }), base);
    assert.notEqual(hashOf((d) => { d.inputs[1].sequence = 3; }), base);
    assert.notEqual(hashOf((d) => { d.outputs[0].value = 1001; }), base);
    assert.notEqual(hashOf((d) => { d.outputs[0].scriptPubKey = '52'; }), base);
    assert.notEqual(hashOf(() => {}, 1), base);
    assert.notEqual(hashOf(() => {}, 0, '50'), base);
    assert.notEqual(hashOf(() => {}, 0, '50'), hashOf(() => {}, 0, '5000'));
  });

  it('rejects bad arguments', () => {
    const rawTx = vectors[0].spending_tx;
    assert.throws(() => txscript.calcTemplateHash(rawTx, 99), /out of range/);
    assert.throws(() => txscript.calcTemplateHash(rawTx, -1), /out of range/);
    assert.throws(
      () => txscript.calcTemplateHash(rawTx, 0, '51'), /must start with 0x50/,
    );
    assert.throws(
      () => txscript.templateHashPreimage(rawTx, 0, '51'),
      /must start with 0x50/,
    );
    assert.throws(() => txscript.calcTemplateHash('zz', 0), /invalid hex/);
  });
});

describe('btcec: schnorrVerifyMessage', () => {
  // BIP 340 test vectors 15 to 18: messages that are not 32 bytes long.
  const pubKey =
    '778caa53b4393ac467774d09497a87224bf9fab6f6e68b23086497324d6fd117';
  const vectors = [
    ['',
      '71535db165ecd9fbbc046e5ffaea61186bb6ad436732fccc25291a55895464cf' +
      '6069ce26bf03466228f19a3a62db8a649f2d560fac652827d1af0574e427ab63'],
    ['11',
      '08a20a0afef64124649232e0693c583ab1b9934ae63b4c3511f3ae1134c6a303' +
      'ea3173bfea6683bd101fa5aa5dbc1996fe7cacfc5a577d33ec14564cec2bacbf'],
    ['0102030405060708090a0b0c0d0e0f1011',
      '5130f39a4059b43bc7cac09a19ece52b5d8699d1a71e3c52da9afdb6b50ac370' +
      'c4a482b77bf960f8681540e25b6771ece1e5a37fd80e5a51897c5566a97ea5a5'],
    ['99'.repeat(100),
      '403b12b0d8555a344175ea7ec746566303321e5dbfa8be6f091635163eca79a8' +
      '585ed3e3170807e7c03b720fc54c7b23897fcba0e9d0b4a06894cfd249f22367'],
  ];

  it('verifies messages of any length', () => {
    for (const [msg, sig] of vectors) {
      assert.equal(btcec.schnorrVerifyMessage(pubKey, msg, sig), true, msg);
      assert.equal(
        btcec.schnorrVerifyMessage(pubKey, msg + '00', sig), false, msg,
      );
    }
  });

  it('agrees with schnorrVerify on 32-byte messages', () => {
    const hash = chainhash.hash('68656c6c6f');
    const key = btcec.privKeyFromBytes(privKey);
    const xOnly = btcec.schnorrSerializePubKey(key.publicKey);
    const sig = btcec.schnorrSign(privKey, hash);
    assert.equal(btcec.schnorrVerify(xOnly, hash, sig), true);
    assert.equal(btcec.schnorrVerifyMessage(xOnly, hash, sig), true);
    assert.equal(btcec.schnorrVerifyMessage(key.publicKey, hash, sig), true);
  });

  it('verifies what schnorrSignMessage signs', () => {
    const xOnly = btcec.schnorrSerializePubKey(
      btcec.privKeyFromBytes(privKey).publicKey,
    );
    const nonces = new Set();
    for (const msg of ['', '00', '11', 'aa'.repeat(31), 'aa'.repeat(33),
      'bb'.repeat(1000)]) {
      const sig = btcec.schnorrSignMessage(privKey, msg);
      assert.equal(sig.length, 64);
      assert.equal(btcec.schnorrVerifyMessage(xOnly, msg, sig), true, msg);
      assert.equal(
        btcec.schnorrVerifyMessage(xOnly, msg + '00', sig), false, msg,
      );

      // Deterministic, and every message has a nonce of its own.
      assert.equal(toHex(btcec.schnorrSignMessage(privKey, msg)), toHex(sig));
      nonces.add(toHex(sig.subarray(0, 32)));

      // Only a 32-byte message can be signed as a hash.
      assert.throws(() => btcec.schnorrSign(privKey, msg), /wrong size/);
    }
    assert.equal(nonces.size, 6);
  });

  it('signs a 32-byte message like schnorrSign', () => {
    const hash = chainhash.hash('68656c6c6f');
    assert.equal(
      toHex(btcec.schnorrSignMessage(privKey, hash)),
      toHex(btcec.schnorrSign(privKey, hash)),
    );
  });

  it('rejects malformed keys and signatures', () => {
    assert.throws(
      () => btcec.schnorrVerifyMessage('00', '', vectors[0][1]), /parsePubKey/,
    );
    assert.throws(
      () => btcec.schnorrVerifyMessage(pubKey, '', '00'), /parseSignature/,
    );
  });
});

describe('txscript: BIP 448 script execution', () => {
  it('executes a rebindable signature once active', () => {
    const spend = tapscriptSpend(privKey, rebindableScript, signTemplate(privKey));
    assert.deepEqual(
      txscript.verifyScript(spend.rawTx, 0, spend.prevOuts, activeFlags),
      { valid: true },
    );
    assert.deepEqual(
      txscript.verifyScript(spend.rawTx, 0, spend.prevOuts, consensusFlags),
      { valid: true },
    );
  });

  it('discourages the op codes under the standard flags', () => {
    const spend = tapscriptSpend(privKey, rebindableScript, signTemplate(privKey));
    for (const flags of [undefined, null, txscript.standardScriptFlags()]) {
      const result = txscript.verifyScript(spend.rawTx, 0, spend.prevOuts, flags);
      assert.equal(result.valid, false);
      // The op code that comes first in the script is the one reported.
      assert.equal(result.errorCode, 'ErrDiscourageTemplateHash');
      assert.match(result.error, /OP_TEMPLATEHASH/);
    }

    // Each op code is discouraged on its own.
    const cases = [
      ['OP_INTERNALKEY', 'ErrDiscourageInternalKey'],
      ['OP_CHECKSIGFROMSTACK', 'ErrDiscourageCheckSigFromStack'],
    ];
    for (const [asm, code] of cases) {
      const s = tapscriptSpend(privKey, asm, () => []);
      assert.equal(
        txscript.verifyScript(s.rawTx, 0, s.prevOuts).errorCode, code,
      );
    }
  });

  it('treats the op codes as OP_SUCCESS while inactive', () => {
    // Without the upgrades any witness spends the output, even a signature
    // of the wrong key.
    const spend = tapscriptSpend(
      privKey, rebindableScript, signTemplate(otherPrivKey),
    );
    assert.deepEqual(
      txscript.verifyScript(spend.rawTx, 0, spend.prevOuts, inactiveFlags),
      { valid: true },
    );

    // The standard flags don't let such a spend into the mempool.
    const discouraged = txscript.verifyScript(
      spend.rawTx, 0, spend.prevOuts,
      [...inactiveFlags, 'DISCOURAGE_OP_SUCCESS'],
    );
    assert.equal(discouraged.errorCode, 'ErrDiscourageOpSuccess');

    // A single inactive op code is enough to make the whole script succeed.
    const mixed = activeFlags.filter((f) => f !== 'INTERNALKEY' &&
      f !== 'DISCOURAGE_OP_SUCCESS');
    assert.deepEqual(
      txscript.verifyScript(spend.rawTx, 0, spend.prevOuts, mixed),
      { valid: true },
    );
  });

  it('rejects a signature of another key or transaction', () => {
    const wrongKey = tapscriptSpend(
      privKey, rebindableScript, signTemplate(otherPrivKey),
    );
    const result = txscript.verifyScript(
      wrongKey.rawTx, 0, wrongKey.prevOuts, activeFlags,
    );
    assert.equal(result.valid, false);
    assert.equal(result.errorCode, 'ErrTaprootSigInvalid');

    // A signature made for other outputs doesn't fit this transaction.
    const good = tapscriptSpend(privKey, rebindableScript, signTemplate(privKey));
    const sig = tx.decode(good.rawTx).inputs[0].witness[0];
    const other = tapscriptSpend(privKey, rebindableScript, () => [sig], 80_000);
    assert.equal(
      txscript.verifyScript(other.rawTx, 0, other.prevOuts, activeFlags)
        .errorCode,
      'ErrTaprootSigInvalid',
    );
  });

  it('rebinds a signature to another output with the same script', () => {
    const good = tapscriptSpend(privKey, rebindableScript, signTemplate(privKey));
    const decoded = tx.decode(good.rawTx);

    // Spend a different outpoint of a different value with the very same
    // witness: the template hash doesn't commit to either.
    decoded.inputs[0].txid = '44'.repeat(32);
    decoded.inputs[0].vout = 3;
    const rebound = tx.encode(decoded);
    const prevOuts = [{ script: good.prevOuts[0].script, amount: 123_456 }];

    assert.notEqual(tx.hash(rebound), tx.hash(good.rawTx));
    assert.deepEqual(
      txscript.verifyScript(rebound, 0, prevOuts, activeFlags),
      { valid: true },
    );
  });

  it('checks a signature over an arbitrary message', () => {
    const key = btcec.schnorrSerializePubKey(
      btcec.privKeyFromBytes(otherPrivKey).publicKey,
    );
    const message = chainhash.hash(Buffer.from('price > 100000').toString('hex'));
    const sig = btcec.schnorrSign(otherPrivKey, message);
    const asm = `${toHex(message)} ${toHex(key)} OP_CHECKSIGFROMSTACK`;

    const good = tapscriptSpend(privKey, asm, () => [sig]);
    assert.deepEqual(
      txscript.verifyScript(good.rawTx, 0, good.prevOuts, activeFlags),
      { valid: true },
    );

    // An empty signature makes the op code push an empty vector instead of
    // failing, which leaves a false value on the stack.
    const empty = tapscriptSpend(privKey, asm, () => ['']);
    assert.equal(
      txscript.verifyScript(empty.rawTx, 0, empty.prevOuts, activeFlags)
        .errorCode,
      'ErrEvalFalse',
    );

    // The message doesn't have to be a hash.
    const text = Buffer.from('price > 100000').toString('hex');
    const textAsm = `${text} ${toHex(key)} OP_CHECKSIGFROMSTACK`;
    const textSpend = tapscriptSpend(
      privKey, textAsm, () => [btcec.schnorrSignMessage(otherPrivKey, text)],
    );
    assert.deepEqual(
      txscript.verifyScript(textSpend.rawTx, 0, textSpend.prevOuts, activeFlags),
      { valid: true },
    );

    // A signature of the wrong length fails the script.
    const short = tapscriptSpend(privKey, asm, () => [sig.subarray(0, 63)]);
    assert.equal(
      txscript.verifyScript(short.rawTx, 0, short.prevOuts, activeFlags)
        .errorCode,
      'ErrInvalidTaprootSigLen',
    );
  });

  it('pushes the internal key', () => {
    const spend = tapscriptSpend(
      privKey, 'OP_INTERNALKEY OP_EQUAL', ({ internalKey }) => [internalKey],
    );
    assert.deepEqual(
      txscript.verifyScript(spend.rawTx, 0, spend.prevOuts, activeFlags),
      { valid: true },
    );

    const wrong = tapscriptSpend(
      privKey, 'OP_INTERNALKEY OP_EQUAL', () => ['00'.repeat(32)],
    );
    assert.equal(
      txscript.verifyScript(wrong.rawTx, 0, wrong.prevOuts, activeFlags)
        .errorCode,
      'ErrEvalFalse',
    );
  });
});

describe('txscript: calcTapscriptSignatureHash', () => {
  const xOnly = toHex(btcec.schnorrSerializePubKey(
    btcec.privKeyFromBytes(privKey).publicKey,
  ));

  it('signs an OP_CHECKSIG of a tapscript leaf', () => {
    const sign = (hashType) => ({ unsigned, prevOuts, script }) => {
      const sigHash = txscript.calcTapscriptSignatureHash(
        hashType, unsigned, 0, prevOuts, script,
      );
      assert.equal(sigHash.length, 32);
      const sig = btcec.schnorrSign(privKey, sigHash);
      return [hashType === 0 ? sig : toHex(sig) + '0' + hashType];
    };

    for (const hashType of [0, 1, 3]) {
      const spend = tapscriptSpend(
        privKey, `${xOnly} OP_CHECKSIG`, sign(hashType),
      );
      assert.deepEqual(
        txscript.verifyScript(spend.rawTx, 0, spend.prevOuts),
        { valid: true },
        `hash type ${hashType}`,
      );
    }
  });

  it('differs from the key path signature hash', () => {
    const spend = tapscriptSpend(privKey, `${xOnly} OP_CHECKSIG`, () => []);
    const leaf = txscript.calcTapscriptSignatureHash(
      0, spend.rawTx, 0, spend.prevOuts, spend.script,
    );
    const keyPath = txscript.calcTaprootSignatureHash(
      0, spend.rawTx, 0, spend.prevOuts,
    );
    assert.notEqual(toHex(leaf), toHex(keyPath));

    const annexed = txscript.calcTapscriptSignatureHash(
      0, spend.rawTx, 0, spend.prevOuts, spend.script, '50aa',
    );
    assert.notEqual(toHex(annexed), toHex(leaf));
  });

  it('rejects bad arguments', () => {
    const spend = tapscriptSpend(privKey, `${xOnly} OP_CHECKSIG`, () => []);
    assert.throws(
      () => txscript.calcTapscriptSignatureHash(
        0, spend.rawTx, 1, spend.prevOuts, spend.script,
      ),
      /out of range/,
    );
    assert.throws(
      () => txscript.calcTapscriptSignatureHash(
        0, spend.rawTx, 0, [], spend.script,
      ),
      /expected 1 previous outputs/,
    );
  });
});

describe('txscript: traceScript', () => {
  it('records every step of a tapscript spend', () => {
    const spend = tapscriptSpend(privKey, rebindableScript, signTemplate(privKey));
    const trace = txscript.traceScript(
      spend.rawTx, 0, spend.prevOuts, activeFlags,
    );
    const sig = tx.decode(spend.rawTx).inputs[0].witness[0];
    const templateHash = txscript.calcTemplateHash(spend.rawTx, 0);

    assert.equal(trace.valid, true);
    assert.equal(trace.error, undefined);
    assert.equal(trace.opSuccess, false);

    // The signature script, the public key script and the tapscript.
    assert.equal(trace.scripts.length, 3);
    assert.deepEqual(trace.scripts[0], []);
    assert.equal(trace.scripts[1].length, 2);
    assert.deepEqual(trace.scripts[2], rebindableScript.split(' '));

    // The steps of the tapscript: one before each op code and a final one.
    const steps = trace.steps.filter((s) => s.scriptIndex === 2);
    assert.deepEqual(
      steps.map((s) => s.opcode),
      [...rebindableScript.split(' '), undefined],
    );
    assert.deepEqual(steps.map((s) => s.opcodeIndex), [0, 1, 2, 3]);
    assert.deepEqual(
      steps.map((s) => s.stack.map(toHex)),
      [
        [toHex(sig)],
        [toHex(sig), toHex(templateHash)],
        [toHex(sig), toHex(templateHash), toHex(spend.internalKey)],
        ['01'],
      ],
    );
    for (const step of trace.steps) {
      assert.deepEqual(step.altStack, []);
    }

    // The last step is the last one overall.
    assert.equal(trace.steps[trace.steps.length - 1], steps[3]);

    // The budget is 50 plus the size of the serialized witness: the item
    // count, then the signature, the script and the control block with their
    // length prefixes. The one signature check uses up 50 of it.
    const witnessSize = 1 + (1 + 64) + (1 + 3) + (1 + 33);
    assert.deepEqual(
      steps.map((s) => s.sigOpsBudget),
      [50 + witnessSize, 50 + witnessSize, 50 + witnessSize, witnessSize],
    );
    for (const step of trace.steps.filter((s) => s.scriptIndex < 2)) {
      assert.equal(step.sigOpsBudget, undefined);
    }
  });

  it('runs out of signature operation budget', () => {
    // Every byte of the witness adds one to the budget and every signature
    // check costs 50, so repeating a three byte check uses it up: the budget
    // of roughly 240 pays for four of the six checks.
    const key = toHex(btcec.schnorrSerializePubKey(
      btcec.privKeyFromBytes(privKey).publicKey,
    ));
    const msg = '00'.repeat(32);
    const sig = btcec.schnorrSign(privKey, msg);
    const check = 'OP_3DUP OP_CHECKSIGFROMSTACK OP_VERIFY';
    const asm = `${msg} ${key} ${Array(6).fill(check).join(' ')} ` +
      'OP_2DROP OP_DROP 1';

    const spend = tapscriptSpend(privKey, asm, () => [sig]);
    const trace = txscript.traceScript(
      spend.rawTx, 0, spend.prevOuts, activeFlags,
    );
    assert.equal(trace.valid, false);
    assert.equal(trace.errorCode, 'ErrTaprootMaxSigOps');

    const budgets = trace.steps
      .filter((s) => s.scriptIndex === 2)
      .map((s) => s.sigOpsBudget);
    assert.ok(budgets.every((b) => b >= 0));
    assert.ok(budgets[budgets.length - 1] < 50);
    assert.equal(budgets[0] - budgets[budgets.length - 1], 4 * 50);
    const last = trace.steps[trace.steps.length - 1];
    assert.equal(last.opcode, 'OP_CHECKSIGFROMSTACK');
  });

  it('stops at the failing op code', () => {
    const spend = tapscriptSpend(
      privKey, rebindableScript, signTemplate(otherPrivKey),
    );
    const trace = txscript.traceScript(
      spend.rawTx, 0, spend.prevOuts, activeFlags,
    );
    assert.equal(trace.valid, false);
    assert.equal(trace.errorCode, 'ErrTaprootSigInvalid');

    const last = trace.steps[trace.steps.length - 1];
    assert.equal(last.scriptIndex, 2);
    assert.equal(last.opcodeIndex, 2);
    assert.equal(last.opcode, 'OP_CHECKSIGFROMSTACK');
    assert.equal(last.stack.length, 3);
  });

  it('shows the alt stack and skipped branches', () => {
    const spend = tapscriptSpend(
      privKey,
      '5 OP_TOALTSTACK OP_IF 2 OP_ELSE 3 OP_ENDIF OP_FROMALTSTACK OP_ADD ' +
        '8 OP_EQUAL',
      () => [''],
    );
    const trace = txscript.traceScript(spend.rawTx, 0, spend.prevOuts);
    assert.equal(trace.valid, true, trace.error);

    const steps = trace.steps.filter((s) => s.scriptIndex === 2);
    assert.equal(steps.length, trace.scripts[2].length + 1);

    // After OP_TOALTSTACK the 5 is on the alt stack.
    assert.deepEqual(steps[2].altStack.map(toHex), ['05']);
    assert.deepEqual(steps[2].stack.map(toHex), ['']);

    // The branch that isn't taken is stepped over without an effect.
    const afterIf = steps[trace.scripts[2].indexOf('OP_ENDIF') + 1];
    assert.deepEqual(afterIf.stack.map(toHex), ['03']);
    assert.deepEqual(steps[steps.length - 1].stack.map(toHex), ['01']);
  });

  it('does not list a tapscript skipped by OP_SUCCESS', () => {
    const spend = tapscriptSpend(privKey, rebindableScript, () => []);
    const trace = txscript.traceScript(
      spend.rawTx, 0, spend.prevOuts, inactiveFlags,
    );
    assert.equal(trace.valid, true);
    assert.equal(trace.opSuccess, true);
    assert.equal(trace.scripts.length, 2);
    assert.ok(trace.steps.every((s) => s.scriptIndex < 2));

    // One op code that is still an OP_SUCCESS is enough.
    const mixed = txscript.traceScript(
      spend.rawTx, 0, spend.prevOuts,
      activeFlags.filter((f) => f !== 'INTERNALKEY' &&
        f !== 'DISCOURAGE_OP_SUCCESS'),
    );
    assert.equal(mixed.valid, true);
    assert.equal(mixed.opSuccess, true);
  });

  it('reports a spend the engine refuses to set up', () => {
    const spend = tapscriptSpend(privKey, rebindableScript, signTemplate(privKey));
    const trace = txscript.traceScript(spend.rawTx, 0, spend.prevOuts);
    assert.equal(trace.valid, false);
    assert.equal(trace.errorCode, 'ErrDiscourageTemplateHash');
    assert.equal(trace.opSuccess, false);
    assert.ok(Array.isArray(trace.scripts));
    assert.ok(Array.isArray(trace.steps));
  });

  it('agrees with verifyScript', () => {
    const p2wpkh = tapscriptSpend(privKey, 'OP_1', () => []);
    for (const flags of [undefined, activeFlags, consensusFlags, []]) {
      const verify = txscript.verifyScript(p2wpkh.rawTx, 0, p2wpkh.prevOuts, flags);
      const trace = txscript.traceScript(p2wpkh.rawTx, 0, p2wpkh.prevOuts, flags);
      assert.equal(trace.valid, verify.valid);
      assert.equal(trace.errorCode, verify.errorCode);
    }
  });
});

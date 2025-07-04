import { ec as EC } from 'elliptic';
import { parseArgs, toBuffer, broadcastTransaction } from './scripts/utils';
import { getHDNodeFromMnemonic, rlpEncode, keccak256 } from './scripts/crypto';

// --- Main execution ---

(async () => {
  const argv = parseArgs();
  let mnemonic = argv.mnemonic ? argv.mnemonic : 'test test test test test test test test test test test junk';

  const node = getHDNodeFromMnemonic(mnemonic);
  const priv = node.key;
  const ec = new EC('secp256k1');
  const key = ec.keyFromPrivate(priv);

  const txData = [
    argv.nonce,
    BigInt(argv.gasPrice),
    argv.gasLimit,
    Buffer.from(argv.to.replace(/^0x/, ''), 'hex'),
    BigInt(Math.floor(argv.value * 1e18)),
    Buffer.alloc(0),
    argv.chainId,
    0,
    0
  ];

  const rlpBody = rlpEncode(txData);
  const hash = keccak256(rlpBody);
  const sig = key.sign(hash, { canonical: true });
  const v = BigInt(argv.chainId * 2 + 35 + sig.recoveryParam!);

  txData[6] = v;
  txData[7] = Buffer.from(sig.r.toArray('be', 32));
  txData[8] = Buffer.from(sig.s.toArray('be', 32));

  const raw = rlpEncode(txData).toString('hex');
  const txHash = keccak256(Buffer.from(raw, 'hex')).toString('hex');
  if (argv.endpoint) {
    await broadcastTransaction(argv.endpoint, '0x' + raw)
    console.log('broadcasted Transaction')
  }
  console.log('raw:', '0x' + raw);
  console.log('txHash:', '0x' + txHash);
})();

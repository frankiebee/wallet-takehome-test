# Wallet CLI — Ethereum TX Signer

This CLI tool derives an Ethereum account from a BIP-39 mnemonic and signs an EIP-155 legacy transaction.

## Setup

```bash
npm install
```

## Usage

```bash
ts-node wallet.ts \
  --to 0x... \
  --value 0.01 \
  --nonce 0
```

Optional: `--gasPrice`, `--gasLimit`, `--chainId`
Default mnemonic: `"test test test ... junk"`
Path: `m/44'/60'/0'/0/0`

## Output

- `raw`: signed tx hex
- `txHash`: transaction hash

## Test

```bash
npm test
```

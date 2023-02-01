# dashkeys.js

Generate, validate, create, and convert WIFs and PayAddress.

- CLI
- Node & Bundlers
- Browser
- API
- Fixtures (for developing and testing)

## CLI

```sh
npm install --location=global dashkeys-cli
dashkeys help
```

See DashKey's CLI README at <https://github.com/dashhive/dashkeys-cli.js>.

## Node

**Install**

```sh
npm install --save dashkeys
```

**Usage**

```js
let DashKeys = require("dashkeys");

let wif = await DashKeys.generate();
// ex: "XCGKuZcKDjNhx8DaNKK4xwMMNzspaoToT6CafJAbBfQTi57buhLK"

let addr = await DashKeys.wifToAddr(wif);
// ex: "XrZJJfEKRNobcuwWKTD3bDu8ou7XSWPbc9"
```

You can use `DashKeys.privateKeyToWif(privateKey)` to generate non-random WIFs:

```js
// TODO
let privateKey = Buffer.from(
  "1d2a6b22fcb5a29a5357eaf27b1444c623e5e580b66ac5f1109e2778a0ffb950",
  "hex",
);
let wif = await DashKeys.privateKeyToWif(privateKey);
let addr = await DashKeys.wifToAddr(wif);
```

## Browser

**Install**

```html
<script src="https://unpkg.com/@dashincubator/base58check/base58check.js"></script>
<script src="https://unpkg.com/@dashincubator/secp256k1/secp256k1.js"></script>
<script src="https://unpkg.com/@dashincubator/ripemd160/ripemd160.js"></script>
<script src="https://unpkg.com/dashkeys/dashkeys.js"></script>
```

**Usage**

```js
async function main() {
  "use strict";

  let DashKeys = window.DashKeys;

  let wif = await DashKeys.generate();
  // ex: "XCGKuZcKDjNhx8DaNKK4xwMMNzspaoToT6CafJAbBfQTi57buhLK"

  let addr = await DashKeys.wifToAddr(wif);
  // ex: "XrZJJfEKRNobcuwWKTD3bDu8ou7XSWPbc9"
}

main().catch(function (err) {
  console.error("Fail:");
  console.error(err.stack || err);
});
```

## API

DashKeys has a small API wrapping Secp256k1 and Base58Check.

Most of what you need to do can be done with those directly.

```js
let wif = await DashKeys.generate();
let addr = await DashKeys.wifToAddr(wif);

let pkh = await DashKeys.publicKeyToPubKeyHash(publicKey);
let wif = await DashKeys.privateKeyToWif(privateKey);
```

## Helpful Helper Functions

These aren't included as part of the DashKeys API because they're things that
[@dashincubator/base58check](https://github.com/dashhive/base58check.js) already
does, 95% or so.

```js
await addrToPubKeyHash(addr); // buffer
await pubKeyHashToAddr(pubKeyHash); // Pay Addr

await wifToPrivateKey(wif); // buffer
await privateKeyToWif(privKey); // WIF

await decode(addrOrWif); // { version, pubKeyHash, privateKey, check, valid }
await encode(pkhOrPkBuf); // Pay Addr or WIF

uint8ArrayToHex(buf); // hex
hexToUint8Array(hex); // buffer
```

However, you are welcome, of course, to copy and paste these to your heart's
content. 😉

```js
let Base58Check = require("@dashincubator/base58check").Base58Check;
let dash58check = Base58Check.create({
  pubKeyHashVersion: "4c", // "8c" for dash testnet, "00" for bitcoin main
  privateKeyVersion: "cc", // "ef" for dash testnet, "80" for bitcoin main
});

/**
 * @param {String} addr
 * @returns {Promise<Uint8Array>} - p2pkh (no magic byte or checksum)
 */
async function addrToPubKeyHash(addr) {
  let b58cAddr = dash58check.decode(addr);
  let pubKeyHash = hexToUint8Array(b58cAddr.pubKeyHash);
  return pubKeyHash;
}

/**
 * @param {Uint8Array} pubKeyHash - no magic byte or checksum
 * @returns {Promise<String>} - Pay Addr
 */
async function pubKeyHashToAddr(pubKeyHash) {
  let hex = uint8ArrayToHex(pubKeyHash);
  let addr = await dash58check.encode({ pubkeyHash: hex });
  return addr;
}

/**
 * @param {String} wif
 * @returns {Promise<Uint8Array>} - private key (no magic byte or checksum)
 */
async function wifToPrivateKey(wif) {
  let b58cWif = dash58check.decode(wif);
  let privateKey = hexToUint8Array(b58cWif.privateKey);
  return privateKey;
}

/**
 * @param {Uint8Array} privKey
 * @returns {Promise<String>} - wif
 */
async function privateKeyToWif(privKey) {
  let privateKey = uint8ArrayToHex(privKey);

  let wif = await dash58check.encode({ privateKey: privateKey });
  return wif;
}

/**
 * @param {String} addrOrWif
 */
async function decode(addrOrWif) {
  let parts = await dash58check.decode(addrOrWif);
  let check = await dash58check.checksum(parts);
  let valid = parts.check === check;

  parts.valid = valid;
  //parts.privateKeyBuffer = hexToUint8Array(parts.privateKey);
  //parts.pubKeyHashBuffer = hexToUint8Array(parts.pubKeyHash);

  return parts;
}

/**
 * @param {Uint8Array} buf
 * @returns {String} - Pay Addr or WIF
 * @throws {Error}
 */
async function encode(buf) {
  let hex = uint8ArrayToHex(buf);

  if (32 === buf.length) {
    return await dash58check.encode({
      privateKey: hex,
    });
  }

  if (20 === buf.length) {
    return await dash58check.encode({
      pubKeyHash: hex,
    });
  }

  throw new Error("buffer length must be (PubKeyHash) or 32 (PrivateKey)");
}

/**
 * JS Buffer to Hex that works in browsers and Little-Endian
 * (which is most of the - ARM, x64, x86, WASM, etc)
 * @param {Uint8Array} buf
 * @returns {String} - hex
 */
function uint8ArrayToHex(buf) {
  /** @type {Array<String>} */
  let hex = [];

  buf.forEach(function (b) {
    let c = b.toString(16).padStart(2, "0");
    hex.push(c);
  });

  return hex.join("");
}

/**
 * Hex to JS Buffer that works in browsers and Little-Endian CPUs
 * (which is most of the - ARM, x64, x86, WASM, etc)
 * @param {String} hex
 * @returns {Uint8Array} - JS Buffer (Node and Browsers)
 */
function hexToUint8Array(hex) {
  let buf = new Uint8Array(hex.length / 2);

  for (let i = 0; i < hex.length; i += 2) {
    let c = hex.slice(i, i + 2);
    let b = parseInt(c, 16);
    let index = i / 2;
    buf[index] = b;
  }

  return buf;
}
```

## Fixtures

For troubleshooting, debugging, etc, the keys used in this example come from the
canonical Dash "Zoomonic":

```txt
Passphrase (Mnemonic)  :  zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong
Secret (Salt Password) :  TREZOR
HD Path                :  m/44'/5'/0'/0/0:
WIF                    :  XCGKuZcKDjNhx8DaNKK4xwMMNzspaoToT6CafJAbBfQTi57buhLK
Addr                   :  XrZJJfEKRNobcuwWKTD3bDu8ou7XSWPbc9
```

### Correct PubKeyHash Values

```sh
dashkeys inspect --unsafe ./examples/m44_5_0_0-0.wif
```

```txt
    Version:     cc
    Private Key: 1d2a6b22fcb5a29a5357eaf27b1444c623e5e580b66ac5f1109e2778a0ffb950
    Compressed:  01
    Pay Addr:    XrZJJfEKRNobcuwWKTD3bDu8ou7XSWPbc9
    Check:       ec533f80
    Valid:       true
```

**Correct Private Key**

```txt
PrivateKey:   cc011d2a6b22fcb5a29a5357eaf27b1444c623e5e580b66ac5f1109e2778a0ffb950
  --------
  Version:    cc
  Comp Flag:  01 (Compressed)
  Priv Key:   1d2a6b22fcb5a29a5357eaf27b1444c623e5e580b66ac5f1109e2778a0ffb950
  --------
WIF:          XCGKuZcKDjNhx8DaNKK4xwMMNzspaoToT6CafJAbBfQTi57buhLK
```

**Correct Pub Key Hash**

```txt
PubKey:       0245ddd5edaa25313bb88ee0abd359f6f58ac38ed597d33a981f1799903633d902
  --------
  Comp Flag:  02 (Quadrant 2)
  X:          45ddd5edaa25313bb88ee0abd359f6f58ac38ed597d33a981f1799903633d902
  SHA256:     8e5abfc42a6d7529b860ce2b4b8889380db893438dc96430f597ddb455e85fdd
  *RMD160:    54408a877b83cb9706373918a430728f72f3d001 (*not used)
  PubKeyHash: ae14c8728915b492d9d77813bd8fddd91ce70948
  Check:      ce08541e
  Version:    4c
  --------
Pay Address:    XrZJJfEKRNobcuwWKTD3bDu8ou7XSWPbc9
```

### Incorrect PubKeyHash (Uncompressed)

If you see these values, you've mistakenly used an uncompressed public key.

**Incorrect Private Key**

```txt
PrivateKey:   cc1d2a6b22fcb5a29a5357eaf27b1444c623e5e580b66ac5f1109e2778a0ffb950
  --------
  Version:    cc
  Comp Flag:  missing, or 00 (Uncompressed)
  Priv Key:   1d2a6b22fcb5a29a5357eaf27b1444c623e5e580b66ac5f1109e2778a0ffb950
  --------
WIF:             XCGKuZcKDjNhx8DaNKK4xwMMNzspaoToT6CafJAbBfQTi4vf57Ka (00 comp flag)
                 7qmhzDpsoPHhYXBZ2f8igQeEgRSZXmWdoh9Wq6hgvAcDrD3Arhr (no comp flag)
```

**Incorrect Pub Key Hash**

```txt
PubKey (X+Y): 04
              45ddd5edaa25313bb88ee0abd359f6f58ac38ed597d33a981f1799903633d902
              607c88b97231d7f1419c772a6c55d2ad6a7c478a66fdd28ac88c622383073d12
  --------
  Comp Flag:  04, or 'false' (uncompressed)
  X:          45ddd5edaa25313bb88ee0abd359f6f58ac38ed597d33a981f1799903633d902
  Y:          607c88b97231d7f1419c772a6c55d2ad6a7c478a66fdd28ac88c622383073d12
  SHA256:     85c03bf3ba5042d2e7a84f0fcc969a7753a91e9c5c299062e1fdf7e0506b5f66
  *RMD160:    b9d17c4c4fb6307ba78c8d4853ed07bd7e4c9f5a (*not used)
  PubKeyHash: 9eee08ab54036069e5aaa15dcb204baa0fae622d
  Check:      d38b9fd2
  Version:    4c
  --------
Pay Address:  XqBBkSnvWMcLyyRRvH1S4mWH4f2zugr7Cd
```

# LICENSE

To keep the dependency tree slim, this includes `BaseX` and `Base58Check`, which
are derivatives of `base58.cpp`, as well as RIPEMD160.

These have all been _complete_ for several years. They do not need updates.

## DashKeys.js

Copyright (c) 2022-2023 Dash Incubator \
Copyright (c) 2021-2023 AJ ONeal

MIT License

## BaseX, Base58, Base58Check

Copyright (c) 2018 base-x contributors \
Copyright (c) 2014-2018 The Bitcoin Core developers

MIT License

## RIPEMD160

Copyright (c) 2016 crypto-browserify

MIT License

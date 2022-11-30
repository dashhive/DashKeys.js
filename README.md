# dashkeys.js

Generate, validate, create, and convert WIFs and PayAddress.

- CLI
- Node & Bundlers
- Browser
- API
- Fixtures (for developing and testing)

## CLI

Saves a private key to a file with the name of the public key hash (pay addr)

**Install**

```sh
npm install --location=global dashkeys
```

**Usage**

```sh
dashkeys generate
```

```txt
Saved new private key to './Xjn9fksLacciynroVhMLKGXMqMJtzJNLvQ.wif'
```

The name of the file is the Pay Addr (public key hash) and the contents are the
WIF (private key).

The leading `X` for each is because they are base58check-encoded.

## Node

**Install**

```sh
npm install --save dashkeys
```

**Usage**

```js
let DashKeys = require("dashkeys");

let wif = await DashKeys.generate();
// ex: "XEez2HcUhEomZoxzgH7H3LxnRAkqF4kRCVE8mW9q4YSUV4yuADec"

let addr = await DashKeys.wifToAddr(wif);
// ex: "Xjn9fksLacciynroVhMLKGXMqMJtzJNLvQ"
```

You can use `DashKeys.privateKeyToWif(privateKey)` to generate non-random WIFs:

```js
let privateKey = Buffer.from(
  "647f06cbd6569feaa4b6a1e400284057a95d27f4206ce38300ae88d44418160d",
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
  // ex: "XEez2HcUhEomZoxzgH7H3LxnRAkqF4kRCVE8mW9q4YSUV4yuADec"

  let addr = await DashKeys.wifToAddr(wif);
  // ex: "Xjn9fksLacciynroVhMLKGXMqMJtzJNLvQ"
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

For troubleshooting, debugging, etc:

**Correct Values**

- WIF: XEez2HcUhEomZoxzgH7H3LxnRAkqF4kRCVE8mW9q4YSUV4yuADec
- Pay Addr: Xjn9fksLacciynroVhMLKGXMqMJtzJNLvQ

```txt
WIF:             XEez2HcUhEomZoxzgH7H3LxnRAkqF4kRCVE8mW9q4YSUV4yuADec (Base58Check)

Private Parts:   cc647f06cbd6569feaa4b6a1e400284057a95d27f4206ce38300ae88d44418160d012dc0e59d
      --------
       Version:  cc
       PrivKey:  647f06cbd6569feaa4b6a1e400284057a95d27f4206ce38300ae88d44418160d
    Compressed:  01
      Checksum:  2dc0e59d


Compressed Pub:  0290940e7a082049ccfbf7999260ab9a6d88bcb34d57f6c6075e52dd7395ed7058
      --------
      Quadrant:  02
        PubKey:  90940e7a082049ccfbf7999260ab9a6d88bcb34d57f6c6075e52dd7395ed7058
        Sha256:  836eaaeef70089f38cbf878f6987a322260ad661f3c0fcaf9715834b5a5224c7
        RipeMD:  63ba19d01e6cf812c01ca6a4041c3c04f2a4dfe9 (Pub Key Hash)


Pub Key Hash:    4c63ba19d01e6cf812c01ca6a4041c3c04f2a4dfe99ec9cefd (Hex)
       --------
       Version:  4c
          Hash:  63ba19d01e6cf812c01ca6a4041c3c04f2a4dfe9
      Checksum:  9ec9cefd


Pay Addr:        Xjn9fksLacciynroVhMLKGXMqMJtzJNLvQ (Base58Check)
```

**Incorrect Values**

These are the values you get for `{ compressed: false }`:

```txt
Private Parts:   cc647f06cbd6569feaa4b6a1e400284057a95d27f4206ce38300ae88d44418160d012dc0e59d
      --------
       Version:  cc
       PrivKey:  647f06cbd6569feaa4b6a1e400284057a95d27f4206ce38300ae88d44418160d
    Compressed:  (MISSING!)
      Checksum:  (WRONG!)

Uncompressed:   0490940e7a082049ccfbf7999260ab9a6d88bcb34d57f6c6075e52dd7395ed70581480b848f5a1e2fd61dd87a2815d90d2d118a46d666a7a559adab68b00e0dc1e
      --------
      Quadrant:  04 (WRONG!)
             X:  90940e7a082049ccfbf7999260ab9a6d88bcb34d57f6c6075e52dd7395ed7058
             Y:  1480b848f5a1e2fd61dd87a2815d90d2d118a46d666a7a559adab68b00e0dc1e
      Sha256:    e1d11902550f530b33e4321f4f9044a67c3b9c38b6ed98accfaf0571067871d2
      RipeMD:    30ad71f52c005b5444f94032dda84466ddaf87a0 (WRONG Pub Key Hash)

Pay Addr:        Xf8E3eA1Sh8vC29fxQVbET8cqfCRcmiQeA (WRONG)
                 4c30ad71f52c005b5444f94032dda84466ddaf87a0dae0ce2f (WRONG)
       --------
       Version:  4c
          Hash:  30ad71f52c005b5444f94032dda84466ddaf87a0 (WRONG)
      Checksum:  dae0ce2f (WRONG)
```

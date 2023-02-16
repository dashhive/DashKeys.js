# [DashKeys.js][dashkeys-js]

Generate, validate, and convert DASH WIFs and Pay Addresses. \
(Base58Check encoding/decoding for Private Keys and Public Key Hashes)

```text
WIF:     XCGKuZcKDjNhx8DaNKK4xwMMNzspaoToT6CafJAbBfQTi57buhLK
Address: XrZJJfEKRNobcuwWKTD3bDu8ou7XSWPbc9
```

> A fully-functional, production-ready **reference implementation** of Dash
> Keys - suitable for learning DASH specs and protocols, and porting to other
> languages.

# Table of Contents

- 🚀 [Install](#install)
  - Terminal (CLI)
  - Node & Bundlers
  - Browser
- 💪 [Usage](#usage)
- ⚙️ [API](#api)
- 🧰 Developer Resources
  - 👩‍🏫 [Glossary of Terms](#glossary)
    - Address, Check, Compressed, Private Key,
    - PubKey Hash, Public Key, Version, WIF, etc ...
  - 🦓 [Fixtures](#fixtures) (for testing)
    - The Canonical Dash "Zoomonic"
    - Anatomy of Addrs & WIFs
    - Troubleshooting Uncompressed Keys
    - Implementation Details
- 📄 [License](#license)

[base58check-js]: https://github.com/dashhive/base58check.js
[dashkeys-js]: https://github.com/dashhive/dashkeys.js
[dashhd-js]: https://github.com/dashhive/dashhd.js
[dashwallet-js]: https://github.com/dashhive/dashwallet.js
[dash-hd-cli]: https://github.com/dashhive/dashhd-cli.js
[dash-keys-cli]: https://github.com/dashhive/dashkeys-cli.js
[dash-wallet-cli]: https://github.com/dashhive/dashwallet-cli.js

# Install

Works in Command Line, Node, Bun, Bundlers, and Browsers

## Terminal

```sh
npm install --location=global dashkeys-cli
dashkeys help
```

See DashKey's CLI README at
[github.com/dashhive/dashkeys-cli.js][dash-keys-cli].

## Node & Bundlers

**Install**

```sh
npm install --save dashkeys@1.x
npm install --save @dashincubator/secp256k1@1.x
```

```js
let DashKeys = require("dashkeys");
let toHex = DashKeys.utils.bytesToHex;
let toBytes = DashKeys.utils.hexToBytes;
```

## Browser

**Install**

```html
<script src="https://unpkg.com/@dashincubator/secp256k1@1.x/secp256k1.js"></script>
<script src="https://unpkg.com/dashkeys@1.x/dashkeys.js"></script>
```

```js
async function main() {
  "use strict";

  let DashKeys = window.DashKeys;
  let toHex = DashKeys.utils.bytesToHex;
  let toBytes = DashKeys.utils.hexToBytes;

  // ...
}

main().catch(function (err) {
  console.error("Fail:");
  console.error(err.stack || err);
});
```

# Usage

```js
let wif = await DashKeys.utils.generateWifNonHd();
// ex: "XCGKuZcKDjNhx8DaNKK4xwMMNzspaoToT6CafJAbBfQTi57buhLK"

let addr = await DashKeys.wifToAddr(wif);
// ex: "XrZJJfEKRNobcuwWKTD3bDu8ou7XSWPbc9"
```

You can use `DashKeys.privKeyToWif(privateKey)` to encode Private Keys to WIFs:

```js
let privBuf = toBytes(
  "1d2a6b22fcb5a29a5357eaf27b1444c623e5e580b66ac5f1109e2778a0ffb950",
);
let wif = await DashKeys.privKeyToWif(privateKey);
let addr = await DashKeys.wifToAddr(wif);
```

# API

Dash Keys doesn't do anything that other Base58Check libraries don't do.

The purpose of this rewrite has been to provide, a simpler, **lightweight**,
more streamlined production-ready **reference implementation** that takes
advantage of modern, cross-platform _JS-native APIs_, such as WebCrypto.

**However**, it does (we think) do a better job at exposing a functions for how
the Base58Check codec is **used in practice** (rather than _everything_ it can
theoretically be used for).

## Common Conversions

```js
// Bi-Directional Conversions
await DashKeys.addrToPkh(address); // PubKey Hash Uint8Array (ShaRipeBytes)
await DashKeys.pkhToAddr(hashBytes, { version }); // Address (Base58Check-encoded)
await DashKeys.pubkeyToAddr(pubBytes); // Address (Base58Check-encoded)
await DashKeys.privKeyToWif(privBytes, { version }); // WIF (Base58Check-encoded)
await DashKeys.wifToPrivKey(wif); // Private Key Uint8Array

// One-Way Conversions
await DashKeys.wifToAddr(wif); // Address (Base58Check-encoded)
await DashKeys.pubkeyToPkh(pubBytes); // shaRipeBytes Uint8Array
```

**Note**: these all output either Base58Check Strings, or Byte Arrays
(Uint8Array).

## Common Encode / Decode Options

```js
{
  // (default) throw if check(sum) fails
  validate: true,

  // which encoding to use
  // (not all are valid all the time - it depends on the use)
  version: "mainnet|testnet|private|pkh|xprv|xpub|cc|4c|ef|8c",
}
```

## Debugging Encoder / Decoder

```js
// Base58Check Codec for all of Private Key and PubKey Hash (and X Keys)
await DashKeys.decode(b58cString, { validate }); // { version, type, check, etc }
await DashKeys.encodeKey(keyBytes, { version }); // Base58Check-encoded key
```

**Decode Output**:

```json5
{
  check: "<hex>",
  compressed: true,
  type: "private|pkh|xprv|xpub",
  version: "cc|4c|ef|8c",
  valid: true, // check matches

  // possible key types
  privateKey: "<hex>",
  pubKeyHash: "<hex>",
  xprv: "<hex>",
  xpub: "<hex>",
}
```

**note**: `compressed` only applies to Private Keys and is _always_ `true`. \
Remains in for compatibility, but not used.

## Helpful Helper Utils

```js
// Byte Utils (NOT async)
let toHex = DashKeys.utils.bytesToHex;
toHex(uint8Array); // hex String

let toBytes = DashKeys.utils.hexToBytes;
toBytes(hexString); // bytes Uint8Array

// Hash Utils
await DashKeys.utils.ripemd160sum(bytes); // hash bytes Uint8Array
await DashKeys.utils.sha256sum(bytes); // hash bytes Uint8Array
```

## Swappable Secp256k1 Utils

We felt it was important to **not strictly depend** on _our_ chosen
**secp256k1** implementation. \
(that's why you have to manually install it as a dependency yourself)

Use these functions **as-is**, or overwrite them with your own implementation.

```js
// Key Utils (over
await DashKeys.utils.generateWifNonHd({ version }); // WIF string (non-hd, dev tool)
await DashKeys.utils.toPublicKey(privBytes); // Public Key Bytes
```

**Example Overwrite**

You **DO NOT** need to do this, but you _may_ if you wish:

```js
let Secp256k1 = require("@noble/secp256k1");

DashKeys.utils.generateWifNonHd = async function (opts) {
  let privBytes = Secp256k1.utils.randomPrivateKey();
  let privateKey = toHex(privBytes);
  let version = opts.version ?? "cc";

  let wif = await DashKeys.encode(privBytes, { version });
  return wif;
};

DashKeys.utils.toPublicKey = async function (privBytes) {
  let isCompressed = true;
  let pubBytes = Secp256k1.getPublicKey(privBytes, isCompressed);

  return pubBytes;
};
```

# Glossary

Here are bunches of terms by their canonical name, as well as a terse
description.

- [Address](#address)
- [Check](#check)
- [Base X](#base-x)
- [Base58](#base58)
- [Base58Check](#base58check)
- [Compressed Byte](#compressed-byte)
- [HD Key](#hd-key)
- [Private Key](#private-key)
- [PubKey Hash](#pubkey-hash)
- [Public Key](#public-key)
- [RIPEMD160](#ripemd160)
- [Version](#version)
- [WIF](#wif)
- [Zoomonic](#zoomonic)

## Address

Also: Payment Address, Pay Addr, Addr

A Base58Check-encoded PubKey Hash. \
(can **NOT** be reversed into the Public Key) \
The encoding is like this:

- Coin Version Public byte(s), which is 4c for DASH
- Public Key Hash (20 bytes)
- Check(sum) is 4 bytes of SHA-256(concat(coin, comp, pkh))
- Base58Check is Base85(concat(coin, comp, pkh, check))

```text
Version:     cc
PubKey Hash: ae14c8728915b492d9d77813bd8fddd91ce70948
Check:       ce08541e

Decoded:     ccae14c8728915b492d9d77813bd8fddd91ce70948ce08541e

Encoded:     XrZJJfEKRNobcuwWKTD3bDu8ou7XSWPbc9
```

## Base X

A bespoke algorithm for arbitrary-width bit encoding. \
Similar to (but **not _at all_ compatible** with) Base64. \
Bit-width is based on the given alphabet's number of characters.

## Base58

A specific 58-character _Base X_ alphabet. \
The same is used for DASH as most cryptocurrencies.

```text
123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
```

Chosen to eliminate confusion between similar characters. \
(`0` and `O`, `1` and `l` and `I`, etc)

## Base58Check

A Base58 encoding schema with prefixes and suffixes. \
`verisonBytes` is added as a prefix (before encoding). \
Some _metadata_ may come after the data. \
`checkBytes` are added as a suffix (before encoding). \

```js
Base58(`${versionBytes}${dataBytes}${metaBytes}${checkBytes}`);
```

See also [Address](#address), [Check](#check) and [WIF](#wif)

## Check

Also: Base58 Checksum, Base58 Hash, Base58 SHA-256

The _last_ 4 bytes of a decoded WIF or Addr. \
These are the _first_ 4 bytes of the SHA-256 Hash of the same.

See [Address](#address) and [WIF](#wif).

## Compressed Byte

Also: Compression Flag, Recovery Bit, Y is Even / Odd Byte, Quadrant

A Base58Check private key has the suffix `0x01`, the compression flag. \
This indicates that Pub Key Hashes must not include the Y value.

See also: [Public Key](#public-key).

## HD Key

Also: HD Wallet WIF

An HD Key is a Private Key or WIF generated from an HD Wallet. \
These are recoverable from a Passphrase "Mnemonic". \
(HD means _Hierarchical-Deterministic_, as in "generated from seed")

HD keys are almost always preferrable over non-HD keys.

See [Dash HD][dashhd-js], [Dash Wallet][dashwallet-js].

## Private Key

Also: PrivKey

Any 32 random bytes (256-bits) that can produce a valid Public Key. \
The public key is produced by creating a point on a known curve.

In essence:

```js
let privBuf = genRandom(32);
let pirvHex = toHex(privBuf);
let privNum = BigInt(`0x${privHex}`);

// magic secp256k1 curve values
let curveN =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
let Gx =
  55066263022277343669578718895168534326250603453777594175500187360389116729240n;
let Gy =
  32670510020758816978083085130507043184471273380659243275938904335757337482424n;
let windowSize = 8;

let isWithinCurveOrder = 0n < privNum && privNum < curveN;
if (!isWithinCurveOrder) {
  throw new Error("not in curve order");
}

let BASE = new JacobianPoint(CURVE.Gx, CURVE.Gy, 1n);
let jPoint = BASE.multiply(privNum, { Gx, Gy, windowSize }); // fancy math
let pubPoint = jPoint.toAffine(); // fancy math

let isOdd = pubPoint.y % 2n;
let prefix = "02";
if (isOdd) {
  prefix = "03";
}

let x = pubPoint.x.toString(16).padStart(32, "0");
let pubHex = `${prefix}${x}`;
```

See <https://github.com/dashhive/secp256k1.js>.

## PubKey Hash

Also: Public Key Hash, PKH, PubKeyHash

The public key is hashed with SHA-256. \
That result is hashed with RIPEMD-160.

```text
RIPEMD160(SHA256(PublicKey))
```

## Public Key

Also: PubKey

An 32-byte `X` value, prefixed with a byte describing the `Y` value. \
The indicator is `0x02`, if `Y` is ever, or `0x03` if `Y` is odd. \

In essence:

```js
let expectOdd = 0x03 === pubkey[0];
let xBuf = pubkey.subarray(1);
let xHex = toHex(xBuf);
let x = BigInt(xHex);

// magic secp256k1 curve values
let a = 0n;
let b = 7n;
let P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;

function mod(a, b = P) {
  let result = a % b;
  if (result >= 0n) {
    return result;
  }
  return b + result;
}
let x2 = mod(x * x);
let x3 = mod(x2 * x);
let y2 = mod(x3 + a * x + b);

let y = curveSqrtMod(y2); // very complicated
let isYOdd = (y & 1n) === 1n;
if (expectOdd && !isYOdd) {
  y = mod(-y);
}

let pubPoint = { x: x, y: y };
```

See <https://github.com/dashhive/secp256k1.js>.

## RIPEMD160

An old, deprecated hash 20-byte algorithm - similar to MD5. \
We're stuck with it for the foreseeable future. Oh, well.

## Version

Also: Base58Check Version, Coin Version, Privacy Byte

`0xcc` is used for DASH mainnet WIFs (Private Key). \
`0x4c` is the prefix for Payment Addresses (PubKey Hash) . \
These bytes Base58Encode to `X`, (for mystery, i.e. "DarkCoin").

`0xef` (Priv) and `0x8c` (PKH) are used for DASH testnet. \
These Base58Encode to `Y`.

For use with HD tools, this Base58Check codec also supports: \
`0x0488ade4`, which Base58-encodes to the `xprv` prefix. \
`0x0488b21e`, which Base58-encodes to the `xpub` prefix. \
`0x04358394` and `0x043587cf`, which encode to `tprv` and `tpub`.

See [Dash HD][dashhd-js] for more info about Extended Private Keys (`xprv`,
`xpriv`) and Extended Public Keys (`xpub`).

## WIF

Also: Wallet Import Format, Paper Wallet, Swipe Key, Private Key QR

A Base58Check-encoded Private Key. \
(**CAN** be reversed into the Private Key) \
The encoding is like this:

- Coin Version Private byte(s), which is cc for DASH
- Compression byte (always 0x01)
- Private Key (32 bytes)
- Checksum is 4 bytes of SHA-256(concat(coin, privkey, compression))
- Base58Check is Base85(concat(coin, privkey, compression, checksum))

```text
Version:     cc
Comp Byte:   01 (always)
Private Key: 1d2a6b22fcb5a29a5357eaf27b1444c623e5e580b66ac5f1109e2778a0ffb950
Checksum:    ec533f80

Decoded:     cc011d2a6b22fcb5a29a5357eaf27b1444c623e5e580b66ac5f1109e2778a0ffb950ec533f80

Encoded:     XCGKuZcKDjNhx8DaNKK4xwMMNzspaoToT6CafJAbBfQTi57buhLK
```

## Zoomonic

The HD Wallet used for all testing fixtures in this ecosystem of code. \
(chosen from the original Trezor / BIP-39 test fixtures)

See [The Canonical Dash "Zoomonic"](#the-canonical-dash-zoomonic).

# Fixtures

For troubleshooting, debugging, etc.

## The Canonical Dash "Zoomonic":

All keys used in this example - and across this ecosystem of DASH tools - are HD
keys derived from the "Zoomonic":

```txt
Passphrase (Mnemonic)  :  zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong
Secret (Salt Password) :  TREZOR
HD Path                :  m/44'/5'/0'/0/0
WIF                    :  XCGKuZcKDjNhx8DaNKK4xwMMNzspaoToT6CafJAbBfQTi57buhLK
Addr                   :  XrZJJfEKRNobcuwWKTD3bDu8ou7XSWPbc9
```

## Anatomy of Addrs & WIFs

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

## Troubleshooting Uncompressed Keys

If you see these values, then you've mistakenly used uncompressed keys.

**Incorrect Private Key** (Uncompressed)

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

**Incorrect Pub Key Hash** (Uncompressed)

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

# Implementation Details

It also serves as a **reference implementation** for porting to **other
platforms** such as modern **mobile** and **desktop** programming languages.

As a reference implementation, it's valuable to **_understand_ that tedium**,
here's a peek behind the curtain:

- _Address_ ↔️ _PubKey Hash_
- _WIF_ ↔️ _Private Key_
- _Private Key_ ➡️ _Public Key_
- _Public Key_ ➡️ _PubKey Hash_

These are _simplified_ version of what's in the actual code: \
 (removed error checking, etc, for clarity)

```js
let Base58Check = require("@dashincubator/base58check").Base58Check;

// "dash58check" because we're using the Dash magic version bytes.
let dash58check = Base58Check.create({
  privateKeyVersion: "cc", // "ef" for dash testnet, "80" for bitcoin main
  pubKeyHashVersion: "4c", // "8c" for dash testnet, "00" for bitcoin main
});

/**
 * @param {String} addr
 * @returns {Promise<Uint8Array>} - p2pkh (no magic byte or checksum)
 */
async function addrToPkh(addr) {
  let b58cAddr = dash58check.decode(addr);
  let pubKeyHash = toBytes(b58cAddr.pubKeyHash);
  return pubKeyHash;
}

/**
 * @param {Uint8Array} pubKeyHash - no magic byte or checksum
 * @returns {Promise<String>} - Pay Addr
 */
async function pkhToAddr(pubKeyHash) {
  let hex = toHex(pubKeyHash);
  let addr = await dash58check.encode({ pubKeyHash: hex });
  return addr;
}

/**
 * @param {String} wif
 * @returns {Promise<Uint8Array>} - private key (no magic byte or checksum)
 */
async function wifToPrivKey(wif) {
  let b58cWif = dash58check.decode(wif);
  let privateKey = toBytes(b58cWif.privateKey);
  return privateKey;
}

/**
 * @param {Uint8Array} privKey
 * @returns {Promise<String>} - wif
 */
async function privKeyToWif(privKey) {
  let privateKey = toHex(privKey);

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
  //parts.privBytes = toBytes(parts.privateKey);
  //parts.shaRipeBytes = toBytes(parts.pubKeyHash);

  return parts;
}

/**
 * @param {Uint8Array} buf
 * @returns {String} - Pay Addr or WIF
 * @throws {Error}
 */
async function encode(buf) {
  let hex = toHex(buf);

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

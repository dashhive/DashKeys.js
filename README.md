# dashkeys.js

Generate, validate, create, and convert WIFs and PayAddress.

- CLI
- Node & Bundlers
- Browser
- API

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
Saved new private key to './Xs8Nv8mbguBwdqapuncm2YbTFTXjNvTQPo.wif'
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
// ex: "XKf1t34T2h2LDTZben1uM8eWT6CZccji4XpSVnaL7M3FSMtjxxpH"

let addr = await DashKeys.wifToAddr(wif);
// ex: "Xs8Nv8mbguBwdqapuncm2YbTFTXjNvTQPo"
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
  // ex: "XKf1t34T2h2LDTZben1uM8eWT6CZccji4XpSVnaL7M3FSMtjxxpH"

  let addr = await DashKeys.wifToAddr(wif);
  // ex: "Xs8Nv8mbguBwdqapuncm2YbTFTXjNvTQPo"
}

main().catch(function (err) {
  console.error("Fail:");
  console.error(err.stack || err);
});
```

## API

```js
let wif = await DashKeys.generate();
let addr = await DashKeys.wifToAddr(wif);

let wifOrAddrParts = await DashKeys.decode(addrOrWif, { verify: true });
let valid = await DashKeys.verify(addrOrWif);
```

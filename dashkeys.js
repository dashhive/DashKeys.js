(function (exports) {
  "use strict";

  let DashKeys = {};
  //@ts-ignore
  exports.DashKeys = DashKeys;

  /** @type {import('node:crypto')} */
  //@ts-ignore
  let Crypto = exports.crypto || require("node:crypto");

  /**
   * @callback Sha256Sum
   * @param {Uint8Array|Buffer} u8
   * @returns {Promise<Uint8Array|Buffer>}
   */

  /** @type {Sha256Sum} */
  let sha256sum = async function (u8) {
    let arrayBuffer = await Crypto.subtle.digest("SHA-256", u8);
    let buf = new Uint8Array(arrayBuffer);
    return buf;
  };

  /** @type {import('@dashincubator/base58check').Base58Check} */
  let Base58Check =
    //@ts-ignore
    exports.Base58Check || require("@dashincubator/base58check").Base58Check;

  /** @type {import('@dashincubator/ripemd160')} */
  //@ts-ignore
  let RIPEMD160 = exports.RIPEMD160 || require("@dashincubator/ripemd160");

  /** @type {import('@dashincubator/secp256k1')} */
  //@ts-ignore
  let Secp256k1 = exports.nobleSecp256k1 || require("@dashincubator/secp256k1");

  /**
   * Gets crypto-random bytes that may or may not be a valid private key
   * (and that's okay - expected even)
   * @param {Number} len
   * @returns {Uint8Array}
   */
  //@ts-ignore
  Secp256k1.utils.randomBytes = function (len) {
    let buf = new Uint8Array(len);
    Crypto.getRandomValues(buf);
    return buf;
  };

  // https://dashcore.readme.io/docs/core-ref-transactions-address-conversion
  // https://docs.dash.org/en/stable/developers/testnet.html
  // "48" for mainnet, "8c" for testnet, '00' for bitcoin
  //DashKeys.pubKeyHashVersion = "4c";

  // "cc" for mainnet, "ef" for testnet, '80' for bitcoin
  //DashKeys.privateKeyVersion = "cc";

  // https://dashcore.readme.io/docs/core-ref-transactions-address-conversion
  // https://docs.dash.org/en/stable/developers/testnet.html
  let b58c = Base58Check.create();

  /**
   * @param {Object} [opts]
   * @param {String} [opts.version] - '8c' for testnet addrs, 'ef' for testnet wifs,
   * @returns {Promise<String>}
   */
  DashKeys.generate = async function (opts) {
    let privKey = Secp256k1.utils.randomPrivateKey();

    let wif = await DashKeys.privateKeyToWif(privKey, opts);
    return wif;
  };

  /**
   * @param {Uint8Array} privKey
   * @param {Object} [opts]
   * @param {String} [opts.version] - '8c' for testnet addrs, 'ef' for testnet wifs,
   * @returns {Promise<String>}
   */
  DashKeys.privateKeyToWif = async function (privKey, opts) {
    let privKeyHex = DashKeys._uint8ArrayToHex(privKey);
    let decoded = {
      version: opts?.version,
      privateKey: privKeyHex,
    };

    let wif = await b58c.encode(decoded);
    return wif;
  };

  //
  // Base58Check / Uint8Array Conversions
  //

  /**
   * @param {String} wif - private key
   * @param {Object} [opts]
   * @param {String} [opts.version]
   * @returns {Promise<String>}
   */
  DashKeys.wifToAddr = async function (wif, opts) {
    let privBuf = await DashKeys._wifToPrivateKey(wif);

    let isCompressed = true;
    let pubBuf = Secp256k1.getPublicKey(privBuf, isCompressed);
    let pubKeyHash = await DashKeys.publicKeyToPubKeyHash(pubBuf);
    let pubKeyHashHex = DashKeys._uint8ArrayToHex(pubKeyHash);

    let addr = await b58c.encode({
      version: opts?.version,
      pubKeyHash: pubKeyHashHex,
    });

    return addr;
  };

  /**
   * @param {String} wif - private key
   * @returns {Promise<Uint8Array>}
   */
  DashKeys._wifToPrivateKey = async function (wif) {
    let b58cWif = b58c.decode(wif);
    let privateKey = DashKeys._hexToUint8Array(b58cWif.privateKey);
    return privateKey;
  };

  /**
   * @param {Uint8Array|Buffer} buf
   * @returns {Promise<Uint8Array>} - pubKeyHash buffer (no magic byte or checksum)
   */
  DashKeys.publicKeyToPubKeyHash = async function (buf) {
    let shaBuf = await sha256sum(buf);

    let ripemd = RIPEMD160.create();
    ripemd.update(shaBuf);
    let hash = ripemd.digest();

    return hash;
  };

  /**
   * JS Buffer to Hex that works for Little-Endian CPUs (ARM, x64, x86, WASM)
   * @param {Buffer|Uint8Array} buf
   * @returns {String} - hex
   */
  DashKeys._uint8ArrayToHex = function (buf) {
    /** @type {Array<String>} */
    let hex = [];

    buf.forEach(function (b) {
      let h = b.toString(16);
      h = h.padStart(2, "0");
      hex.push(h);
    });

    return hex.join("");
  };

  /**
   * Hex to JS Buffer that works in browsers and Little-Endian CPUs
   * (which is most of the - ARM, x64, x86, WASM, etc)
   * @param {String} hex
   * @returns {Uint8Array} - JS Buffer (Node and Browsers)
   */
  DashKeys._hexToUint8Array = function (hex) {
    let len = hex.length / 2;
    let buf = new Uint8Array(len);

    let index = 0;
    for (let i = 0; i < hex.length; i += 2) {
      let c = hex.slice(i, i + 2);
      let b = parseInt(c, 16);
      buf[index] = b;
      index += 1;
    }

    return buf;
  };

  if ("undefined" !== typeof module) {
    module.exports = DashKeys;
  }
})(("undefined" !== typeof module && module.exports) || window);

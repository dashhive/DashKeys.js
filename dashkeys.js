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
  DashKeys.pubKeyHashVersion = "4c";

  // "cc" for mainnet, "ef" for testnet, '80' for bitcoin
  DashKeys.privateKeyVersion = "cc";

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

    let hex = DashKeys._bufferToHex(privKey);
    let wif = await b58c.encode({
      version: opts?.version,
      privateKey: hex,
      compressed: true,
    });

    return wif;
  };

  /**
   * @param {String} addrOrWif - pay addr or private key wif
   * @param {Object} opts
   * @param {Boolean} opts.verify - 'false' to skip verification (default: 'true')
   */
  DashKeys.decode = async function (addrOrWif, opts) {
    let parts = await b58c.decode(addrOrWif);
    if (false !== opts?.verify) {
      parts = await b58c.verify(addrOrWif);
    }
    return parts;
  };

  /**
   * @param {String} addrOrWif - pay address or private key
   * @returns {Promise<Boolean>}
   * TODO separate functions for verifying PayAddr vs WIF
   */
  DashKeys.verify = async function (addrOrWif) {
    await b58c.verify(addrOrWif);
    return true;
  };

  /**
   * @param {String} wif - private key
   * @returns {Promise<String>}
   */
  DashKeys.wifToAddr = async function (wif) {
    let parts = await b58c.verify(wif);

    let privBuf = new Uint8Array(32);
    for (let i = 0; i < parts.privateKey.length; i += 2) {
      privBuf[i] = parts.privateKey.slice(i, i + 2);
    }

    let pubBuf = Secp256k1.getPublicKey(privBuf);
    let pubKeyHex = await DashKeys._bufferToPubKeyHash(pubBuf);
    let addr = await b58c.encode({
      pubKeyHash: pubKeyHex,
      compressed: true,
    });

    return addr;
  };

  /**
   * @param {Uint8Array|Buffer} buf
   * @returns {Promise<String>} - normal Pay Address (Base58Check for p2pkh)
   */
  DashKeys._bufferToPubKeyHash = async function (buf) {
    let shaBuf = await sha256sum(buf);

    let ripemd = RIPEMD160.create();
    ripemd.update(shaBuf);
    let hash = ripemd.digest("hex");

    return hash;
  };

  /**
   * JS Buffer to Hex that works for Little-Endian CPUs (ARM, x64, x86, WASM)
   * @param {Buffer|Uint8Array} buf
   * @returns {String} - hex
   */
  DashKeys._bufferToHex = function (buf) {
    /** @type {Array<String>} */
    let hex = [];

    buf.forEach(function (b) {
      let c = b.toString(16).padStart(2, "0");
      hex.push(c);
    });

    return hex.join("");
  };

  if ("undefined" !== typeof module) {
    module.exports = DashKeys;
  }
})(("undefined" !== typeof module && module.exports) || window);

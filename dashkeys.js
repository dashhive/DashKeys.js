/** @typedef {import('./base-x.types.js').BaseX} BaseX */
/** @typedef {import('./base-x.types.js').Create} BaseXCreate */
/** @typedef {import('./base-x.types.js').Decode} BaseXDecode */
/** @typedef {import('./base-x.types.js').DecodeUnsafe} BaseXDecodeUnsafe */
/** @typedef {import('./base-x.types.js').Encode} BaseXEncode */
/** @typedef {import('./base58check.types.js').Base58Check} Base58Check */
/** @typedef {import('./base58check.types.js').base58Check} Base58CheckInstance */
/** @typedef {import('./base58check.types.js').Checksum} Base58CheckChecksum */
/** @typedef {import('./base58check.types.js').Create} Base58CheckCreate */
/** @typedef {import('./base58check.types.js').Decode} Base58CheckDecode */
/** @typedef {import('./base58check.types.js').DecodeHex} Base58CheckDecodeHex */
/** @typedef {import('./base58check.types.js').Encode} Base58CheckEncode */
/** @typedef {import('./base58check.types.js').EncodeHex} Base58CheckEncodeHex */
/** @typedef {import('./base58check.types.js').EncodeParts} Base58CheckEncodeParts */
/** @typedef {import('./base58check.types.js').Parts} Base58CheckParts */
/** @typedef {import('./base58check.types.js').PrivateParts} Base58CheckPrivateParts */
/** @typedef {import('./base58check.types.js').PubKeyHashParts} Base58CheckPubKeyHashParts */
/** @typedef {import('./base58check.types.js').XPrvParts} Base58CheckXPrvParts */
/** @typedef {import('./base58check.types.js').XPubParts} Base58CheckXPubParts */

/** @typedef {import('./base58check.types.js').Verify} Base58CheckVerify */
/** @typedef {import('./base58check.types.js').VerifyHex} Base58CheckVerifyHex */
/** @typedef {import('./ripemd160.types.js').RIPEMD160} RIPEMD160 */
/** @typedef {import('./ripemd160.types.js').Create} RIPEMD160Create */
/** @typedef {import('./ripemd160.types.js').Digest} RIPEMD160Digest */
/** @typedef {import('./ripemd160.types.js').Hash} RIPEMD160Hash */
/** @typedef {import('./ripemd160.types.js').Update} RIPEMD160Update */

/**
 * @typedef DashKeys
 * @prop {DecodeBase58Check} decode
 * @prop {EncodeKeyUint8Array} encodeKey
 * @prop {AddressToPubKeyHash} addrToPkh
 * @prop {PubKeyHashToAddress} pkhToAddr
 * @prop {PrivateKeyToWif} privKeyToWif
 * @prop {PublicKeyToAddress} pubkeyToAddr
 * @prop {PublicKeyToPubKeyHash} pubkeyToPkh
 * @prop {WifToAddress} wifToAddr
 * @prop {WifToPrivateKey} wifToPrivKey
 * @prop {DashKeysUtils} utils
 * @prop {EncodeKeyUint8Array} _encodeXKey
 * @prop {Base58CheckInstance} _dash58check
 */

/**
 * @typedef DashKeysUtils
 * @prop {Uint8ArrayToHex} bytesToHex
 * @prop {GenerateWif} generateWifNonHd
 * @prop {HexToUint8Array} hexToBytes
 * @prop {Hasher} ripemd160sum
 * @prop {Hasher} sha256sum
 * @prop {ToPublicKey} toPublicKey
 */

/** @type {BaseX} */
//@ts-ignore
var BaseX = {};

/** @type {Base58Check} */
//@ts-ignore
var Base58Check = {};

/** @type {RIPEMD160} */
//@ts-ignore
var RIPEMD160 = {};

/** @typedef {"4c"} DASH_PKH */
/** @typedef {"8c"} DASH_PKH_TESTNET */
/** @typedef {"cc"} DASH_PRIV_KEY */
/** @typedef {"ef"} DASH_PRIV_KEY_TESTNET */
/** @typedef {"0488ade4"} XPRV */
/** @typedef {"0488b21e"} XPUB */
/** @typedef {"04358394"} TPRV */
/** @typedef {"043587cf"} TPUB */
/** @typedef {"mainnet"|"testnet"|DASH_PKH|DASH_PRIV_KEY|DASH_PKH_TESTNET|DASH_PRIV_KEY_TESTNET|"xprv"|"tprv"|"xpub"|"tpub"|XPRV|XPUB|TPRV|TPUB} VERSION */

/** @typedef {"mainnet"|"cc"|"testnet"|"ef"} VERSION_PRIVATE */

/** @type {DashKeys} */
//@ts-ignore
var DashKeys = ("object" === typeof module && exports) || {};
(function (Window, /** @type {DashKeys} */ _DashKeys) {
  "use strict";

  // generally the same across cryptocurrencies
  const BASE58 = `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`;
  // specific to DASH mainnet and testnet
  const DASH_PKH = "4c";
  const DASH_PKH_TESTNET = "8c";
  const DASH_PRIV_KEY = "cc";
  const DASH_PRIV_KEY_TESTNET = "ef";
  // generally the same across coins for mainnet
  const XPRV = "0488ade4";
  const XPUB = "0488b21e";
  // sometimes different for various coins on testnet
  const TPRV = "04358394";
  const TPUB = "043587cf";

  /** @type {typeof window.crypto} */
  let Crypto = globalThis.crypto;
  let Utils = {};

  /** @type {Uint8ArrayToHex} */
  Utils.bytesToHex = function (bytes) {
    /** @type {Array<String>} */
    let hex = [];

    bytes.forEach(function (b) {
      let h = b.toString(16);
      h = h.padStart(2, "0");
      hex.push(h);
    });

    return hex.join("");
  };

  /** @type {GenerateWif} */
  Utils.generateWifNonHd = async function (opts) {
    /** @type {import('@dashincubator/secp256k1')} */
    let Secp256k1 =
      //@ts-ignore
      Window.nobleSecp256k1 || require("@dashincubator/secp256k1");

    let privBytes = Secp256k1.utils.randomPrivateKey();
    let privateKey = Utils.bytesToHex(privBytes);
    let version = opts?.version ?? "";
    switch (version) {
      case "mainnet":
        version = DASH_PRIV_KEY;
        break;
      case "testnet":
        version = DASH_PRIV_KEY_TESTNET;
        break;
      default:
      // no change
    }

    let wif = await _DashKeys._dash58check.encode({ privateKey, version });
    return wif;
  };

  /** @type {HexToUint8Array} */
  Utils.hexToBytes = function (hex) {
    let len = hex.length / 2;
    let bytes = new Uint8Array(len);

    let index = 0;
    for (let i = 0; i < hex.length; i += 2) {
      let c = hex.slice(i, i + 2);
      let b = parseInt(c, 16);
      bytes[index] = b;
      index += 1;
    }

    return bytes;
  };

  /** @type {Hasher} */
  Utils.ripemd160sum = async function (bytes) {
    let hashBytes = await RIPEMD160.hash(bytes);
    return hashBytes;
  };

  /** @type {Hasher} */
  Utils.sha256sum = async function (bytes) {
    if (!Crypto.subtle) {
      //@ts-ignore
      let sha256 = Crypto.createHash("sha256").update(bytes).digest();
      return new Uint8Array(sha256);
    }
    let arrayBuffer = await Crypto.subtle.digest("SHA-256", bytes);
    let hashBytes = new Uint8Array(arrayBuffer);
    return hashBytes;
  };

  /** @type {ToPublicKey} */
  Utils.toPublicKey = async function (privBytes) {
    /** @type {import('@dashincubator/secp256k1')} */
    let Secp256k1 =
      //@ts-ignore
      Window.nobleSecp256k1 || require("@dashincubator/secp256k1");

    let isCompressed = true;
    return Secp256k1.getPublicKey(privBytes, isCompressed);
  };

  (function () {
    // BaseX

    // base58 (base-x) encoding / decoding
    // Copyright (c) 2022 Dash Incubator (base58)
    // Copyright (c) 2021-2022 AJ ONeal (base62)
    // Copyright (c) 2018 base-x contributors
    // Copyright (c) 2014-2018 The Bitcoin Core developers (base58.cpp)
    // Distributed under the MIT software license, see the accompanying
    // file LICENSE or http://www.opensource.org/licenses/mit-license.php.
    //
    // Taken from https://github.com/therootcompany/base62.js
    // which is a fork of https://github.com/cryptocoinjs/base-x

    /** @type {BaseXCreate} */
    BaseX.create = function (ALPHABET) {
      let baseX = {};

      if (!ALPHABET) {
        ALPHABET = BASE58;
      }
      if (ALPHABET.length >= 255) {
        throw new TypeError("Alphabet too long");
      }

      var BASE_MAP = new Uint8Array(256);
      for (var j = 0; j < BASE_MAP.length; j += 1) {
        BASE_MAP[j] = 255;
      }
      for (var i = 0; i < ALPHABET.length; i += 1) {
        var x = ALPHABET.charAt(i);
        var xc = x.charCodeAt(0);
        if (BASE_MAP[xc] !== 255) {
          throw new TypeError(x + " is ambiguous");
        }
        BASE_MAP[xc] = i;
      }

      var BASE = ALPHABET.length;
      var LEADER = ALPHABET.charAt(0);
      var FACTOR = Math.log(BASE) / Math.log(256); // log(BASE) / log(256), rounded up
      var iFACTOR = Math.log(256) / Math.log(BASE); // log(256) / log(BASE), rounded up
      /** @type {BaseXDecode} */
      baseX.decode = function (string) {
        var buffer = decodeUnsafe(string);
        if (buffer) {
          return buffer;
        }
        throw new Error("Non-base" + BASE + " character");
      };

      /** @type {BaseXDecodeUnsafe} */
      function decodeUnsafe(source) {
        if (typeof source !== "string") {
          throw new TypeError("Expected String");
        }
        if (source.length === 0) {
          return new Uint8Array(0);
        }
        var psz = 0;
        // Skip and count leading '1's.
        var zeroes = 0;
        var length = 0;
        while (source[psz] === LEADER) {
          zeroes += 1;
          psz += 1;
        }
        // Allocate enough space in big-endian base256 representation.
        var size = ((source.length - psz) * FACTOR + 1) >>> 0; // log(58) / log(256), rounded up.
        var b256 = new Uint8Array(size);
        // Process the characters.
        while (source[psz]) {
          // Decode character
          var carry = BASE_MAP[source.charCodeAt(psz)];
          // Invalid character
          if (carry === 255) {
            return null;
          }
          var i = 0;
          for (
            var it3 = size - 1;
            (carry !== 0 || i < length) && it3 !== -1;
            it3 -= 1, i += 1
          ) {
            carry += (BASE * b256[it3]) >>> 0;
            b256[it3] = carry % 256 >>> 0;
            carry = (carry / 256) >>> 0;
          }
          if (carry !== 0) {
            throw new Error("Non-zero carry");
          }
          length = i;
          psz += 1;
        }
        // Skip leading zeroes in b256.
        var it4 = size - length;
        while (it4 !== size && b256[it4] === 0) {
          it4 += 1;
        }
        var vch = new Uint8Array(zeroes + (size - it4));
        var j = zeroes;
        while (it4 !== size) {
          vch[j] = b256[it4];
          j += 1;
          it4 += 1;
        }
        return vch;
      }

      /** @type {BaseXEncode} */
      baseX.encode = function (source) {
        if (Array.isArray(source) || !(source instanceof Uint8Array)) {
          source = Uint8Array.from(source);
        }
        if (!(source instanceof Uint8Array)) {
          throw new TypeError("Expected Uint8Array");
        }
        if (source.length === 0) {
          return "";
        }
        // Skip & count leading zeroes.
        var zeroes = 0;
        var length = 0;
        var pbegin = 0;
        var pend = source.length;
        while (pbegin !== pend && source[pbegin] === 0) {
          pbegin += 1;
          zeroes += 1;
        }
        // Allocate enough space in big-endian base58 representation.
        var size = ((pend - pbegin) * iFACTOR + 1) >>> 0;
        var b58 = new Uint8Array(size);
        // Process the bytes.
        while (pbegin !== pend) {
          var carry = source[pbegin];
          // Apply "b58 = b58 * 256 + ch".
          var i = 0;
          for (
            var it1 = size - 1;
            (carry !== 0 || i < length) && it1 !== -1;
            it1 -= 1, i += 1
          ) {
            carry += (256 * b58[it1]) >>> 0;
            b58[it1] = carry % BASE >>> 0;
            carry = (carry / BASE) >>> 0;
          }
          if (carry !== 0) {
            throw new Error("Non-zero carry");
          }
          length = i;
          pbegin += 1;
        }
        // Skip leading zeroes in base58 result.
        var it2 = size - length;
        while (it2 !== size && b58[it2] === 0) {
          it2 += 1;
        }
        // Translate the result into a string.
        var str = LEADER.repeat(zeroes);
        for (; it2 < size; it2 += 1) {
          str += ALPHABET.charAt(b58[it2]);
        }
        return str;
      };

      return baseX;
    };
  })();

  (function () {
    // Base58Check

    // See also:
    // - https://en.bitcoin.it/wiki/Base58Check_encoding
    // - https://appdevtools.com/base58-encoder-decoder
    // - https://dashcore.readme.io/docs/core-ref-transactions-address-conversion
    // - https://docs.dash.org/en/stable/developers/testnet.html

    /** @type {Base58CheckCreate} */
    Base58Check.create = function (opts) {
      let dictionary = opts?.dictionary || BASE58;
      // See https://github.com/dashhive/dashkeys.js/blob/1f0f4e0d0aabf9e68d94925d660f00666f502391/dashkeys.js#L38
      let privateKeyVersion = opts?.privateKeyVersion || DASH_PRIV_KEY;
      let pubKeyHashVersion = opts?.pubKeyHashVersion || DASH_PKH;
      // From https://bitcoin.stackexchange.com/questions/38878/how-does-the-bip32-version-bytes-convert-to-base58
      let xprvVersion = opts?.xprvVersion || XPRV; // base58-encoded "xprv..."
      let xpubVersion = opts?.xpubVersion || XPUB; // base58-encoded "xpub..."

      let bs58 = BaseX.create(dictionary);
      let b58c = {};

      /** @type {Base58CheckChecksum} */
      b58c.checksum = async function (parts) {
        b58c._setVersion(parts);
        //@ts-ignore
        parts.compressed = true; // parts.compressed ?? true;

        let key =
          //@ts-ignore
          parts.pubKeyHash || parts.privateKey || parts.xprv || parts.xpub;
        let compression = "";
        //@ts-ignore
        if (parts.compressed && 64 === key.length) {
          compression = "01";
        }

        let hex = `${parts.version}${key}${compression}`;
        let check = await b58c._checksumHexRaw(hex);

        return check;
      };

      /**
       * @private
       * @param {String} hex
       */
      b58c._checksumHexRaw = async function (hex) {
        let buf = Utils.hexToBytes(hex);
        let hash1 = await Utils.sha256sum(buf);
        let hash2 = await Utils.sha256sum(hash1);

        let last4 = hash2.slice(0, 4);
        let check = Utils.bytesToHex(last4);
        return check;
      };

      /**
       * @private
       * @param {Base58CheckEncodeParts} parts
       */
      b58c._setVersion = function (parts) {
        //@ts-ignore
        if (parts.pubKeyHash) {
          //@ts-ignore
          if (parts.privateKey) {
            throw new Error(
              `[@dashincubator/base58check] either 'privateKey' or 'pubKeyHash' must exist, but not both`,
            );
          }
        }

        if (!parts.version) {
          //@ts-ignore
          if (parts.privateKey) {
            parts.version = privateKeyVersion;
          }
          //@ts-ignore
          else if (parts.pubKeyHash) {
            parts.version = pubKeyHashVersion;
          }
          return;
        }

        //@ts-ignore
        if (parts.privateKey) {
          if (parts.version === pubKeyHashVersion) {
            throw new Error(
              `[@dashincubator/base58check] '${parts.version}' is a public version, but the given key is private`,
            );
          }
          return;
        }

        //@ts-ignore
        if (parts.pubKeyHash) {
          if (parts.version === privateKeyVersion) {
            throw new Error(
              `[@dashincubator/base58check] '${parts.version}' is a private version, but the given key is a pubKeyHash`,
            );
          }
        }
      };

      /** @type {Base58CheckVerify} */
      b58c.verify = async function (b58Addr, opts) {
        let bytes = bs58.decode(b58Addr);
        let hex = Utils.bytesToHex(bytes);
        return await b58c.verifyHex(hex, opts);
      };

      /** @type {Base58CheckVerifyHex} */
      b58c.verifyHex = async function (base58check, opts) {
        let parts = b58c.decodeHex(base58check, opts);
        let check = await b58c.checksum(parts);
        let valid = parts.check === check;

        if (!valid) {
          if (false !== opts?.verify) {
            throw new Error(`expected '${parts.check}', but got '${check}'`);
          }
          parts.valid = valid;
        }

        return parts;
      };

      /** @type {Base58CheckDecode} */
      b58c.decode = function (b58Addr, opts) {
        let bytes = bs58.decode(b58Addr);
        let hex = Utils.bytesToHex(bytes);
        return b58c.decodeHex(hex, opts);
      };

      /** @type {Base58CheckDecodeHex} */
      b58c.decodeHex = function (addr, opts) {
        let version = addr.slice(0, privateKeyVersion.length);
        let versions = opts?.versions || [pubKeyHashVersion, privateKeyVersion];
        let xversions = opts?.xversions || [xpubVersion, xprvVersion];
        let isXKey = false;

        if (!versions.includes(version)) {
          let xversion = addr.slice(0, xprvVersion.length);
          isXKey = xversions.includes(xversion);
          if (!isXKey) {
            throw new Error(
              `[@dashincubator/base58check] expected pubKeyHash (or privateKey) to start with 0x${pubKeyHashVersion} (or 0x${privateKeyVersion}), not '0x${version}'`,
            );
          }
          version = xversion;
        }

        // Public Key Hash: 1 + 20 + 4 // 50 hex
        // Private Key: 1 + 32 + 1 + 4 // 74 or 76 hex
        if (![50, 74, 76].includes(addr.length)) {
          if (!isXKey) {
            throw new Error(
              `pubKeyHash (or privateKey) isn't as long as expected (should be 50, 74, or 76 hex chars, not ${addr.length})`,
            );
          }
        }

        let rawAddr = addr.slice(version.length, -8);
        if (50 === addr.length) {
          return {
            version: version,
            pubKeyHash: rawAddr,
            check: addr.slice(-8),
          };
        }

        if (isXKey) {
          if (version === xprvVersion) {
            return {
              version: version,
              xprv: rawAddr,
              check: addr.slice(-8),
            };
          }
          return {
            version: version,
            xpub: rawAddr,
            check: addr.slice(-8),
          };
        }

        return {
          version: version,
          privateKey: rawAddr.slice(0, 64),
          compressed: true, // "01" === rawAddr.slice(64),
          check: addr.slice(-8),
        };
      };

      /** @type {Base58CheckEncode} */
      b58c.encode = async function (parts) {
        //@ts-ignore
        if (parts.xprv) {
          let version = parts.version || xprvVersion;
          //@ts-ignore
          return await b58c._encodeXKey(`${version}${parts.xprv}`);
        }
        //@ts-ignore
        if (parts.xpub) {
          let version = parts.version || xpubVersion;
          //@ts-ignore
          return await b58c._encodeXKey(`${version}${parts.xpub}`);
        }

        let hex = await b58c.encodeHex(parts);
        let bytes = Utils.hexToBytes(hex);
        return bs58.encode(bytes);
      };

      /** @type {Base58CheckEncodeHex} */
      b58c.encodeHex = async function (parts) {
        //@ts-ignore
        if (parts.pubKeyHash) {
          return await b58c._encodePubKeyHashHex(parts);
        }

        //@ts-ignore
        if (parts.privateKey) {
          return await b58c._encodePrivateKeyHex(parts);
        }

        throw new Error(
          `[@dashincubator/base58check] either 'privateKey' or 'pubKeyHash' must exist to encode`,
        );
      };

      /**
       * @private
       * @param {String} versionAndKeyHex
       */
      b58c._encodeXKey = async function (versionAndKeyHex) {
        let checkHex = await b58c._checksumHexRaw(versionAndKeyHex);
        let bytes = Utils.hexToBytes(`${versionAndKeyHex}${checkHex}`);
        return bs58.encode(bytes);
      };

      /**
       * @private
       * @param {Base58CheckEncodeParts} parts
       */
      b58c._encodePrivateKeyHex = async function (parts) {
        parts.compressed = true; // parts.compressed ?? true;

        //@ts-ignore
        let key = parts.privateKey;
        if (66 === key.length && "01" === key.slice(-2)) {
          //key.slice(0, 64);
          parts.compressed = true;
        } else if (64 === key.length && parts.compressed) {
          key += "01";
        } else {
          throw new Error(
            `[@dashincubator/dashkeys/base58check] ${key.length} is not a valid length for a private key - it should be 32 bytes (64 hex chars), or 33 bytes with compressed marker byte`,
          );
        }

        b58c._setVersion(parts);

        // after version and compression are set
        let check = await b58c.checksum(parts);

        return `${parts.version}${key}${check}`;
      };

      /**
       * @private
       * @param {Base58CheckEncodeParts} parts
       */
      b58c._encodePubKeyHashHex = async function (parts) {
        //@ts-ignore
        let key = parts.pubKeyHash;

        if (40 !== key.length) {
          throw new Error(
            `[@dashincubator/base58check] ${key.length} is not a valid pub key hash length, should be 20 bytes (40 hex chars)`,
          );
        }

        b58c._setVersion(parts);

        // after version is set
        let check = await b58c.checksum(parts);

        return `${parts.version}${key}${check}`;
      };

      return b58c;
    };
  })();

  (function () {
    // RIPEMD160
    const ARRAY16 = new Array(16);

    const zl = [
      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6,
      15, 3, 12, 0, 9, 5, 2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6,
      13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2, 4, 0,
      5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
    ];

    const zr = [
      5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13,
      5, 10, 14, 15, 8, 12, 4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2,
      10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14, 12,
      15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
    ];

    const sl = [
      11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11,
      9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8,
      13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5,
      12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
    ];

    const sr = [
      8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12,
      8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13,
      5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15,
      8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
    ];

    const hl = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];
    const hr = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000];

    const blockSize = 64;

    class _RIPEMD160 {
      constructor() {
        // state
        /** @private */
        this._a = 0x67452301;
        /** @private */
        this._b = 0xefcdab89;
        /** @private */
        this._c = 0x98badcfe;
        /** @private */
        this._d = 0x10325476;
        /** @private */
        this._e = 0xc3d2e1f0;

        /** @private */
        this._block = new Uint8Array(blockSize);
        /** @private */
        this._blockSize = blockSize;
        /** @private */
        this._blockOffset = 0;
        /** @private */
        this._length = [0, 0, 0, 0];

        /** @private */
        this._finalized = false;
      }

      /** @type {RIPEMD160Update} */
      update(data) {
        if (this._finalized) {
          throw new Error("Digest already called");
        }
        if (!(data instanceof Uint8Array)) {
          throw new Error("update() requires a Uint8Array");
        }

        // consume data
        const block = this._block;
        let offset = 0;
        while (this._blockOffset + data.length - offset >= this._blockSize) {
          for (let i = this._blockOffset; i < this._blockSize; ) {
            block[i++] = data[offset++];
          }
          this._update();
          this._blockOffset = 0;
        }
        while (offset < data.length) {
          block[this._blockOffset++] = data[offset++];
        }

        // update length
        for (let j = 0, carry = data.length * 8; carry > 0; ++j) {
          this._length[j] += carry;
          carry = (this._length[j] / 0x0100000000) | 0;
          if (carry > 0) {
            this._length[j] -= 0x0100000000 * carry;
          }
        }

        return this;
      }

      /** @private */
      _update() {
        const words = ARRAY16;
        const dv = new DataView(
          this._block.buffer,
          this._block.byteOffset,
          blockSize,
        );
        for (let j = 0; j < 16; ++j) {
          words[j] = dv.getInt32(j * 4, true);
        }

        let al = this._a | 0;
        let bl = this._b | 0;
        let cl = this._c | 0;
        let dl = this._d | 0;
        let el = this._e | 0;

        let ar = this._a | 0;
        let br = this._b | 0;
        let cr = this._c | 0;
        let dr = this._d | 0;
        let er = this._e | 0;

        // computation
        for (let i = 0; i < 80; i += 1) {
          let tl;
          let tr;
          if (i < 16) {
            tl = fn1(al, bl, cl, dl, el, words[zl[i]], hl[0], sl[i]);
            tr = fn5(ar, br, cr, dr, er, words[zr[i]], hr[0], sr[i]);
          } else if (i < 32) {
            tl = fn2(al, bl, cl, dl, el, words[zl[i]], hl[1], sl[i]);
            tr = fn4(ar, br, cr, dr, er, words[zr[i]], hr[1], sr[i]);
          } else if (i < 48) {
            tl = fn3(al, bl, cl, dl, el, words[zl[i]], hl[2], sl[i]);
            tr = fn3(ar, br, cr, dr, er, words[zr[i]], hr[2], sr[i]);
          } else if (i < 64) {
            tl = fn4(al, bl, cl, dl, el, words[zl[i]], hl[3], sl[i]);
            tr = fn2(ar, br, cr, dr, er, words[zr[i]], hr[3], sr[i]);
          } else {
            // if (i<80) {
            tl = fn5(al, bl, cl, dl, el, words[zl[i]], hl[4], sl[i]);
            tr = fn1(ar, br, cr, dr, er, words[zr[i]], hr[4], sr[i]);
          }

          al = el;
          el = dl;
          dl = rotl(cl, 10);
          cl = bl;
          bl = tl;

          ar = er;
          er = dr;
          dr = rotl(cr, 10);
          cr = br;
          br = tr;
        }

        // update state
        const t = (this._b + cl + dr) | 0;
        this._b = (this._c + dl + er) | 0;
        this._c = (this._d + el + ar) | 0;
        this._d = (this._e + al + br) | 0;
        this._e = (this._a + bl + cr) | 0;
        this._a = t;
      }

      /** @type {RIPEMD160Digest} */
      digest() {
        if (this._finalized) {
          throw new Error("Digest already called");
        }
        this._finalized = true;

        const dig = this._digest();
        return dig;
      }

      /**
       * @returns {Uint8Array}
       */
      _digest() {
        // create padding and handle blocks
        this._block[this._blockOffset++] = 0x80;
        if (this._blockOffset > 56) {
          for (let i = this._blockOffset; i < 64; i++) {
            this._block[i] = 0;
          }
          this._update();
          this._blockOffset = 0;
        }

        for (let i = this._blockOffset; i < 56; i++) {
          this._block[i] = 0;
        }
        let dv = new DataView(
          this._block.buffer,
          this._block.byteOffset,
          blockSize,
        );
        dv.setUint32(56, this._length[0], true);
        dv.setUint32(60, this._length[1], true);
        this._update();

        // produce result
        const buffer = new Uint8Array(20);
        dv = new DataView(buffer.buffer, buffer.byteOffset, 20);
        dv.setInt32(0, this._a, true);
        dv.setInt32(4, this._b, true);
        dv.setInt32(8, this._c, true);
        dv.setInt32(12, this._d, true);
        dv.setInt32(16, this._e, true);
        return buffer;
      }
    }

    /** @type {RIPEMD160Create} */
    RIPEMD160.create = function () {
      return new _RIPEMD160();
    };

    /** @type {RIPEMD160Hash} */
    RIPEMD160.hash = function (bytes) {
      let hasher = new _RIPEMD160();
      hasher.update(bytes);
      return hasher.digest();
    };

    /**
     * @param {number} x
     * @param {number} n
     * @returns {number}
     */
    function rotl(x, n) {
      return (x << n) | (x >>> (32 - n));
    }

    /**
     * @param {number} a
     * @param {number} b
     * @param {number} c
     * @param {number} d
     * @param {number} e
     * @param {number} m
     * @param {number} k
     * @param {number} s
     * @returns {number}
     */
    function fn1(a, b, c, d, e, m, k, s) {
      return (rotl((a + (b ^ c ^ d) + m + k) | 0, s) + e) | 0;
    }

    /**
     * @param {number} a
     * @param {number} b
     * @param {number} c
     * @param {number} d
     * @param {number} e
     * @param {number} m
     * @param {number} k
     * @param {number} s
     * @returns {number}
     */
    function fn2(a, b, c, d, e, m, k, s) {
      return (rotl((a + ((b & c) | (~b & d)) + m + k) | 0, s) + e) | 0;
    }

    /**
     * @param {number} a
     * @param {number} b
     * @param {number} c
     * @param {number} d
     * @param {number} e
     * @param {number} m
     * @param {number} k
     * @param {number} s
     * @returns
     */
    function fn3(a, b, c, d, e, m, k, s) {
      return (rotl((a + ((b | ~c) ^ d) + m + k) | 0, s) + e) | 0;
    }

    /**
     * @param {number} a
     * @param {number} b
     * @param {number} c
     * @param {number} d
     * @param {number} e
     * @param {number} m
     * @param {number} k
     * @param {number} s
     * @returns {number}
     */
    function fn4(a, b, c, d, e, m, k, s) {
      return (rotl((a + ((b & d) | (c & ~d)) + m + k) | 0, s) + e) | 0;
    }

    /**
     * @param {number} a
     * @param {number} b
     * @param {number} c
     * @param {number} d
     * @param {number} e
     * @param {number} m
     * @param {number} k
     * @param {number} s
     * @returns {number}
     */
    function fn5(a, b, c, d, e, m, k, s) {
      return (rotl((a + (b ^ (c | ~d)) + m + k) | 0, s) + e) | 0;
    }
  })();

  let dash58check = Base58Check.create();
  //@ts-ignore
  _DashKeys._dash58check = dash58check;

  /** @type {AddressToPubKeyHash} */
  _DashKeys.addrToPkh = async function (address, opts) {
    /** @type {Base58CheckPubKeyHashParts} */
    //@ts-ignore - address has pkh parts
    let addrParts = await _DashKeys.decode(address, opts);
    let shaRipeBytes = Utils.hexToBytes(addrParts.pubKeyHash);

    return shaRipeBytes;
  };

  /** @type {DecodeBase58Check} */
  _DashKeys.decode = async function (keyB58c, opts) {
    /* jshint maxcomplexity:35 */
    let _opts = {};
    if (opts?.version) {
      switch (opts.version) {
        case XPRV:
        /* fallsthrough */
        case "xprv":
        /* fallsthrough */
        case 0x0488ade4:
        /* fallsthrough */
        case XPUB:
        /* fallsthrough */
        case "xpub":
        /* fallsthrough */
        case 0x0488b21e:
        /* fallsthrough */
        case DASH_PRIV_KEY:
        /* fallsthrough */
        case 0xcc:
        /* fallsthrough */
        case DASH_PKH:
        /* fallsthrough */
        case 0x4c:
        /* fallsthrough */
        case "mainnet":
          Object.assign(_opts, {
            versions: [DASH_PKH, DASH_PRIV_KEY],
            xversions: [XPRV, XPUB],
          });
          break;

        case TPRV:
        /* fallsthrough */
        case "tprv":
        /* fallsthrough */
        case 0x04358394:
        /* fallsthrough */
        case TPUB:
        /* fallsthrough */
        case "tpub":
        /* fallsthrough */
        case 0x043587cf:
        /* fallsthrough */
        case DASH_PRIV_KEY_TESTNET:
        /* fallsthrough */
        case 0xef:
        /* fallsthrough */
        case DASH_PKH_TESTNET:
        /* fallsthrough */
        case 0x8c:
        /* fallsthrough */
        case "testnet":
          Object.assign(_opts, {
            versions: [DASH_PKH_TESTNET, DASH_PRIV_KEY_TESTNET],
            xversions: [TPRV, TPUB],
          });
          break;
        default:
          throw new Error(`unknown version ${opts.version}`);
      }
    }
    if (opts?.versions) {
      Object.assign(_opts, opts);
    }
    let parts = await dash58check.decode(keyB58c, _opts);
    let check = await dash58check.checksum(parts);
    let valid = parts.check === check;
    if (!valid) {
      if (false !== opts?.validate) {
        // to throw the inner error
        await dash58check.verify(keyB58c, _opts);
      }
    }
    parts.valid = valid;

    switch (parts.version) {
      case DASH_PKH:
      /* fallsthrough */
      case DASH_PKH_TESTNET:
        parts.type = "pkh";
        break;
      case DASH_PRIV_KEY:
      /* fallsthrough */
      case DASH_PRIV_KEY_TESTNET:
        parts.type = "private";
        break;
      case XPRV:
      /* fallsthrough */
      case TPRV:
        parts.type = "xprv";
        break;
      case XPUB:
      /* fallsthrough */
      case TPUB:
        parts.type = "xpub";
        break;
      default:
        throw new Error(`unknown version ${parts.version}`);
    }

    return parts;
  };

  /** @type {EncodeKeyUint8Array} */
  _DashKeys.encodeKey = async function (keyBytes, opts = {}) {
    if (20 === keyBytes.length) {
      if (!opts.version) {
        opts.version = DASH_PKH;
      }
      return await _DashKeys.pkhToAddr(keyBytes, opts);
    }

    if (32 === keyBytes.length) {
      if (!opts.version) {
        opts.version = DASH_PRIV_KEY;
      }
      return await _DashKeys.privKeyToWif(
        keyBytes,
        //@ts-ignore - is private key opts (see above)
        opts,
      );
    }

    if (33 === keyBytes.length) {
      let pkhBytes = await _DashKeys.pubkeyToPkh(keyBytes);
      if (!opts.version) {
        opts.version = DASH_PKH;
      }
      return await _DashKeys.pkhToAddr(pkhBytes, opts);
    }

    if (74 === keyBytes.length) {
      if (!opts.version) {
        if (0x00 === keyBytes[41]) {
          opts.version = XPRV;
        } else {
          opts.version = XPUB;
        }
      }
      return await _DashKeys._encodeXKey(keyBytes, opts);
    }

    throw new Error(
      `invalid key bytes length '${keyBytes.length}': must be 20 (PubKeyHash), 32 (PrivateKey), or 74 (Extended Key)`,
    );
  };

  _DashKeys._encodeXKey = async function (xkeyBytes, opts) {
    let xkey = Utils.bytesToHex(xkeyBytes);
    let version = opts?.version;

    let xprv;
    let xpub;
    switch (version) {
      case "xprv":
        version = XPRV;
        xprv = xkey;
        break;
      case "tprv":
        version = TPRV;
        xprv = xkey;
        break;
      case "xpub":
        version = XPUB;
        xpub = xkey;
        break;
      case "tpub":
        version = TPUB;
        xpub = xkey;
        break;
      default:
        throw new Error(
          `cannot determine Extended Key (xkey) type from bytes length: please supply 'version' as 'xprv', 'xpub', 'tprv', or 'tpub'`,
        );
    }

    let xkeyB58c = await dash58check.encode({
      version,
      xprv,
      xpub,
    });
    return xkeyB58c;
  };

  /** @type {PubKeyHashToAddress} */
  _DashKeys.pkhToAddr = async function (shaRipeBytes, opts) {
    let pubKeyHash = Utils.bytesToHex(shaRipeBytes);
    let version = opts?.version;

    switch (version) {
      case "mainnet":
        version = DASH_PKH;
        break;
      case "testnet":
        version = DASH_PKH_TESTNET;
        break;
      case DASH_PKH:
        // keep as is
        break;
      case DASH_PKH_TESTNET:
        // keep as is
        break;
      default:
        throw new Error(
          `Address (PubKey Hash) version must be "mainnet" ("${DASH_PKH}") or "testnet" ("${DASH_PKH_TESTNET}"), not '${version}'`,
        );
    }

    let addr = await dash58check.encode({
      pubKeyHash,
      version,
    });
    return addr;
  };

  /** @type {PrivateKeyToWif} */
  _DashKeys.privKeyToWif = async function (privBytes, opts) {
    let privateKey = Utils.bytesToHex(privBytes);
    let version = opts?.version || "mainnet";

    switch (version) {
      case "mainnet":
        version = DASH_PRIV_KEY;
        break;
      case "testnet":
        version = DASH_PRIV_KEY_TESTNET;
        break;
      case DASH_PRIV_KEY:
        // keep as is
        break;
      case DASH_PRIV_KEY_TESTNET:
        // keep as is
        break;
      default:
        throw new Error(
          `WIF (Private Key) version must be "mainnet" ("${DASH_PRIV_KEY}") or "testnet" ("${DASH_PRIV_KEY_TESTNET}"), not '${version}'`,
        );
    }

    let wif = await dash58check.encode({
      privateKey,
      version,
    });
    return wif;
  };

  /** @type {PublicKeyToAddress} */
  _DashKeys.pubkeyToAddr = async function (pubBytes, opts) {
    let shaRipeBytes = await _DashKeys.pubkeyToPkh(pubBytes);
    let addr = await _DashKeys.pkhToAddr(
      shaRipeBytes,
      //@ts-ignore - has version property
      opts,
    );

    return addr;
  };

  /** @type {PublicKeyToPubKeyHash} */
  _DashKeys.pubkeyToPkh = async function (pubBytes) {
    let shaBytes = await Utils.sha256sum(pubBytes);
    let shaRipeBytes = await Utils.ripemd160sum(shaBytes);

    return shaRipeBytes;
  };

  /** @type {WifToAddress} */
  _DashKeys.wifToAddr = async function (wif, opts) {
    let versionCode = opts?.version || "mainnet";
    /** @type {VERSION_PRIVATE} */
    let privVersion = DASH_PRIV_KEY;
    /** @type {VERSION} */
    let pubVersion = DASH_PKH;

    switch (versionCode) {
      case DASH_PRIV_KEY:
      /* fallsthrough */
      case DASH_PKH:
      /* fallsthrough */
      case "mainnet":
        privVersion = DASH_PRIV_KEY;
        pubVersion = DASH_PKH;
        break;
      case DASH_PKH_TESTNET:
      /* fallsthrough */
      case DASH_PRIV_KEY_TESTNET:
      /* fallsthrough */
      case "testnet":
        privVersion = DASH_PRIV_KEY_TESTNET;
        pubVersion = DASH_PKH_TESTNET;
        break;
      default:
        let msg = `'version' must be "mainnet" or "testnet", not '${versionCode}', or use priv => priv or pub => pub methods for more control`;
        throw new Error(msg);
    }

    let privBytes = await _DashKeys.wifToPrivKey(wif, { version: privVersion });

    let pubBytes = await Utils.toPublicKey(privBytes);
    let pubKeyHash = await _DashKeys.pubkeyToPkh(pubBytes);
    let pubKeyHashHex = Utils.bytesToHex(pubKeyHash);

    let addr = await dash58check.encode({
      pubKeyHash: pubKeyHashHex,
      version: pubVersion,
    });
    return addr;
  };

  /**
   * @param {String} wif - Base58Check-encoded Private Key
   * @param {DecodeOpts} [opts]
   * @returns {Promise<Uint8Array>} - private key (no magic byte or checksum)
   */
  _DashKeys.wifToPrivKey = async function (wif, opts) {
    let wifParts = await _DashKeys.decode(wif, opts);
    //@ts-ignore - wifParts does have privateKey
    let privBytes = Utils.hexToBytes(wifParts.privateKey);

    return privBytes;
  };

  /**
   * @callback PrivateKeyToWif
   * @param {Uint8Array} privBytes
   * @param {EncodeKeyUint8ArrayOpts} [opts]
   * @returns {Promise<String>} - wif
   */

  _DashKeys.utils = Utils;

  //@ts-ignore
  Window.DashKeys = _DashKeys;
  //@ts-ignore
  Window.BaseX = _DashKeys.BaseX = BaseX;
  //@ts-ignore
  Window.Base58 = _DashKeys.Base58 = BaseX;
  //@ts-ignore
  Window.Base58Check = _DashKeys.Base58Check = Base58Check;
  //@ts-ignore
  Window.RIPEMD160 = _DashKeys.RIPEMD160 = RIPEMD160;
})(globalThis.window || /** @type {window} */ {}, DashKeys);
if ("object" === typeof module) {
  module.exports = DashKeys;
}

// Type Aliases

/** @typedef {String} HexString */

// Type Definitions

/**
 * @callback AddressToPubKeyHash
 * @param {String} addr - Base58Check encoded version + pkh + check
 * @param {DecodeOpts} [opts]
 * @returns {Promise<Uint8Array>} - pkh bytes (no version or check, NOT Base58Check)
 */

/**
 * @callback DecodeBase58Check
 * @param {String} keyB58c - addr, wif, or xkey (xprv, xpub)
 * @param {DecodeOpts} [opts]
 * @returns {Promise<Base58CheckParts>}
 */

/**
 * @typedef DecodeOpts
 * @prop {Boolean} [validate] - throw if check fails, true by default
 * @prop {Array<VERSION|Number>} [versions]
 * @prop {VERSION|Number} [version]
 */

/**
 * @callback EncodeKeyUint8Array
 * @param {Uint8Array} keyBytes - privKey, pkh, or xkey (xprv or xpub) bytes
 * @param {EncodeKeyUint8ArrayOpts} [opts]
 * @returns {Promise<String>} - Address or WIF (or Extended Key - xPrv or xPub)
 * @throws {Error}
 */

/**
 * @typedef EncodeKeyUint8ArrayOpts
 * @prop {VERSION} [version] - needed for xprv and xpub, or testnet
 */

/**
 * Developer Convenience function for Generating Non-HD (NON-RECOVERABLE) WIFs
 * @callback GenerateWif
 * @param {PrivateKeyToWifOpts} [opts]
 * @returns {Promise<String>} - JS Bytes Buffer (Uint8Array, Node & Browsers)
 */

/**
 * @callback Hasher
 * @param {Uint8Array|Buffer} bytes
 * @returns {Promise<Uint8Array>} - hash Uint8Array
 */

/**
 * Hex to JS Bytes Buffer (Uint8Array)
 * @callback HexToUint8Array
 * @param {String} hex - hex
 * @returns {Uint8Array} - JS Bytes Buffer (Uint8Array, Node & Browsers)
 */

/**
 * @callback PrivateKeyToWif
 * @param {Uint8Array} privBytes
 * @param {PrivateKeyToWifOpts} [opts]
 * @returns {Promise<String>}
 */

/**
 * @typedef PrivateKeyToWifOpts
 * @prop {VERSION_PRIVATE} version - "mainnet" ("cc") by default
 */

/**
 * @callback PubKeyHashToAddress
 * @param {Uint8Array} shaRipeBytes - PubKey Hash (no magic byte or checksum)
 * @param {EncodeKeyUint8ArrayOpts} opts - for version
 * @returns {Promise<String>} - Address
 */

/**
 * @callback PublicKeyToAddress
 * @param {Uint8Array} pubBytes - Public Key Uint8Array
 * @param {EncodeKeyUint8ArrayOpts} [opts] - for coin version
 * @returns {Promise<String>} - Address
 */

/**
 * @callback PublicKeyToPubKeyHash
 * @param {Uint8Array|Buffer} pubBytes - Public Key Uint8Array
 * @returns {Promise<Uint8Array>} - pubKeyHash Uint8Array (no magic byte or checksum)
 */

/**
 * @callback ToPublicKey
 * @param {Uint8Array} privBytes - Private Key Uint8Array
 * @returns {Promise<Uint8Array>} - Public Key Uint8Array
 */

/**
 * JS Bytes Buffer (Uint8Array) to Hex
 * @callback Uint8ArrayToHex
 * @param {Uint8Array} bytes
 * @returns {String} - hex
 */

/**
 * Converts a WIF-encoded PrivateKey to a PubKey Hash
 * (of the same coin type, of course)
 * @callback WifToAddress
 * @param {String} wif - private key
 * @param {EncodeKeyUint8ArrayOpts} [opts]
 * @returns {Promise<String>} - address
 */

/**
 * Decodes a WIF-encoded PrivateKey to Bytes
 * @callback WifToPrivateKey
 * @param {String} wif - private key
 * @param {PrivateKeyToWifOpts} [opts]
 * @returns {Promise<Uint8Array>}
 */

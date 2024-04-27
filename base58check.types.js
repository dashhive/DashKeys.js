module.exports._types = true;
/**
 * @typedef Base58Check
 * @prop {Create} create
 */

/**
 * @callback Create
 * @param {Base58CheckOpts} [opts]
 */

/**
 * @typedef base58Check
 * @prop {Checksum} checksum
 * @prop {Decode} decode
 * @prop {DecodeHex} decodeHex
 * @prop {Encode} encode
 * @prop {EncodeHex} encodeHex
 * @prop {Verify} verify
 * @prop {VerifyHex} verifyHex
 * @prop {Function} _checksumHexRaw
 * @prop {Function} _encodeXKey
 * @prop {Function} _encodePrivateKeyHex
 * @prop {Function} _encodePubKeyHashHex
 * @prop {Function} _setVersion
 */

/**
 * Base58Check Options, see https://github.com/dashhive/dashkeys.js/blob/1f0f4e0d0aabf9e68d94925d660f00666f502391/dashkeys.js#L38 and see https://bitcoin.stackexchange.com/questions/38878/how-does-the-bip32-version-bytes-convert-to-base58
 * @typedef Base58CheckOpts
 * @prop {String} [opts.dictionary] - "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" for Dash / Bitcoin Base58
 * @prop {String} [opts.privateKeyVersion] - "cc" for mainnet (default), "ef" for testnet, '80' for bitcoin
 * @prop {String} [opts.pubKeyHashVersion] - "4c" for mainnet (default), "8c" for testnet, "00" for bitcoin
 * @prop {String} [opts.xprvVersion] - "4c" for mainnet (default), "8c" for testnet, "00" for bitcoin
 * @prop {String} [opts.xprvVersion] - "0488ade4" for "xprv" on mainnet (default), "04358394" for "tprv" on testnet
 * @prop {String} [opts.xpubVersion] - "0488b21e" for "xpub" on mainnet (default), "043587cf" for "tpub" on testnet
 */

/**
 * @typedef {PrivateParts|PubKeyHashParts|XPrvParts|XPubParts} Parts
 */

/**
 * @typedef PrivatePartial
 * @prop {String} privateKey
 */

/**
 * @typedef PubKeyHashPartial
 * @prop {String} pubKeyHash
 */

/**
 * @typedef XPrvPartial
 * @prop {String} xprv
 */

/**
 * @typedef XPubPartial
 * @prop {String} xpub
 */

/**
 * @typedef {PrivatePartial|PubKeyHashPartial|XPrvPartial|XPubPartial} PartsPartial
 */

/**
 * @typedef PartsOptionalPartial
 * @prop {String} [check]
 * @prop {true} [compressed]
 * @prop {String} [version]
 */

/**
 * @typedef {PartsPartial & PartsOptionalPartial} EncodeParts
 */

/** @typedef {"private"|"pkh"|"xprv"|"xpub"|""} KeyType */

/**
 * @typedef PrivateParts
 * @prop {String} check - the 4 checksum bytes
 * @prop {true} compressed - expect (public key) hash to be of the X value only
 * @prop {String} privateKey - hex private key
 * @prop {String} [pubKeyHash] - hex (public key) hash
 * @prop {KeyType} [type] - "private"
 * @prop {Boolean} [valid] - checksum passed
 * @prop {String} version - 1 magic bytes
 */

/**
 * @typedef PubKeyHashParts
 * @prop {String} check - the 4 checksum bytes
 * @prop {String} pubKeyHash - hex sha256-ripemd160 hash of public key
 * @prop {KeyType} [type] - "pkh"
 * @prop {Boolean} [valid] - checksum passed
 * @prop {String} version - 1 magic bytes
 */

/**
 * @typedef XPrvParts
 * @prop {String} check - the 4 checksum bytes
 * @prop {String} xprv - hex extended private key
 * @prop {KeyType} [type] - "xprv"
 * @prop {Boolean} [valid] - checksum passed
 * @prop {String} version - 4 magic bytes
 * @prop {String} [xpub] - hex extended public key
 */

/**
 * @typedef XPubParts
 * @prop {String} check - the 4 checksum bytes
 * @prop {KeyType} [type] - "xpub"
 * @prop {Boolean} [valid] - checksum passed
 * @prop {String} version - 4 magic bytes
 * @prop {String} xpub - hex extended public key
 */

/**
 * @callback Checksum
 * @param {Parts|EncodeParts} parts - private key or public hash or xkey parts
 * @returns {Promise<String>} - 8 hex chars (4 bytes) of checksum
 */

/**
 * @callback Decode
 * @param {String} base58check - WIF, Payment Address, xPrv, or xPub
 * @param {DecodeOpts} opts
 * @returns {Parts}
 */

/**
 * @callback DecodeHex
 * @param {String} hex - magic version bytes + data + checksum
 * @param {DecodeOpts} [opts]
 * @returns {Parts}
 */

/**
 * @typedef DecodeOpts
 * @prop {[String, String]} [versions]
 * @prop {[String, String]} [xversions]
 */

/**
 * @callback Verify
 * @param {String} base58check - WIF, Payment Address, xPrv, or xPub
 * @param {VerifyOpts} [opts]
 * @returns {Promise<Parts>}
 * @throws {Error}
 */

/**
 * @callback VerifyHex
 * @param {String} hex - magic version bytes + data + checksum
 * @param {VerifyOpts} [opts]
 * @returns {Promise<Parts>}
 * @throws {Error}
 */

/**
 * @typedef {DecodeOpts & VerifyOptsPartial} VerifyOpts
 * @typedef VerifyOptsPartial
 * @prop {Boolean} [verify] - set 'false' to set 'valid' false rather than throw
 */

/**
 * @callback Encode
 * @param {EncodeParts} parts
 * @returns {Promise<String>} - base58check WIF, Payment Address, xPrv, or xPub
 */

/**
 * @callback EncodeHex
 * @param {EncodeParts} parts
 * @returns {Promise<String>} - hex magic version bytes + key + checksum
 */

module.exports._types = true;
/**
 * @typedef BaseX
 * @prop {Create} create
 */

/**
 * @callback Create
 * @param {String} ALPHABET - typically 58 or 62 characters, but anything 2+
 * @returns {baseX}
 */

/**
 * @typedef baseX
 * @prop {Decode} decode
 * @prop {Encode} encode
 */

/**
 * @callback Decode
 * @param {String} basex
 * @returns {Uint8Array}
 */

/**
 * @callback DecodeUnsafe
 * @param {String} basex
 * @returns {Uint8Array?}
 */

/**
 * @callback Encode
 * @param {Uint8Array} buf
 * @returns {String}
 */

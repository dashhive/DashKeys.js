module.exports._types = true;
/**
 * @typedef RIPEMD160
 * @prop {Create} create
 * @prop {Hash} hash
 */

/**
 * @callback Create
 * @returns {ripemd160}
 */

/**
 * @callback Hash
 * @param {Uint8Array} bytes
 * @returns {Uint8Array}
 */

/**
 * @typedef ripemd160
 * @prop {Update} update
 * @prop {Digest} digest
 */

/**
 * @callback Digest
 * @returns {Uint8Array}
 */

/**
 * @callback Update
 * @param {Uint8Array} data
 * @returns {ripemd160}
 */

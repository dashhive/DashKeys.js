"use strict";

let Crypto = require("node:crypto");

/**
 * @param {ArrayBuffer|Buffer|Uint8Array} sourceBuf
 * @returns {Promise<Uint8Array|Buffer>}
 */
module.exports = async function (sourceBuf) {
  let sha256 = Crypto.createHash("sha256");
  //@ts-ignore
  sha256.update(sourceBuf);
  let buf = sha256.digest();

  return buf;
};

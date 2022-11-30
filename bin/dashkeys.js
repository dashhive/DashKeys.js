#!/usr/bin/env node
"use strict";

//@ts-ignore
let pkg = require("../package.json");

let Fs = require("node:fs/promises");

let DashKeys = require("../dashkeys.js");

let Base58Check = require("@dashincubator/base58check").Base58Check;
let b58c = Base58Check.create();

// let Qr = require("./qr.js");

/**
 * @typedef FsStoreConfig
 * @prop {String} dir
 * @prop {String} cachePath
 * @prop {String} payWalletsPath
 * @prop {String} preferencesPath
 * @prop {String} privateWalletsPath
 */

/**
 * @callback Subcommand
 * @param {Array<String>} args
 */

let jsonOut = "";
let unsafe = "";

async function main() {
  /* jshint maxcomplexity:1000 */
  let args = process.argv.slice(2);

  let version = removeFlag(args, ["version", "-V", "--version"]);
  if (version) {
    console.info(`dashwallet v${pkg.version}`);
    process.exit(0);
    return;
  }

  jsonOut = removeFlag(args, ["--json"]) ?? "";
  unsafe = removeFlag(args, ["--unsafe"]) ?? "";

  let gen = removeFlag(args, ["generate"]);
  if (gen) {
    await generateWif(args);
    return;
  }

  let getAddr = removeFlag(args, ["address", "pub"]);
  if (getAddr) {
    await generateAddr(args);
    return;
  }

  let decodeAddr = removeFlag(args, ["decode", "inspect"]);
  if (decodeAddr) {
    await decode(args);
    return;
  }

  let checkAddr = removeFlag(args, ["verify", "validate"]);
  if (checkAddr) {
    await verify(args);
    return;
  }

  let help = removeFlag(args, ["help", "--help", "-h"]);
  if (help) {
    usage();
    return null;
  }

  if (!args[0]) {
    usage();
    process.exit(1);
    return;
  }

  throw new Error(`'${args[0]}' is not a recognized subcommand`);
}

/**
 * @param {Array<String>} arr
 * @param {Array<String>} aliases
 * @returns {String?}
 */
function removeFlag(arr, aliases) {
  /** @type {String?} */
  let arg = null;
  aliases.forEach(function (item) {
    let index = arr.indexOf(item);
    if (-1 === index) {
      return null;
    }

    if (arg) {
      throw Error(`duplicate flag ${item}`);
    }

    arg = arr.splice(index, 1)[0];
  });

  return arg;
}

function usage() {
  console.info();
  console.info(`Usage:`);
  console.info(`    dashkeys generate                create a new WIF`);
  console.info(`    dashkeys address <./file.wif>    convert WIF to Pay Addr`);
  console.info(`    dashkeys inspect <addr-or-file>  decode base58check`);
  console.info(`    dashkeys verify <addr-or-file>   validate checksum`);
  console.info();
  console.info(`    dashkeys help     show this menu`);
  console.info(`    dashkeys version  show version`);
  console.info();
  console.info(`Global Flags:`);
  console.info(`    --json             machine-friendly json to stdout`);
  console.info(`    --unsafe           no private key mask, accept as string`);
  console.info();
}

/** @type {Subcommand} */
async function generateWif(args) {
  let wif = await DashKeys.generate();
  let addr = await DashKeys.wifToAddr(wif);

  if (jsonOut) {
    let result = {
      wif: wif,
      address: addr,
    };
    console.info(JSON.stringify(result, null, 2));
    return;
  }

  await Fs.writeFile(`./${addr}.wif`, wif, "ascii");

  console.info();
  console.info(`Saved new private key to './${addr}.wif'`);
  console.info();
}

/** @type {Subcommand} */
async function generateAddr(args) {
  let [addrOrPath] = args;

  let { addrOrWif, isString } = await readAddrOrPath(addrOrPath);
  if (isString) {
    if (!unsafe) {
      throw newExposedKeyError();
    }
  }

  if (52 !== addrOrWif.length) {
    throw newError(
      "E_BAD_INPUT",
      `a valid WIF is 52 characters in length, not '${addrOrWif.length}'`,
    );
  }

  let addr = await DashKeys.wifToAddr(addrOrWif);

  if (jsonOut) {
    let result = {
      address: addr,
    };
    console.info(JSON.stringify(result, null, 2));
    return;
  }

  console.info();
  console.info(`Pay Addr (pubKeyHash) is ${addr}`);
  console.info();
}

// TODO expose in Base58Check?
let BASE58 = `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`;
let b58re = new RegExp(`^[${BASE58}]+$`);

/** @type {Subcommand} */
async function decode(args) {
  let [addrOrPath] = args;

  let { addrOrWif, isString } = await readAddrOrPath(addrOrPath);

  let decoded = await dashDecode(addrOrWif);
  console.log(decoded);
  if (decoded.privateKey) {
    if (!unsafe) {
      decoded.privateKey = maskPrivateKey(decoded.privateKey);
    }
    let address = await DashKeys.wifToAddr(addrOrWif);
    decoded = Object.assign({ address }, decoded);
  }

  if (jsonOut) {
    console.info(JSON.stringify(decoded, null, 2));
    return;
  }

  let wout = function () {
    //@ts-ignore
    console.info.apply(console, arguments);
  };

  if (!decoded.valid) {
    wout = function () {
      //@ts-ignore
      console.error.apply(console, arguments);
    };
  }

  wout();
  if (isString) {
    if (decoded.privateKey) {
      if (!unsafe) {
        throw newExposedKeyError();
      }
      wout(`Decoded Private Key string:`);
    } else {
      wout(`Decoded Pay Addr string:`);
    }
  } else {
    if (decoded.privateKey) {
      wout(`Decoded Private Key file '${addrOrPath}':`);
    } else {
      wout(`Decoded Pay Addr file '${addrOrPath}':`);
    }
  }

  wout();
  wout(`    Valid:       ${decoded.valid}`);
  wout(`    Version:     ${decoded.version}`);
  if (decoded.pubKeyHash) {
    wout(`    PubKey Hash: ${decoded.pubKeyHash}`);
  }
  if (decoded.privateKey) {
    //@ts-ignore - TODO make new definition for CLI
    wout(`    Pay Addr:    ${decoded.address}`);
    wout(`    Private Key: ${decoded.privateKey}`);
  }
  wout(`    Check:       ${decoded.check}`);
  wout();
}

/** @type {Subcommand} */
async function verify(args) {
  let [addrOrPath] = args;

  let { addrOrWif, isString } = await readAddrOrPath(addrOrPath);

  let decoded = await dashDecode(addrOrWif);
  let status = "invalid";
  if (decoded.valid) {
    status = "valid";
  }

  if (jsonOut) {
    let result = { valid: decoded.valid, isPrivate: !!decoded.privateKey };
    console.info(JSON.stringify(result, null, 2));
    return;
  }

  let wout = function () {
    //@ts-ignore
    console.info.apply(console, arguments);
  };

  if (!decoded.valid) {
    wout = function () {
      //@ts-ignore
      console.error.apply(console, arguments);
    };
  }

  if (!isString) {
    wout();
    if (decoded.privateKey) {
      wout(`Private Key file ${status}`);
    } else {
      wout(`Pay Addr file ${status}`);
    }
    wout();
    return;
  }

  if (!decoded.privateKey) {
    wout();
    wout(`Pay Addr string is ${status}`);
    wout();
    return;
  }

  if (!unsafe) {
    throw newExposedKeyError();
  }

  wout();
  wout(`Private Key string is ${status}`);
  wout();
}

/**
 * @param {String} addrOrWif - pay addr or private key wif
 * @param {Object} opts
 * @param {Boolean} opts.verify - 'false' to skip verification (default: 'true')
 */
async function dashDecode(addrOrWif) {
  let parts = await b58c.decode(addrOrWif);
  let check = await b58c.checksum(parts);
  let valid = parts.check === check;

  return Object.assign({ valid }, parts);
}

/**
 * @param {String} addrOrPath
 */
async function readAddrOrPath(addrOrPath) {
  let isString = false;
  let txt = await Fs.readFile(addrOrPath, "ascii").catch(function (err) {
    if ("ENOENT" !== err.code) {
      throw err;
    }

    isString = true;
    return addrOrPath;
  });
  let addrOrWif = txt.trim();

  if (!b58re.test(txt)) {
    throw newError(
      "E_BAD_INPUT",
      `'${addrOrWif}' is not a valid WIF or Pay Addr`,
    );
  }

  return {
    isString,
    addrOrWif,
  };
}

/**
 * @param {String} privateKey - hex private key
 */
function maskPrivateKey(privateKey) {
  let maskLen = 66 + -2 + -2;
  let mask = "*".repeat(maskLen);
  let first2 = privateKey.slice(0, 2);
  let last2 = privateKey.slice(-2);

  let privateKeyMask = `${first2}${mask}${last2}`;
  return privateKeyMask;
}

/**
 * A `detail`ed, `code`d error message. Throw it yourself.
 * @param {String} code - all uppercase with underscores, for machines (ex: E_BAD_INPUT)
 * @param {String} message - all lowercase, no punctuation, for devs (ex: "failed to parse '${x}'")
 * @param {any} [details] - extra details for machine or devs
 */
function newError(code, message, details) {
  let err = new Error(message);
  //@ts-ignore
  err.code = code;
  //@ts-ignore
  err.details = details;
  return err;
}

function newExposedKeyError() {
  let histfile = "your Shell history";
  if (process.env.HISTFILE) {
    histfile = process.env.HISTFILE;
  }
  return newError(
    "E_EXPOSED_KEY",
    `You've exposed your private key, which may have been written to ${histfile}.`,
  );
}

main()
  .then(async function () {
    process.exit(0);
  })
  .catch(function (err) {
    if ("E_BAD_INPUT" === err.code) {
      console.error("Error:");
      console.error();
      console.error(err.message);
      console.error();

      process.exit(1);
      return;
    }

    if ("E_EXPOSED_KEY" === err.code) {
      console.error("Security Error:");
      console.error();
      console.error(err.message);
      console.error(`Use --unsafe to run anyway.`);
      console.error();

      process.exit(1);
      return;
    }

    console.error("Fail:");
    console.error(err.stack || err);

    process.exit(1);
  });

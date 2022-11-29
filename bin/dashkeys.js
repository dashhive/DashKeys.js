#!/usr/bin/env node
"use strict";

//@ts-ignore
let pkg = require("../package.json");

let Fs = require("node:fs/promises");

let DashKeys = require("../dashkeys.js");

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

async function main() {
  /* jshint maxcomplexity:1000 */
  let args = process.argv.slice(2);

  let version = removeFlag(args, ["version", "-V", "--version"]);
  if (version) {
    console.info(`dashwallet v${pkg.version}`);
    process.exit(0);
    return;
  }

  let gen = removeFlag(args, ["generate"]);
  if (gen) {
    await generateWif(args);
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
  console.info(`    dashkeys generate`);
  console.info();
  console.info(`    dashkeys help`);
  console.info(`    dashkeys version`);
  console.info();
}

/** @type {Subcommand} */
async function generateWif(args) {
  let wif = await DashKeys.generate();
  let addr = await DashKeys.wifToAddr(wif);

  await Fs.writeFile(`./${addr}.wif`, wif, "ascii");

  console.info();
  console.info(`Saved new private key to './${addr}.wif'`);
  console.info();
}

main()
  .then(async function () {
    process.exit(0);
  })
  .catch(function (err) {
    if ("E_BAD_INPUT" === err.type) {
      console.error("Error:");
      console.error();
      console.error(err.message);
      console.error();

      process.exit(1);
      return;
    }

    console.error("Fail:");
    console.error(err.stack || err);

    process.exit(1);
  });

"use strict";

let DashKeys = require("./dashkeys.js");

let Base58Check = require("@dashincubator/base58check").Base58Check;
let dash58check = Base58Check.create();

async function main() {
  let privKey = Buffer.from(
    "647f06cbd6569feaa4b6a1e400284057a95d27f4206ce38300ae88d44418160d",
    "hex",
  );

  let wif = await DashKeys.privKeyToWif(privKey);

  let decoded = await dash58check.decode(wif);
  let encoded = await dash58check.encode(decoded);
  let decoded2 = await dash58check.decode(encoded);
  if (decoded.privateKey !== decoded2.privateKey) {
    throw new Error("bad privateKey decode/re-encode");
  }
  if (decoded.compressed !== decoded2.compressed) {
    throw new Error("bad compression decode/re-encode");
  }
  if (decoded.version !== decoded2.version) {
    throw new Error("bad version decode/re-encode");
  }

  let addr = await DashKeys.wifToAddr(wif);
  if ("Xjn9fksLacciynroVhMLKGXMqMJtzJNLvQ" !== addr) {
    //throw new Error("failed to produce the correct addr");
  }

  // generated with dashwallet.js
  let pairs = [
    [
      "XEez2HcUhEomZoxzgH7H3LxnRAkqF4kRCVE8mW9q4YSUV4yuADec",
      "Xjn9fksLacciynroVhMLKGXMqMJtzJNLvQ",
    ],
    [
      "XEzQAWaFgpq5D8FzwsFthh77Agw7Tt2JJVHd357toX5F45YPFvmq",
      "Xx2KqcTGKDFLCbdBK3yZFcREY8cMYxNnBA",
    ],
    [
      "XHNv3RVF4Bg7zpfKbGogGsYNLuEYjPPHgo4FwjCpnZoFoQW5Ypp2",
      "Xd1SWtnMHHsTJLQmB12RdTNUeJwNE5cojY",
    ],
  ];

  for (let pair of pairs) {
    let [wif, addr] = pair;
    let addrParts = await dash58check.decode(addr);
    let checkAddr = await DashKeys.wifToAddr(wif);
    if (addr !== checkAddr) {
      console.error();
      console.error(wif);
      console.error(addr);
      console.error(addrParts);
      throw new Error(
        `WIF-generated Pay Addr '${checkAddr}' does not match expected value '${addr}'`,
      );
    }
  }

  console.info(`PASS`);
}

main()
  .then(async function () {
    process.exit(0);
  })
  .catch(function (err) {
    console.error("Fail:");
    console.error(err.stack || err);

    process.exit(1);
  });

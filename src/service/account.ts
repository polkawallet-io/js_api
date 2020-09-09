import {
  keyExtractSuri,
  mnemonicGenerate,
  cryptoWaitReady,
} from "@polkadot/util-crypto";
import { hexToU8a, u8aToHex, hexToString } from "@polkadot/util";
// @ts-ignore
import { ss58Decode } from "oo7-substrate/src/ss58";
import { polkadotIcon } from "@polkadot/ui-shared";
import BN from "bn.js";
import {
  parseQrCode,
  getSigner,
  makeTx,
  getSubmittable,
} from "../utils/QrSigner";
import gov from "./gov";

import { Keyring } from "@polkadot/keyring";
import { KeypairType } from "@polkadot/util-crypto/types";
import { KeyringPair, KeyringPair$Json } from "@polkadot/keyring/types";
import { ApiPromise, SubmittableResult } from "@polkadot/api";
import { SubmittableExtrinsic } from "@polkadot/api/types";
import { ITuple } from "@polkadot/types/types";
import { DispatchError } from "@polkadot/types/interfaces";
let keyring = new Keyring({ ss58Format: 0, type: "sr25519" });

/**
 * Generate a set of new mnemonic.
 */
async function gen() {
  const mnemonic = mnemonicGenerate();
  return {
    mnemonic,
  };
}

/**
 * Get svg icons of addresses.
 */
async function genIcons(addresses: string[]) {
  return addresses.map((i) => {
    const circles = polkadotIcon(i, { isAlternative: false })
      .map(
        ({ cx, cy, fill, r }) =>
          `<circle cx='${cx}' cy='${cy}' fill='${fill}' r='${r}' />`
      )
      .join("");
    return [
      i,
      `<svg viewBox='0 0 64 64' xmlns='http://www.w3.org/2000/svg'>${circles}</svg>`,
    ];
  });
}

/**
 * Get svg icons of pubKeys.
 */
async function genPubKeyIcons(pubKeys: string[]) {
  const icons = await genIcons(
    pubKeys.map((key) => keyring.encodeAddress(hexToU8a(key), 2))
  );
  return icons.map((i, index) => {
    i[0] = pubKeys[index];
    return i;
  });
}

/**
 * Import keyPair from mnemonic, rawSeed or keystore.
 */
function recover(
  keyType: string,
  cryptoType: KeypairType,
  key: string,
  password: string
) {
  return new Promise((resolve, reject) => {
    let keyPair: KeyringPair;
    let mnemonic = "";
    let rawSeed = "";
    try {
      switch (keyType) {
        case "mnemonic":
          keyPair = keyring.addFromMnemonic(key, {}, cryptoType);
          mnemonic = key;
          break;
        case "rawSeed":
          keyPair = keyring.addFromUri(key, {}, cryptoType);
          rawSeed = key;
          break;
        case "keystore":
          const keystore = JSON.parse(key);
          keyPair = keyring.addFromJson(keystore);
          try {
            keyPair.decodePkcs8(password);
          } catch (err) {
            resolve(null);
          }
          resolve({
            pubKey: u8aToHex(keyPair.publicKey),
            ...keyPair.toJson(password),
          });
          break;
      }
    } catch (err) {
      resolve({ error: err.message });
    }
    if (keyPair.address) {
      const json = keyPair.toJson(password);
      keyPair.lock();
      // try add to keyring again to avoid no encrypted data bug
      keyring.addFromJson(json);
      resolve({
        pubKey: u8aToHex(keyPair.publicKey),
        mnemonic,
        rawSeed,
        ...json,
      });
    } else {
      resolve(null);
    }
  });
}

/**
 * Add user's accounts to keyring incedence,
 * so user can use them to sign txs with password.
 * We use a list of ss58Formats to encode the accounts
 * into different address formats for different networks.
 */
async function initKeys(accounts: KeyringPair$Json[], ss58Formats: number[]) {
  await cryptoWaitReady();
  const res = {};
  ss58Formats.forEach((ss58) => {
    (<any>res)[ss58] = {};
  });

  accounts.forEach((i) => {
    // import account to keyring
    const keyPair = keyring.addFromJson(i);
    // then encode address into different ss58 formats
    ss58Formats.forEach((ss58) => {
      const pubKey = u8aToHex(keyPair.publicKey);
      (<any>res)[ss58][pubKey] = keyring.encodeAddress(keyPair.publicKey, ss58);
    });
  });
  return res;
}

/**
 * decode address to it's publicKey
 */
async function decodeAddress(addresses: string[]) {
  await cryptoWaitReady();
  try {
    const res = {};
    addresses.forEach((i) => {
      const pubKey = u8aToHex(keyring.decodeAddress(i));
      (<any>res)[pubKey] = i;
    });
    return res;
  } catch (err) {
    (<any>window).send("log", { error: err.message });
    return null;
  }
}

/**
 * encode pubKey to addresses with different prefixes
 */
async function encodeAddress(pubKeys: string[], ss58Formats: number[]) {
  await cryptoWaitReady();
  const res = {};
  ss58Formats.forEach((ss58) => {
    (<any>res)[ss58] = {};
    pubKeys.forEach((i) => {
      (<any>res)[ss58][i] = keyring.encodeAddress(hexToU8a(i), ss58);
    });
  });
  return res;
}

/**
 * query account address with account index
 */
async function queryAddressWithAccountIndex(
  api: ApiPromise,
  accIndex: string,
  ss58: number
) {
  const num = ss58Decode(accIndex, ss58).toJSON();
  const res = await api.query.indices.accounts(num.data);
  return res;
}

/**
 * get staking stash/controller relationship of accounts
 */
async function queryAccountsBonded(api: ApiPromise, pubKeys: string[]) {
  return Promise.all(
    pubKeys
      .map((key) => keyring.encodeAddress(hexToU8a(key), 2))
      .map((i) =>
        Promise.all([api.query.staking.bonded(i), api.query.staking.ledger(i)])
      )
  ).then((ls) =>
    ls.map((i, index) => [
      pubKeys[index],
      i[0],
      i[1].toHuman() ? i[1].toHuman()["stash"] : null,
    ])
  );
}

/**
 * get network base token balance of an address
 */
async function getBalance(api: ApiPromise, address: string) {
  const all = await api.derive.balances.all(address);
  const lockedBreakdown = all.lockedBreakdown.map((i) => {
    return {
      ...i,
      use: hexToString(i.id.toHex()),
    };
  });
  return {
    ...all,
    lockedBreakdown,
  };
}

/**
 * get humen info of addresses
 */
async function getAccountIndex(api: ApiPromise, addresses: string[]) {
  return api.derive.accounts.indexes().then((res) => {
    return Promise.all(addresses.map((i) => api.derive.accounts.info(i)));
  });
}

/**
 * estimate gas fee of an extrinsic
 */
async function txFeeEstimate(api: ApiPromise, txInfo: any, paramList: any[]) {
  let tx: SubmittableExtrinsic<"promise">;
  // wrap tx with council.propose for treasury propose
  if (txInfo.txName == "treasury.approveProposal") {
    tx = await gov.makeTreasuryProposalSubmission(api, paramList[0], false);
  } else if (txInfo.txName == "treasury.rejectProposal") {
    tx = await gov.makeTreasuryProposalSubmission(api, paramList[0], true);
  } else {
    tx = api.tx[txInfo.module][txInfo.call](...paramList);
  }

  let sender = txInfo.address;
  if (txInfo.proxy) {
    // wrap tx with recovery.asRecovered for proxy tx
    tx = api.tx.recovery.asRecovered(txInfo.address, tx);
    sender = keyring.encodeAddress(hexToU8a(txInfo.proxy));
  }
  const dispatchInfo = await tx.paymentInfo(sender);
  return dispatchInfo;
}

function _extractEvents(api: ApiPromise, result: SubmittableResult) {
  if (!result || !result.events) {
    return {};
  }

  let success = false;
  let error: DispatchError["type"] = "";
  result.events
    .filter((event) => !!event.event)
    .map(({ event: { data, method, section } }) => {
      if (section === "system" && method === "ExtrinsicFailed") {
        const [dispatchError] = (data as unknown) as ITuple<[DispatchError]>;
        let message = dispatchError.type;

        if (dispatchError.isModule) {
          try {
            const mod = dispatchError.asModule;
            const err = api.registry.findMetaError(
              new Uint8Array([mod.index.toNumber(), mod.error.toNumber()])
            );

            message = `${err.section}.${err.name}`;
          } catch (error) {
            // swallow error
          }
        }
        (<any>window).send("txUpdateEvent", {
          title: `${section}.${method}`,
          message,
        });
        error = message;
      } else {
        (<any>window).send("txUpdateEvent", {
          title: `${section}.${method}`,
          message: "ok",
        });
        if (section == "system" && method == "ExtrinsicSuccess") {
          success = true;
        }
      }
    });
  return { success, error };
}

/**
 * sign and send extrinsic to network and wait for result.
 */
function sendTx(api: ApiPromise, txInfo: any, paramList: any[]) {
  return new Promise(async (resolve) => {
    let tx: SubmittableExtrinsic<"promise">;
    // wrap tx with council.propose for treasury propose
    if (txInfo.txName == "treasury.approveProposal") {
      tx = await gov.makeTreasuryProposalSubmission(api, paramList[0], false);
    } else if (txInfo.txName == "treasury.rejectProposal") {
      tx = await gov.makeTreasuryProposalSubmission(api, paramList[0], true);
    } else {
      tx = api.tx[txInfo.module][txInfo.call](...paramList);
    }
    let unsub = () => {};
    const onStatusChange = (result: SubmittableResult) => {
      if (result.status.isInBlock || result.status.isFinalized) {
        const { success, error } = _extractEvents(api, result);
        if (success) {
          resolve({ hash: tx.hash.toString() });
        }
        if (error) {
          resolve({ error });
        }
        unsub();
      } else {
        (<any>window).send("txStatusChange", result.status.type);
      }
    };
    if (txInfo.isUnsigned) {
      tx.send(onStatusChange)
        .then((res) => {
          unsub = res;
        })
        .catch((err) => {
          resolve({ error: err.message });
        });
      return;
    }

    let keyPair: KeyringPair;
    if (!txInfo.proxy) {
      keyPair = keyring.getPair(hexToU8a(txInfo.pubKey));
    } else {
      // wrap tx with recovery.asRecovered for proxy tx
      tx = api.tx.recovery.asRecovered(txInfo.address, tx);
      keyPair = keyring.getPair(hexToU8a(txInfo.proxy));
    }

    try {
      keyPair.decodePkcs8(txInfo.password);
    } catch (err) {
      resolve({ error: "password check failed" });
    }
    tx.signAndSend(keyPair, { tip: new BN(txInfo.tip, 10) }, onStatusChange)
      .then((res) => {
        unsub = res;
      })
      .catch((err) => {
        resolve({ error: err.message });
      });
  });
}

/**
 * check password of an account.
 */
function checkPassword(pubKey: string, pass: string) {
  return new Promise((resolve) => {
    const keyPair = keyring.getPair(hexToU8a(pubKey));
    try {
      if (!keyPair.isLocked) {
        keyPair.lock();
      }
      keyPair.decodePkcs8(pass);
    } catch (err) {
      resolve(null);
    }
    resolve({ success: true });
  });
}

/**
 * change password of an account.
 */
function changePassword(pubKey: string, passOld: string, passNew: string) {
  return new Promise((resolve) => {
    const u8aKey = hexToU8a(pubKey);
    const keyPair = keyring.getPair(u8aKey);
    try {
      if (!keyPair.isLocked) {
        keyPair.lock();
      }
      keyPair.decodePkcs8(passOld);
    } catch (err) {
      resolve(null);
      return;
    }
    const json = keyPair.toJson(passNew);
    keyring.removePair(u8aKey);
    keyring.addFromJson(json);
    resolve({
      pubKey: u8aToHex(keyPair.publicKey),
      ...json,
    });
  });
}

/**
 * check if user input DerivePath valid.
 */
async function checkDerivePath(
  seed: string,
  derivePath: string,
  pairType: KeypairType
) {
  try {
    const { path } = keyExtractSuri(`${seed}${derivePath}`);
    // we don't allow soft for ed25519
    if (pairType === "ed25519" && path.some(({ isSoft }) => isSoft)) {
      return "Soft derivation paths are not allowed on ed25519";
    }
  } catch (error) {
    return error.message;
  }
  return null;
}

/**
 * sign tx with QR
 */
async function signAsync(api: ApiPromise, password: string) {
  return new Promise((resolve) => {
    const { unsignedData } = getSigner();
    const keyPair = keyring.getPair(unsignedData.data.account);
    try {
      if (!keyPair.isLocked) {
        keyPair.lock();
      }
      keyPair.decodePkcs8(password);
      const payload = api.registry.createType(
        "ExtrinsicPayload",
        unsignedData.data.data,
        { version: api.extrinsicVersion }
      );
      const signed = payload.sign(keyPair);
      resolve(signed);
    } catch (err) {
      resolve({ error: err.message });
    }
  });
}

/**
 * send tx with signed data from QR
 */
function addSignatureAndSend(api: ApiPromise, address: string, signed: string) {
  return new Promise((resolve) => {
    const { tx, payload } = getSubmittable();
    if (!!tx.addSignature) {
      tx.addSignature(address, `0x${signed}`, payload);

      let unsub = () => {};
      const onStatusChange = (result: SubmittableResult) => {
        if (result.status.isInBlock || result.status.isFinalized) {
          const { success, error } = _extractEvents(api, result);
          if (success) {
            resolve({ hash: tx.hash.toString() });
          }
          if (error) {
            resolve({ error });
          }
          unsub();
        } else {
          (<any>window).send("txStatusChange", result.status.type);
        }
      };

      tx.send(onStatusChange)
        .then((res) => {
          unsub = res;
        })
        .catch((err) => {
          resolve({ error: err.message });
        });
    } else {
      resolve({ error: "invalid tx" });
    }
  });
}

/**
 * sign tx from dapp as extension
 */
async function signTxAsExtension(api: ApiPromise, password: string, json: any) {
  return new Promise((resolve) => {
    const keyPair = keyring.getPair(json["address"]);
    try {
      if (!keyPair.isLocked) {
        keyPair.lock();
      }
      keyPair.decodePkcs8(password);
      api.registry.setSignedExtensions(json["signedExtensions"]);
      const payload = api.registry.createType("ExtrinsicPayload", json, {
        version: json["version"],
      });
      const signed = payload.sign(keyPair);
      resolve(signed);
    } catch (err) {
      resolve({ error: err.message });
    }
  });
}

/**
 * sign bytes from dapp as extension
 */
async function signBytesAsExtension(password: string, json: any) {
  return new Promise((resolve) => {
    const keyPair = keyring.getPair(json["address"]);
    try {
      if (!keyPair.isLocked) {
        keyPair.lock();
      }
      keyPair.decodePkcs8(password);
      resolve({
        signature: u8aToHex(keyPair.sign(hexToU8a(json["data"]))),
      });
    } catch (err) {
      resolve({ error: err.message });
    }
  });
}

export default {
  initKeys,
  encodeAddress,
  decodeAddress,
  queryAddressWithAccountIndex,
  gen,
  genIcons,
  genPubKeyIcons,
  recover,
  queryAccountsBonded,
  getBalance,
  getAccountIndex,
  txFeeEstimate,
  sendTx,
  checkPassword,
  changePassword,
  checkDerivePath,
  parseQrCode,
  signAsync,
  makeTx,
  addSignatureAndSend,
  signTxAsExtension,
  signBytesAsExtension,
};

import {
  keyExtractSuri,
  mnemonicGenerate,
  cryptoWaitReady,
} from "@polkadot/util-crypto";
import { hexToU8a, u8aToHex, hexToString } from "@polkadot/util";
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
let keyring = new Keyring({ ss58Format: 0, type: "sr25519" });

/**
 * Generate a set of new mnemonic.
 *
 * @returns {Map} mnemonic
 */
async function gen() {
  const mnemonic = mnemonicGenerate();
  return {
    mnemonic,
  };
}

/**
 * Get svg icons of addresses.
 *
 * @param {List<String>} addresses
 * @returns {List} icons
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
 *
 * @param {List<String>} pubKeys
 * @returns {List} icons
 */
async function genPubKeyIcons(pubKeys) {
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
 *
 * @param {String} keyType
 * @param {String} cryptoType
 * @param {String} key
 * @param {String} password
 * @returns {Map} JSON data of keystore
 */
function recover(keyType, cryptoType, key, password) {
  return new Promise((resolve, reject) => {
    let keyPair = {};
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
 *
 * @param {List<Keystore>} accounts
 * @param {List<int>} ss58Formats
 * @returns {Map<String, String>} pubKeyAddressMap
 */
async function initKeys(accounts, ss58Formats) {
  await cryptoWaitReady();
  const res = {};
  ss58Formats.forEach((ss58) => {
    res[ss58] = {};
  });

  accounts.forEach((i) => {
    // import account to keyring
    const keyPair = keyring.addFromJson(i);
    // then encode address into different ss58 formats
    ss58Formats.forEach((ss58) => {
      const pubKey = u8aToHex(keyPair.publicKey);
      res[ss58][pubKey] = keyring.encodeAddress(keyPair.publicKey, ss58);
    });
  });
  return res;
}

/**
 * decode address to it's publicKey
 *
 * @param {List<String>} addresses
 * @returns {Map<String, String>} pubKeyAddressMap
 */
async function decodeAddress(addresses) {
  await cryptoWaitReady();
  try {
    const res = {};
    addresses.forEach((i) => {
      const pubKey = u8aToHex(keyring.decodeAddress(i));
      res[pubKey] = i;
    });
    return res;
  } catch (err) {
    send("log", { error: err.message });
    return null;
  }
}

/**
 * encode pubKey to addresses with different prefixes
 *
 * @param {List<String>} pubKeys
 * @param {List<int>} ss58Formats
 * @returns {Map<String, String>} pubKeyAddressMap
 */
async function encodeAddress(pubKeys, ss58Formats) {
  await cryptoWaitReady();
  const res = {};
  ss58Formats.forEach((ss58) => {
    res[ss58] = {};
    pubKeys.forEach((i) => {
      res[ss58][i] = keyring.encodeAddress(hexToU8a(i), ss58);
    });
  });
  return res;
}

/**
 * query account address with account index
 *
 * @param {String} accountIndex
 * @param {int} ss58Format
 * @returns {List} indicesInfo
 */
async function queryAddressWithAccountIndex(accIndex, ss58) {
  const num = ss58Decode(accIndex, ss58).toJSON();
  const res = await api.query.indices.accounts(num.data);
  return res;
}

/**
 * get staking stash/controller relationship of accounts
 *
 * @param {List<String>} pubKeys
 * @returns {List<String>} [][pubKey, controller, stash]
 */
async function queryAccountsBonded(pubKeys) {
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
      i[1].toHuman() ? i[1].toHuman().stash : null,
    ])
  );
}

/**
 * get network base token balance of an address
 *
 * @param {String} address
 * @returns {Map} balances
 */
async function getBalance(address) {
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
 *
 * @param {List<String>} addresses
 * @returns {List<Map>} AccountIndex
 */
function getAccountIndex(addresses) {
  return api.derive.accounts.indexes().then((res) => {
    return Promise.all(addresses.map((i) => api.derive.accounts.info(i)));
  });
}

/**
 * estimate gas fee of an extrinsic
 *
 * @param {Map} txInfo
 * @param {List} paramList
 * @returns {Map} dispatchInfo
 */
async function txFeeEstimate(txInfo, paramList) {
  let tx;
  // wrap tx with council.propose for treasury propose
  if (txInfo.txName == "treasury.approveProposal") {
    tx = await gov.makeTreasuryProposalSubmission(paramList[0], false);
  } else if (txInfo.txName == "treasury.rejectProposal") {
    tx = await gov.makeTreasuryProposalSubmission(paramList[0], true);
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

function _extractEvents(api, result) {
  if (!result || !result.events) {
    return;
  }

  let success = false;
  let error;
  result.events
    .filter((event) => !!event.event)
    .map(({ event: { data, method, section } }) => {
      if (section === "system" && method === "ExtrinsicFailed") {
        const [dispatchError] = data;
        let message = dispatchError.type;

        if (dispatchError.isModule) {
          try {
            const mod = dispatchError.asModule;
            const error = api.registry.findMetaError(
              new Uint8Array([mod.index.toNumber(), mod.error.toNumber()])
            );

            message = `${error.section}.${error.name}`;
          } catch (error) {
            // swallow error
          }
        }
        window.send("txUpdateEvent", {
          title: `${section}.${method}`,
          message,
        });
        error = message;
      } else {
        window.send("txUpdateEvent", {
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
 *
 * @param {Map} txInfo
 * @param {List} paramList
 * @returns {Map} txResult
 */
function sendTx(txInfo, paramList) {
  return new Promise(async (resolve) => {
    let tx;
    // wrap tx with council.propose for treasury propose
    if (txInfo.txName == "treasury.approveProposal") {
      tx = await gov.makeTreasuryProposalSubmission(paramList[0], false);
    } else if (txInfo.txName == "treasury.rejectProposal") {
      tx = await gov.makeTreasuryProposalSubmission(paramList[0], true);
    } else {
      tx = api.tx[txInfo.module][txInfo.call](...paramList);
    }
    let unsub = () => {};
    const onStatusChange = (result) => {
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
        window.send("txStatusChange", result.status.type);
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

    let keyPair;
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
 *
 * @param {String} pubKey
 * @param {String} pass
 * @returns {Map} check result
 */
function checkPassword(pubKey, pass) {
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
 *
 * @param {String} pubKey
 * @param {String} passOld
 * @param {String} passNew
 * @returns {Map} check result
 */
function changePassword(pubKey, passOld, passNew) {
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
 *
 * @param {String} seed
 * @param {String} derivePath
 * @param {String} pairType
 * @returns {String} error msg
 */
async function checkDerivePath(seed, derivePath, pairType) {
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
 *
 * @param {String} password
 * @returns {Map} signature
 */
async function signAsync(password) {
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
 *
 * @param {String} password
 * @param {String} signed
 * @returns {Map} tx result
 */
function addSignatureAndSend(address, signed) {
  return new Promise((resolve) => {
    const { tx, payload } = getSubmittable();
    if (tx.addSignature) {
      tx.addSignature(address, `0x${signed}`, payload);

      let unsub = () => {};
      const onStatusChange = (result) => {
        if (result.status.isInBlock || result.status.isFinalized) {
          const { success, error } = _extractEvents(api, result);
          if (success) {
            resolve({ hash: tx.hash.hash.toHuman() });
          }
          if (error) {
            resolve({ error });
          }
          unsub();
        } else {
          window.send("txStatusChange", result.status.type);
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
 *
 * @param {String} password
 * @param {Map} json
 * @returns {Map} signature
 */
async function signTxAsExtension(password, json) {
  return new Promise((resolve) => {
    const keyPair = keyring.getPair(json.address);
    try {
      if (!keyPair.isLocked) {
        keyPair.lock();
      }
      keyPair.decodePkcs8(password);
      api.registry.setSignedExtensions(json.signedExtensions);
      const payload = api.registry.createType("ExtrinsicPayload", json, {
        version: json.version,
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
 *
 * @param {String} password
 * @param {Map} json
 * @returns {Map} signature
 */
async function signBytesAsExtension(password, json) {
  return new Promise((resolve) => {
    const keyPair = keyring.getPair(json.address);
    try {
      if (!keyPair.isLocked) {
        keyPair.lock();
      }
      keyPair.decodePkcs8(password);
      resolve({
        signature: u8aToHex(keyPair.sign(hexToU8a(json.data))),
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

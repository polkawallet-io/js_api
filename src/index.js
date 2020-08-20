import "@babel/polyfill";
import { WsProvider, ApiPromise } from "@polkadot/api";
import account from "./service/account";
import staking from "./service/staking";
import gov from "./service/gov";
import { genLinks } from "./utils/config/config";

// send message to JSChannel: PolkaWallet
function send(path, data) {
  if (window.location.href === "about:blank") {
    PolkaWallet.postMessage(JSON.stringify({ path, data }));
  } else {
    console.log(path, data);
  }
}
send("log", "main js loaded");
window.send = send;

/**
 * connect to a specific node.
 *
 * @param {String} nodeEndpoint
 */
async function connect(endpoint) {
  return new Promise(async (resolve, reject) => {
    const wsProvider = new WsProvider(endpoint);
    try {
      const res = await ApiPromise.create({
        provider: wsProvider,
      });
      window.api = res;
      send("log", `${endpoint} wss connected success`);
      resolve(endpoint);
    } catch (err) {
      send("log", `connect ${endpoint} failed`);
      wsProvider.disconnect();
      resolve(null);
    }
  });
}

/**
 * connect to a list of nodes,
 * use first connection as global api instance
 * and ignore other connections.
 *
 * @param {List<String>} nodeList
 */
async function connectAll(nodes) {
  let failCount = 0;
  return new Promise((resolve, reject) => {
    nodes.forEach(async (endpoint) => {
      const wsProvider = new WsProvider(endpoint);
      try {
        const res = await ApiPromise.create({
          provider: wsProvider,
        });
        if (!window.api) {
          window.api = res;
          send("log", `${endpoint} wss connected success`);
          resolve(endpoint);
        } else {
          send("log", `${endpoint} wss connected and ignored`);
          res.disconnect();
        }
      } catch (err) {
        send("log", `connect ${endpoint} failed`);
        wsProvider.disconnect();
        failCount += 1;
        if (failCount >= nodes.length) {
          resolve(null);
        }
      }
    });
  });
}

const test = async (address) => {
  // const props = await api.rpc.system.properties();
  // send("log", props);
};

/**
 * get consts of network.
 *
 * @returns {Map} consts
 */
async function getNetworkConst() {
  return api.consts;
}

/**
 * subscribe messages of network state.
 *
 * @param {String} section
 * @param {String} method
 * @param {List<String>} params
 * @param {String} msgChannel
 */
async function subscribeMessage(section, method, params, msgChannel) {
  return api.derive[section][method](...params, (res) => {
    send(msgChannel, res);
  }).then((unsub) => {
    const unsubFuncName = `unsub${msgChannel}`;
    window[unsubFuncName] = unsub;
    return {};
  });
}

const settings = {
  test,
  connect,
  connectAll,
  getNetworkConst,
  subscribeMessage,
  // generate external links to polkascan/subscan/polkassembly...
  genLinks,
};

window.settings = settings;
window.account = account;
window.staking = staking;
window.gov = gov;

export default settings;

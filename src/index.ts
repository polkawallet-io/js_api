import "@babel/polyfill";
import { WsProvider, ApiPromise } from "@polkadot/api";
import {
  subscribeMessage,
  getNetworkConst,
  getNetworkProperties,
} from "./service/setting";
import keyring from "./service/keyring";
import account from "./service/account";
import staking from "./service/staking";
import gov from "./service/gov";
import { genLinks } from "./utils/config/config";

// send message to JSChannel: PolkaWallet
function send(path: string, data: any) {
  if (window.location.href === "about:blank") {
    PolkaWallet.postMessage(JSON.stringify({ path, data }));
  } else {
    console.log(path, data);
  }
}
send("log", "main js loaded");
(<any>window).send = send;

/**
 * connect to a specific node.
 *
 * @param {string} nodeEndpoint
 */
async function connect(endpoint: string) {
  return new Promise(async (resolve, reject) => {
    const wsProvider = new WsProvider(endpoint);
    try {
      const res = await ApiPromise.create({
        provider: wsProvider,
      });
      (<any>window).api = res;
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
async function connectAll(nodes: string[]) {
  let failCount = 0;
  return new Promise((resolve, reject) => {
    nodes.forEach(async (endpoint) => {
      const wsProvider = new WsProvider(endpoint);
      try {
        const res = await ApiPromise.create({
          provider: wsProvider,
        });
        if (!(<any>window).api) {
          (<any>window).api = res;
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

const test = async () => {
  // const props = await api.rpc.system.properties();
  // send("log", props);
};

const settings = {
  test,
  connect,
  connectAll,
  subscribeMessage,
  getNetworkConst,
  getNetworkProperties,
  // generate external links to polkascan/subscan/polkassembly...
  genLinks,
};

(<any>window).settings = settings;
(<any>window).keyring = keyring;
(<any>window).account = account;
(<any>window).staking = staking;
(<any>window).gov = gov;

export default settings;

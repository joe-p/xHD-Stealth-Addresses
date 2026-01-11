import {
  BIP32DerivationType,
  fromSeed,
  KeyContext,
  XHDWalletAPI,
} from "@algorandfoundation/xhd-wallet-api";
import { ed25519 } from "@noble/curves/ed25519.js";
import { generateStealthKeyAndNote, parseDiscoveryNote } from "../src/index";
import { Bench } from "tinybench";

const xhd = new XHDWalletAPI();

const SEED = new Uint8Array(32);
crypto.getRandomValues(SEED);

const ROOT_KEY = fromSeed(SEED);

async function setupBenchmark() {
  const sender = ed25519.keygen().publicKey;

  const receiverPublic = await xhd.keyGen(
    ROOT_KEY,
    KeyContext.Address,
    0,
    0,
    BIP32DerivationType.Peikert,
  );

  const firstValid = 100n;
  const lastValid = 200n;
  const lease = new Uint8Array(32);
  crypto.getRandomValues(lease);

  const result = await generateStealthKeyAndNote({
    sender,
    receiver: receiverPublic,
    firstValid,
    lastValid,
    lease,
  });

  return {
    note: result.note,
    sender,
    firstValid,
    lastValid,
    lease,
    receiverPublic,
  };
}

(async () => {
  const bench = new Bench({ iterations: 1_000 });

  const data = await setupBenchmark();

  bench.add("parseDiscoveryNote", async () => {
    await parseDiscoveryNote({
      note: data.note,
      rootKey: ROOT_KEY,
      account: 0,
      index: 0,
      sender: data.sender,
      firstValid: data.firstValid,
      lastValid: data.lastValid,
      lease: data.lease,
      receiverBase: data.receiverPublic,
    });
  });

  await bench.run();

  console.table(bench.table());
})();

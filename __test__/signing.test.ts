import {
  BIP32DerivationType,
  fromSeed,
  harden,
  KeyContext,
  XHDWalletAPI,
} from "@algorandfoundation/xhd-wallet-api";
import { ed25519 } from "../node_modules/@noble/curves/ed25519";
import {
  deriveStealthPublicKey,
  xHdStealthSign,
  generateDiscoveryNote,
  checkDiscoveryNote,
} from "../src/index";
import { describe, it, expect } from "vitest";

const xhd = new XHDWalletAPI();

const SEED = new Uint8Array(32);
crypto.getRandomValues(SEED);

const PATH = [harden(44), harden(283), harden(0), 0, 0];
const ROOT_KEY = fromSeed(SEED);
const MESSAGE = new TextEncoder().encode("Hello, world!");

describe("xHD Stealth", () => {
  it("xHdStealthSign", async () => {
    const tweakScalar = BigInt(1234567890);

    const basePublic = (
      await xhd.deriveKey(ROOT_KEY, PATH, false, BIP32DerivationType.Peikert)
    ).slice(0, 32);

    const sig = await xHdStealthSign({
      rootKey: ROOT_KEY,
      account: 0,
      index: 0,
      tweakScalar,
      message: MESSAGE,
    });

    const isValid = ed25519.verify(
      sig,
      MESSAGE,
      deriveStealthPublicKey(basePublic, tweakScalar),
    );

    expect(isValid).toBe(true);
  });

  it("discovery", async () => {
    const sender = ed25519.keygen().publicKey;

    const receiverPublic = await xhd.keyGen(
      ROOT_KEY,
      KeyContext.Address,
      0,
      0,
      BIP32DerivationType.Peikert,
    );

    const firstValid = 100;
    const lastValid = 200;
    const lease = new Uint8Array(32);
    crypto.getRandomValues(lease);

    const note = await generateDiscoveryNote({
      sender,
      receiver: receiverPublic,
      firstValid,
      lastValid,
      lease,
    });

    const isValid = await checkDiscoveryNote({
      note,
      rootKey: ROOT_KEY,
      account: 0,
      index: 0,
      sender,
      firstValid,
      lastValid,
      lease,
    });

    expect(isValid).toBe(true);
  });
});

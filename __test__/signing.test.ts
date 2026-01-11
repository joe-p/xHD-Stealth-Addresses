import {
  BIP32DerivationType,
  fromSeed,
  KeyContext,
  XHDWalletAPI,
} from "@algorandfoundation/xhd-wallet-api";
import { ed25519 } from "../node_modules/@noble/curves/ed25519";
import {
  deriveStealthPublicKeyRaw,
  xHdStealthSignRaw,
  generateStealthKeyAndNote,
  checkDiscoveryNote,
  xHdStealthSign,
} from "../src/index";
import { describe, it, expect } from "vitest";
import { equalBytes } from "@noble/curves/utils.js";

const xhd = new XHDWalletAPI();

const SEED = new Uint8Array(32);
crypto.getRandomValues(SEED);

const ROOT_KEY = fromSeed(SEED);
const MESSAGE = new TextEncoder().encode("Hello, world!");

describe("xHD Stealth", () => {
  it("xHdStealthSignRaw", async () => {
    const tweakScalar = BigInt(1234567890);

    const basePublic = await xhd.keyGen(
      ROOT_KEY,
      KeyContext.Address,
      0,
      0,
      BIP32DerivationType.Peikert,
    );

    const sig = await xHdStealthSignRaw({
      rootKey: ROOT_KEY,
      account: 0,
      index: 0,
      tweakScalar,
      message: MESSAGE,
    });

    const isValid = ed25519.verify(
      sig,
      MESSAGE,
      deriveStealthPublicKeyRaw(basePublic, tweakScalar),
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

    const { note } = await generateStealthKeyAndNote({
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

  it("xHdStealthSign", async () => {
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

    const { note, stealthPublicKey } = await generateStealthKeyAndNote({
      sender,
      receiver: receiverPublic,
      firstValid,
      lastValid,
      lease,
    });

    expect(equalBytes(stealthPublicKey, receiverPublic)).toBe(false);

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

    const sig = await xHdStealthSign({
      note,
      rootKey: ROOT_KEY,
      account: 0,
      index: 0,
      message: MESSAGE,
    });

    const isSigValid = ed25519.verify(sig, MESSAGE, stealthPublicKey);

    expect(isSigValid).toBe(true);
  });
});

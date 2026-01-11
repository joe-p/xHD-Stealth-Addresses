import {
  BIP32DerivationType,
  fromSeed,
  harden,
  XHDWalletAPI,
} from "@algorandfoundation/xhd-wallet-api";
import { ed25519 } from "../node_modules/@noble/curves/ed25519";
import { deriveStealthPublicKey, xHdStealthSign } from "../src/index";
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
});

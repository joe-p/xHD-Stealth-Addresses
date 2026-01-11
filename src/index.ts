import {
  BIP32DerivationType,
  harden,
  XHDWalletAPI,
} from "@algorandfoundation/xhd-wallet-api";
import { ed25519 } from "@noble/curves/ed25519.js";
import {
  bytesToNumberLE,
  concatBytes,
  numberToBytesLE,
} from "@noble/curves/utils.js";
import { sha512 } from "js-sha512";
const ORDER = ed25519.Point.CURVE().n; // subgroup order
const scalar = {
  add: (a: bigint, b: bigint) => {
    return (a + b) % ORDER;
  },
};

const COIN_TYPE = 283;

export function getPath(account: number, addressIndex: number) {
  return [harden(44), harden(COIN_TYPE), harden(account), 0, addressIndex];
}

const xhd = new XHDWalletAPI();

export function deriveStealthPublicKey(
  basePublicKey: Uint8Array,
  tweakScalar: bigint,
): Uint8Array {
  const basePoint = ed25519.Point.fromBytes(basePublicKey);

  const tweakPoint = ed25519.Point.BASE.multiply(tweakScalar);
  const stealthPoint = basePoint.add(tweakPoint);

  return stealthPoint.toBytes();
}

function signWithExtendedKey(
  message: Uint8Array,
  scalar: bigint,
  prefix: Uint8Array,
  publicKey: Uint8Array,
): Uint8Array {
  // 1. r = SHA512(prefix || message) mod L
  const rHash = sha512.digest(concatBytes(prefix, message));
  const r = bytesToNumberLE(new Uint8Array(rHash)) % ORDER;

  // 2. R = r * G
  const R = ed25519.Point.BASE.multiply(r);
  const Rbytes = R.toBytes();

  // 3. k = SHA512(R || publicKey || message) mod L
  const kHash = sha512.digest(concatBytes(Rbytes, publicKey, message));
  const k = bytesToNumberLE(new Uint8Array(kHash)) % ORDER;

  // 4. S = (r + k * scalar) mod L
  const S = (r + k * scalar) % ORDER;

  // 5. Return signature (R || S)
  return concatBytes(Rbytes, numberToBytesLE(S, 32));
}

function deriveStealthPrivateKey(
  baseScalar: bigint,
  tweakScalar: bigint,
  basePrefix: Uint8Array,
): { scalar: bigint; prefix: Uint8Array } {
  const tweakedScalar = scalar.add(baseScalar, tweakScalar);
  const tweakdPrefix = sha512.digest(
    concatBytes(numberToBytesLE(tweakScalar, 32), basePrefix),
  );

  return { scalar: tweakedScalar, prefix: new Uint8Array(tweakdPrefix) };
}

export async function xHdStealthSign({
  rootKey,
  account,
  index,
  tweakScalar,
  message,
}: {
  rootKey: Uint8Array;
  account: number;
  index: number;
  tweakScalar: bigint;
  message: Uint8Array;
}) {
  const path = getPath(account, index);

  const basePublic = (
    await xhd.deriveKey(rootKey, path, false, BIP32DerivationType.Peikert)
  ).slice(0, 32);
  const stealthPublicKey = deriveStealthPublicKey(basePublic, tweakScalar);

  const basePrivate = await xhd.deriveKey(
    rootKey,
    path,
    true,
    BIP32DerivationType.Peikert,
  );

  const baseScalar = bytesToNumberLE(basePrivate.slice(0, 32));
  const basePrefix = basePrivate.slice(32, 64);

  const stealthSecret = deriveStealthPrivateKey(
    baseScalar,
    tweakScalar,
    basePrefix,
  );

  return signWithExtendedKey(
    message,
    stealthSecret.scalar,
    stealthSecret.prefix,
    stealthPublicKey,
  );
}

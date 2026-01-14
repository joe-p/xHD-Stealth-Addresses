import {
  BIP32DerivationType,
  harden,
  KeyContext,
  XHDWalletAPI,
} from "@algorandfoundation/xhd-wallet-api";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import {
  bytesToNumberLE,
  concatBytes,
  equalBytes,
  numberToBytesLE,
} from "@noble/curves/utils.js";
import { blake2b } from "@noble/hashes/blake2.js";
import { sha512 } from "@noble/hashes/sha2.js";

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

export function deriveStealthPublicKeyRaw(
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
  const rHash = sha512(concatBytes(prefix, message));
  const r = bytesToNumberLE(new Uint8Array(rHash)) % ORDER;

  // 2. R = r * G
  const R = ed25519.Point.BASE.multiply(r);
  const Rbytes = R.toBytes();

  // 3. k = SHA512(R || publicKey || message) mod L
  const kHash = sha512(concatBytes(Rbytes, publicKey, message));
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
  const tweakdPrefix = sha512(
    concatBytes(numberToBytesLE(tweakScalar, 32), basePrefix),
  );

  return { scalar: tweakedScalar, prefix: new Uint8Array(tweakdPrefix) };
}

export async function xHdStealthSignRaw({
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
  const stealthPublicKey = deriveStealthPublicKeyRaw(basePublic, tweakScalar);

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

/**
 * Generate a note that is used for discovery. The note is EPHEMERAL_KEY || DISCOVERY_TAG
 * Where DISCOVERY_TAG = BLAKE2B("discovery-tag" || ECDH_SECRET || sender || fv || lv || lease)
 */
export async function generateStealthKeyAndNote(args: {
  sender: Uint8Array;
  receiver: Uint8Array;
  firstValid: bigint;
  lastValid: bigint;
  lease: Uint8Array;
}): Promise<{ note: Uint8Array; stealthPublicKey: Uint8Array }> {
  const ephEd = ed25519.keygen();
  const ephMontgomerySk = ed25519.utils.toMontgomerySecret(ephEd.secretKey);
  const ephMontgomeryPk = ed25519.utils.toMontgomery(ephEd.publicKey);
  const receiverMontgomeryPk = ed25519.utils.toMontgomery(args.receiver);

  const sharedPoint = x25519.getSharedSecret(
    ephMontgomerySk,
    receiverMontgomeryPk,
  );

  const secret = blake2b(
    concatBytes(sharedPoint, ephMontgomeryPk, receiverMontgomeryPk),
    {
      dkLen: 32,
    },
  );

  const discoveryTag = blake2b(
    concatBytes(
      new TextEncoder().encode("discovery-tag"),
      secret,
      args.sender,
      numberToBytesLE(args.firstValid, 8),
      numberToBytesLE(args.lastValid, 8),
      args.lease,
    ),
    { dkLen: 32 },
  );

  const note = concatBytes(ephEd.publicKey, new Uint8Array(discoveryTag));
  const stealthPublicKey = deriveStealthPublicKeyRaw(
    args.receiver,
    bytesToNumberLE(secret) % ORDER,
  );

  return { note, stealthPublicKey };
}

export async function parseDiscoveryNote(args: {
  note: Uint8Array;
  rootKey: Uint8Array;
  account: number;
  index: number;
  sender: Uint8Array;
  firstValid: bigint;
  lastValid: bigint;
  lease: Uint8Array;
  receiverBase: Uint8Array;
}): Promise<{ matches: boolean; stealthPublicKey?: Uint8Array }> {
  const ephPublicKey = args.note.slice(0, 32);
  const receivedTag = args.note.slice(32, 64);

  const ecdhSecret = await xhd.ECDH(
    args.rootKey,
    KeyContext.Address,
    args.account,
    args.index,
    ephPublicKey,
    false,
    BIP32DerivationType.Peikert,
  );

  const discoveryTag = blake2b(
    concatBytes(
      new TextEncoder().encode("discovery-tag"),
      ecdhSecret,
      args.sender,
      numberToBytesLE(args.firstValid, 8),
      numberToBytesLE(args.lastValid, 8),
      args.lease,
    ),
    { dkLen: 32 },
  );

  if (!equalBytes(receivedTag, new Uint8Array(discoveryTag))) {
    return { matches: false };
  }

  const derivedStealthPublicKey = deriveStealthPublicKeyRaw(
    args.receiverBase,
    bytesToNumberLE(ecdhSecret) % ORDER,
  );

  return {
    matches: true,
    stealthPublicKey: derivedStealthPublicKey,
  };
}

export async function xHdStealthSign(args: {
  rootKey: Uint8Array;
  account: number;
  index: number;
  note: Uint8Array;
  message: Uint8Array;
}): Promise<Uint8Array> {
  const ephPublicKey = args.note.slice(0, 32);

  const ecdhSecret = await xhd.ECDH(
    args.rootKey,
    KeyContext.Address,
    args.account,
    args.index,
    ephPublicKey,
    false,
    BIP32DerivationType.Peikert,
  );

  return xHdStealthSignRaw({
    rootKey: args.rootKey,
    account: args.account,
    index: args.index,
    tweakScalar: bytesToNumberLE(ecdhSecret) % ORDER,
    message: args.message,
  });
}

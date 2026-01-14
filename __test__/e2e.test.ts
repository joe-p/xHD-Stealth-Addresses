import {
  BIP32DerivationType,
  fromSeed,
  KeyContext,
  XHDWalletAPI,
} from "@algorandfoundation/xhd-wallet-api";
import {
  generateStealthKeyAndNote,
  parseDiscoveryNote,
  xHdStealthSign,
} from "../src/index";
import { describe, it, expect, beforeAll } from "vitest";
import { Address, AlgorandClient } from "@algorandfoundation/algokit-utils";
import {
  encodeSignedTransaction,
  encodeTransaction,
  Transaction,
  type SignedTransaction,
} from "@algorandfoundation/algokit-utils/transact";
import { AlgoAmount } from "@algorandfoundation/algokit-utils/types/amount";
const xhd = new XHDWalletAPI();

describe("xHD Stealth E2E", () => {
  let receiverRoot: Uint8Array;
  let senderRoot: Uint8Array;
  let sender: Address;
  let receiver: Address;
  let algorand: AlgorandClient;

  beforeAll(async () => {
    const senderSeed = new Uint8Array(32);
    crypto.getRandomValues(senderSeed);
    senderRoot = fromSeed(senderSeed);

    const receiverSeed = new Uint8Array(32);
    crypto.getRandomValues(receiverSeed);
    receiverRoot = fromSeed(receiverSeed);

    const senderPublic = await xhd.keyGen(
      senderRoot,
      KeyContext.Address,
      0,
      0,
      BIP32DerivationType.Peikert,
    );

    const receiverPublic = await xhd.keyGen(
      receiverRoot,
      KeyContext.Address,
      0,
      0,
      BIP32DerivationType.Peikert,
    );

    receiver = new Address(receiverPublic);
    sender = new Address(senderPublic);
    algorand = AlgorandClient.defaultLocalNet();

    await algorand.account.ensureFundedFromEnvironment(
      sender,
      AlgoAmount.Algo(10),
    );
  });

  it("Send stealth payment", async () => {
    const receiverBalanceBefore = (await algorand.account.getInformation(receiver)).balance.microAlgo;
    expect(receiverBalanceBefore).toBe(0n);

    // Put the sending side in a closure to ensure we don't accidentally use sender variables
    // in the receiving logic
    const send = async () => {
      const sp = await algorand.getSuggestedParams();
      const firstValid = sp.firstValid;
      const lastValid = sp.lastValid;
      const lease = new Uint8Array(32);
      crypto.getRandomValues(lease);

      const { note, stealthPublicKey } = await generateStealthKeyAndNote({
        sender: sender.publicKey,
        receiver: receiver.publicKey,
        firstValid,
        lastValid,
        lease,
      });

      const stealthAddress = new Address(stealthPublicKey);

      const stealthBalanceBefore = (await algorand.account.getInformation(stealthAddress)).balance.microAlgo;
      expect(stealthBalanceBefore).toBe(0n);

      const pay = await algorand.send.payment({
        sender,
        receiver: stealthAddress,
        amount: AlgoAmount.Algo(1),
        firstValidRound: firstValid,
        lastValidRound: lastValid,
        lease,
        note,
        signer: async (txns: Transaction[], _: number[]) => {
          const txn = txns[0];
          const sig = await xhd.signAlgoTransaction(
            senderRoot,
            KeyContext.Address,
            0,
            0,
            encodeTransaction(txn!),
            BIP32DerivationType.Peikert,
          );

          const stxn: SignedTransaction = {
            txn: txn!,
            sig,
          };
          return [encodeSignedTransaction(stxn)];
        },
      });

      const receiverBalanceAfter = (await algorand.account.getInformation(receiver)).balance.microAlgo;
      expect(receiverBalanceAfter).toBe(0n);

      const stealthBalanceAfter = (await algorand.account.getInformation(stealthAddress)).balance.algo;
      expect(stealthBalanceAfter).toBe(1);

      return pay.confirmation.txn.txn;
    };

    // Receiver reads the confirmed txn
    const confirmedTxn = await send();
    const note = confirmedTxn.note!;

    const parsed = await parseDiscoveryNote({
      receiverBase: receiver.publicKey,
      note: note,
      rootKey: receiverRoot,
      account: 0,
      index: 0,
      sender: sender.publicKey,
      firstValid: confirmedTxn.firstValid!,
      lastValid: confirmedTxn.lastValid!,
      lease: confirmedTxn.lease!,
    });
    expect(parsed.matches).toBe(true);

    // now spend from the stealth address
    await algorand.send.payment({
      sender: new Address(parsed.stealthPublicKey!),
      receiver: sender,
      amount: AlgoAmount.Algo(0.5),
      signer: async (txns: Transaction[], _: number[]) => {
        const txn = txns[0];
        const sig = await xHdStealthSign({
          rootKey: receiverRoot,
          account: 0,
          index: 0,
          message: encodeTransaction(txn!),
          note: note,
        });

        const stxn: SignedTransaction = {
          txn: txn!,
          sig,
        };
        return [encodeSignedTransaction(stxn)];
      },
    });
  });
});

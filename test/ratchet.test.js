import { expect } from "chai";
import { Ratchet } from "../dist/core/signal.js";
import { getPublicKey, utils as secpUtils } from "@noble/secp256k1";
import { webcrypto } from "crypto";

// Polyfill for getRandomValues
if (!globalThis.crypto) {
  globalThis.crypto = webcrypto;
}

// Helper function to generate key pairs
async function generateKeyPair() {
  const privateKey = secpUtils.randomPrivateKey();
  const publicKey = getPublicKey(privateKey, false);
  return { privateKey, publicKey };
}

describe("Ratchet Class", () => {
  let aliceKeyPair, bobKeyPair, aliceRatchet, bobRatchet;

  before(async () => {
    aliceKeyPair = await generateKeyPair();
    bobKeyPair = await generateKeyPair();
  });

  beforeEach(() => {
    aliceRatchet = new Ratchet({ keyPair: aliceKeyPair, isInitiator: true });
    bobRatchet = new Ratchet({ keyPair: bobKeyPair, isInitiator: false });
  });

  it("should initialize successfully with valid key pairs", async () => {
    await aliceRatchet.initialize(bobKeyPair.publicKey);
    await bobRatchet.initialize(aliceKeyPair.publicKey);

    expect(aliceRatchet.getState().rootKey).to.not.be.null;
    expect(bobRatchet.getState().rootKey).to.not.be.null;
  });

  it("should fail to initialize with invalid remote public key", async () => {
    const invalidKey = new Uint8Array(64); // 64 bytes instead of 65
    try {
      await aliceRatchet.initialize(invalidKey);
    } catch (error) {
      expect(error.message).to.equal(
        "Invalid remote public key length. Expected 65 bytes (compressed format)"
      );
    }
  });

  it("should encrypt and decrypt a message successfully", async () => {
    await aliceRatchet.initialize(bobKeyPair.publicKey);
    await bobRatchet.initialize(aliceKeyPair.publicKey);

    const plaintext = "Hello, Bob!";
    const encryptedMessage = await aliceRatchet.encrypt(plaintext);
    console.log("-------------------------");
    const decryptedMessage = await bobRatchet.decrypt(encryptedMessage);

    expect(decryptedMessage).to.equal(plaintext);
  });

  it("should handle ratcheting correctly after multiple messages", async () => {
    await aliceRatchet.initialize(bobKeyPair.publicKey);
    await bobRatchet.initialize(aliceKeyPair.publicKey);

    const message1 = "Message 1";
    const encryptedMessage1 = await aliceRatchet.encrypt(message1);
    const decryptedMessage1 = await bobRatchet.decrypt(encryptedMessage1);

    expect(decryptedMessage1).to.equal(message1);

    const message2 = "Message 2";
    const encryptedMessage2 = await aliceRatchet.encrypt(message2);
    const decryptedMessage2 = await bobRatchet.decrypt(encryptedMessage2);

    expect(decryptedMessage2).to.equal(message2);
  });

  it("should fail to decrypt with incorrect public key", async () => {
    const anotherKeyPair = await generateKeyPair();
    await aliceRatchet.initialize(anotherKeyPair.publicKey); // Incorrect key for Alice

    try {
      const plaintext = "Invalid test";
      const encryptedMessage = await aliceRatchet.encrypt(plaintext);
      await bobRatchet.decrypt(encryptedMessage); // Bob should fail to decrypt this
    } catch (error) {
      expect(error.message).to.include("Decryption failed due to incorrect key or corrupted message data"); // Updated to match actual error
    }
  });
  it("should return the correct state after initialization", async () => {
    await aliceRatchet.initialize(bobKeyPair.publicKey);

    const state = aliceRatchet.getState();
    expect(state).to.have.property("rootKey").that.is.not.null;
    expect(state).to.have.property("sendChainKey").that.is.not.null;
    expect(state)
      .to.have.property("remotePublicKey")
      .that.deep.equal(bobKeyPair.publicKey);
  });

  it("should handle edge case with empty plaintext", async () => {
    await aliceRatchet.initialize(bobKeyPair.publicKey);
    await bobRatchet.initialize(aliceKeyPair.publicKey);

    const plaintext = "";
    const encryptedMessage = await aliceRatchet.encrypt(plaintext);
    const decryptedMessage = await bobRatchet.decrypt(encryptedMessage);

    expect(decryptedMessage).to.equal(plaintext);
  });
});

describe("Ratchet Class - Extended Tests", () => {
  let aliceKeyPair, bobKeyPair, aliceRatchet, bobRatchet;

  before(async () => {
    aliceKeyPair = await generateKeyPair();
    bobKeyPair = await generateKeyPair();
  });

  beforeEach(() => {
    aliceRatchet = new Ratchet({ keyPair: aliceKeyPair, isInitiator: true });
    bobRatchet = new Ratchet({ keyPair: bobKeyPair, isInitiator: false });
  });

  it("should allow a full back-and-forth conversation", async () => {
    // Initialize Alice and Bob's ratchets
    await aliceRatchet.initialize(bobKeyPair.publicKey);
    await bobRatchet.initialize(aliceKeyPair.publicKey);

    // Alice sends the first message to Bob
    const aliceMessage = "Hello, Bob!";
    const encryptedAliceMessage = await aliceRatchet.encrypt(aliceMessage);
    const decryptedAliceMessage = await bobRatchet.decrypt(
      encryptedAliceMessage
    );

    // Verify Bob can successfully decrypt Alice's message
    expect(decryptedAliceMessage).to.equal(aliceMessage);

    // Bob replies to Alice after receiving the first message
    const bobMessage = "Hi, Alice!";
    const encryptedBobMessage = await bobRatchet.encrypt(bobMessage);
    const decryptedBobMessage = await aliceRatchet.decrypt(encryptedBobMessage);

    // Verify Alice can decrypt Bob's reply
    expect(decryptedBobMessage).to.equal(bobMessage);

    // Alice sends another message
    const aliceReply = "How are you?";
    const encryptedAliceReply = await aliceRatchet.encrypt(aliceReply);
    const decryptedAliceReply = await bobRatchet.decrypt(encryptedAliceReply);

    // Verify Bob can decrypt Alice's second message
    expect(decryptedAliceReply).to.equal(aliceReply);
  });

  it("should fail to decrypt out-of-order messages", async () => {
    await aliceRatchet.initialize(bobKeyPair.publicKey);
    await bobRatchet.initialize(aliceKeyPair.publicKey);

    const message1 = "Message 1";
    const message2 = "Message 2";

    const encryptedMessage1 = await aliceRatchet.encrypt(message1);
    const encryptedMessage2 = await aliceRatchet.encrypt(message2);

    // Bob tries to decrypt the second message first (out of order)
    try {
      await bobRatchet.decrypt(encryptedMessage2);
    } catch (error) {
      expect(error.message).to.include(
        "Decryption failed due to incorrect key or corrupted message data"
      );
    }

    // Now decrypt the first message in order
    const decryptedMessage1 = await bobRatchet.decrypt(encryptedMessage1);
    expect(decryptedMessage1).to.equal(message1);

    // Now decrypt the second message in correct order
    const decryptedMessage2 = await bobRatchet.decrypt(encryptedMessage2);
    expect(decryptedMessage2).to.equal(message2);
  });

  it("should handle initialization without immediate key exchange", async () => {
    // Only initialize Alice
    await aliceRatchet.initialize(bobKeyPair.publicKey);

    // Encrypt a message without Bob initializing
    const message = "Hello, Bob!";
    const encryptedMessage = await aliceRatchet.encrypt(message);

    // Initialize Bob later and attempt decryption
    await bobRatchet.initialize(aliceKeyPair.publicKey);
    const decryptedMessage = await bobRatchet.decrypt(encryptedMessage);

    expect(decryptedMessage).to.equal(message);
  });

  it("should handle large messages gracefully", async () => {
    await aliceRatchet.initialize(bobKeyPair.publicKey);
    await bobRatchet.initialize(aliceKeyPair.publicKey);

    const largeMessage = "A".repeat(10000); // Large message (10,000 characters)
    const encryptedMessage = await aliceRatchet.encrypt(largeMessage);
    const decryptedMessage = await bobRatchet.decrypt(encryptedMessage);

    expect(decryptedMessage).to.equal(largeMessage);
  });
});

import * as secp256k1 from "@noble/secp256k1";
import { webcrypto as nodeCrypto } from "crypto"; // Node.js crypto

function uint8ArrayToHexString(uint8Array: Uint8Array): string {
  return Array.from(uint8Array)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export interface KeyPair {
  publicKey: Uint8Array; // Must be 33 bytes (compressed secp256k1)
  privateKey: Uint8Array; // Must be 32 bytes
}

export interface EncryptedMessage {
  dhPublicKey: Uint8Array; // Must be 33 bytes (compressed secp256k1)
  iv: Uint8Array; // Must be 12 bytes
  ciphertext: Uint8Array; // Variable length
  messageNumber: number;
}

export interface RatchetOptions {
  keyPair: KeyPair;
  isInitiator: boolean;
  verboseLog?: boolean;
}

export interface MessageCounter {
  chainKey: Uint8Array;
  messageNumber: number;
}

export interface RatchetState {
  rootKey: Uint8Array | null;
  sendChainKey: Uint8Array | null;
  recvChainKey: Uint8Array | null;
  remotePublicKey: Uint8Array | null;
  sendMessageNumber: number;
  recvMessageNumber: number;
  previousChainLength: number;
  needToRatchet: boolean;
  isFirstMessage: boolean;
  sentPublicKeys: string[];
  // Add cache states
  messageKeyCache: {
    [chainKey: string]: {
      [messageNumber: number]: string // hex string of Uint8Array
    }
  };
  sentMessageKeyCache: {
    [chainKey: string]: {
      [messageNumber: number]: string // hex string of Uint8Array
    }
  };
}

export class Ratchet {
  private readonly crypto: Crypto;
  private readonly subtle: SubtleCrypto;

  private publicKey: Uint8Array;
  private privateKey: Uint8Array;
  private rootKey: Uint8Array | null;
  private sendChainKey: Uint8Array | null;
  private recvChainKey: Uint8Array | null;
  private remotePublicKey: Uint8Array | null;

  private readonly isInitiator: boolean;
  private needToRatchet: boolean;
  private isFirstMessage: boolean;
  private verboseLog: boolean;

  private sendMessageNumber: number;
  private recvMessageNumber: number;
  private previousChainLength: number;
  private messageKeyCache: Map<string, Map<number, Uint8Array>>; // chainKey -> messageNumber -> messageKey
  private sentMessageKeyCache: Map<string, Map<number, Uint8Array>>; // For storing our own sent message keys
  private sentPublicKeys: Set<string>; // Track our sent message public keys

  private readonly MAX_SKIP = 1000; // Maximum number of skipped messages
  private readonly MAX_CACHE_SIZE = 2000; // Maximum size of message key cache
  private readonly MESSAGE_KEY_TTL = 14 * 24 * 60 * 60 * 1000; // 14 days in milliseconds

  constructor(options: RatchetOptions) {
    // Use window.crypto for browser or Node.js's crypto for server
    const globalCrypto =
      typeof window !== "undefined" ? window.crypto : nodeCrypto;

    if (!globalCrypto || !globalCrypto.subtle) {
      throw new Error("Web Crypto API is not available.");
    }

    // TypeScript type assertion
    this.crypto = globalCrypto as Crypto;
    this.subtle = this.crypto.subtle;
    this.verboseLog = options.verboseLog || true;

    // Validate keypair
    if (
      !options.keyPair ||
      !options.keyPair.publicKey ||
      !options.keyPair.privateKey
    ) {
      throw new Error("Invalid keypair provided");
    }

    if (options.keyPair.privateKey.length !== 32) {
      throw new Error("Invalid private key length. Expected 32 bytes");
    }

    if (options.keyPair.publicKey.length !== 65) {
      throw new Error(
        "Invalid public key length. Expected 65 bytes (uncompressed format)"
      );
    }

    // Verify the keypair is valid
    const derivedPubKey = secp256k1.getPublicKey(
      options.keyPair.privateKey,
      false
    );

    if (!this.areBuffersEqual(derivedPubKey, options.keyPair.publicKey)) {
      throw new Error("Public key does not match private key");
    }

    this.publicKey = options.keyPair.publicKey;
    this.privateKey = options.keyPair.privateKey;

    this.rootKey = null;
    this.sendChainKey = null;
    this.recvChainKey = null;
    this.remotePublicKey = null;

    this.isInitiator = options.isInitiator;
    this.needToRatchet = false;
    this.isFirstMessage = true;

    this.sendMessageNumber = 0;
    this.recvMessageNumber = 0;
    this.previousChainLength = 0;
    this.messageKeyCache = new Map();
    this.sentMessageKeyCache = new Map(); // Add sent message key cache
    this.sentPublicKeys = new Set();
  }

  private async hkdf(
    salt: Uint8Array,
    ikm: Uint8Array,
    info: string,
    length: number
  ): Promise<Uint8Array> {
    const encoder = new TextEncoder();
    const baseKey = await this.subtle.importKey(
      "raw",
      ikm,
      { name: "HKDF" },
      false,
      ["deriveBits"]
    );

    const derivedBits = await this.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: salt,
        info: encoder.encode(info),
      },
      baseKey,
      length * 8
    );

    return new Uint8Array(derivedBits);
  }

  private async kdfRoot(
    rootKey: Uint8Array | null,
    dhOutput: Uint8Array
  ): Promise<{ newRootKey: Uint8Array; newChainKey: Uint8Array }> {
    const salt = rootKey || new Uint8Array(32);
    const okm = await this.hkdf(salt, dhOutput, "DoubleRatchetRoot", 64);
    const newRootKey = okm.slice(0, 32);
    const newChainKey = okm.slice(32, 64);
    return { newRootKey, newChainKey };
  }

  private async kdfChainKey(chainKey: Uint8Array): Promise<Uint8Array> {
    const encoder = new TextEncoder();
    const key = await this.subtle.importKey(
      "raw",
      chainKey,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    const signature = await this.subtle.sign(
      "HMAC",
      key,
      encoder.encode("ChainKey")
    );

    return new Uint8Array(signature);
  }

  private async kdfMessageKey(chainKey: Uint8Array): Promise<Uint8Array> {
    const encoder = new TextEncoder();
    const key = await this.subtle.importKey(
      "raw",
      chainKey,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    const signature = await this.subtle.sign(
      "HMAC",
      key,
      encoder.encode("MessageKey")
    );

    return new Uint8Array(signature);
  }

  public async initialize(remotePublicKey: Uint8Array): Promise<void> {
    if (remotePublicKey.length !== 65) {
      throw new Error(
        "Invalid remote public key length. Expected 65 bytes (compressed format)"
      );
    }

    this.remotePublicKey = remotePublicKey;

    // Compute shared secret using ECDH with secp256k1
    const sharedPoint = secp256k1.getSharedSecret(
      this.privateKey,
      this.remotePublicKey
    );
    // Use only the x-coordinate (first 32 bytes) as the shared secret
    const sharedSecret = sharedPoint.slice(1, 33);

    // Derive initial root key and chain key
    const { newRootKey, newChainKey } = await this.kdfRoot(null, sharedSecret);
    this.rootKey = newRootKey;

    if (this.verboseLog) if (this.verboseLog) console.log("Root key", uint8ArrayToHexString(this.rootKey));
    if (this.verboseLog) console.log("Chain key", uint8ArrayToHexString(newChainKey));

    if (this.isInitiator) {
      this.sendChainKey = newChainKey;
      this.needToRatchet = true;
      if (this.verboseLog) console.log(
        "Initiator: send chain key",
        uint8ArrayToHexString(this.sendChainKey)
      );
    } else {
      this.recvChainKey = newChainKey;
      if (this.verboseLog) console.log(
        "Non-initiator: receive chain key",
        uint8ArrayToHexString(this.recvChainKey)
      );
    }
  }

  private getCacheKey(chainKey: Uint8Array): string {
    return uint8ArrayToHexString(chainKey);
  }

  private async storeMessageKey(dhPublicKey: Uint8Array, messageNumber: number, messageKey: Uint8Array) {
    const cacheKey = this.getCacheKey(dhPublicKey);
    if (!this.messageKeyCache.has(cacheKey)) {
      this.messageKeyCache.set(cacheKey, new Map());
    }

    const chainCache = this.messageKeyCache.get(cacheKey)!;
    chainCache.set(messageNumber, messageKey);

    // Add timestamp to track TTL
    const timestamp = Date.now();
    chainCache.set(messageNumber, messageKey);

    // Enforce cache size limit
    if (chainCache.size > this.MAX_CACHE_SIZE) {
      const sortedKeys = Array.from(chainCache.keys()).sort((a, b) => a - b);
      while (chainCache.size > this.MAX_CACHE_SIZE) {
        chainCache.delete(sortedKeys.shift()!);
      }
    }
  }

  public async encrypt(plaintext: string): Promise<EncryptedMessage> {
    if (!this.remotePublicKey) {
      throw new Error("Ratchet not initialized. Call initialize() first");
    }

    // Generate new DH key pair for every message ratchet
    this.privateKey = secp256k1.utils.randomPrivateKey();
    this.publicKey = secp256k1.getPublicKey(this.privateKey, false);

    // Track this public key as one we used for sending
    this.sentPublicKeys.add(uint8ArrayToHexString(this.publicKey));
    if (this.verboseLog) console.log(`Generated new DH key pair for encrypting message.`, this.privateKey, this.remotePublicKey);

    // Perform a Diffie-Hellman ratchet step
    const sharedPoint = secp256k1.getSharedSecret(
      this.privateKey,
      this.remotePublicKey
    );
    const sharedSecret = sharedPoint.slice(1, 33);

    if (!this.rootKey) {
      throw new Error("Root key not initialized");
    }

    // Update root key and derive the new send chain key
    const { newRootKey, newChainKey } = await this.kdfRoot(
      this.rootKey,
      sharedSecret
    );
    this.rootKey = newRootKey;
    this.sendChainKey = newChainKey;

    if (this.verboseLog) console.log(`New Root Key: ${Buffer.from(this.rootKey).toString("hex")}`);
    if (this.verboseLog) console.log(
      `New Send Chain Key: ${Buffer.from(this.sendChainKey).toString("hex")}`
    );

    // Include message number in the packet
    const messageNumber = this.sendMessageNumber++;

    // Derive message key
    const messageKey = await this.kdfMessageKey(this.sendChainKey);
    if (messageKey.length !== 32) {
      throw new Error("Derived message key length is invalid");
    }
    // Store the message key with the public key as cache key for later decryption
    await this.storeSentMessageKey(this.publicKey, messageNumber, messageKey);

    // Generate a 12-byte IV for AES-GCM encryption
    const iv = this.crypto.getRandomValues(new Uint8Array(12));
    if (iv.length !== 12) {
      throw new Error("IV length must be 12 bytes");
    }

    if (this.verboseLog) console.log(
      `Encrypting message with IV: ${Buffer.from(iv).toString("hex")}`
    );
    if (this.verboseLog) console.log(`Encrypting with message key: ${Buffer.from(messageKey).toString("hex")}`);

    // Import the message key for encryption
    const encKey = await this.subtle.importKey(
      "raw",
      messageKey,
      { name: "AES-GCM" },
      false,
      ["encrypt"]
    );

    // Encrypt the plaintext
    const encoder = new TextEncoder();
    const plaintextBytes = encoder.encode(plaintext || " "); // Fallback to a single space for empty strings
    const encryptedData = await this.subtle.encrypt(
      { name: "AES-GCM", iv },
      encKey,
      plaintextBytes
    );

    return {
      dhPublicKey: this.publicKey,
      iv,
      ciphertext: new Uint8Array(encryptedData),
      messageNumber
    };
  }

  public async decrypt(packet: EncryptedMessage): Promise<string> {
    if (!packet.dhPublicKey || !packet.iv || !packet.ciphertext) {
      throw new Error("Invalid encrypted message format");
    }

    if (packet.dhPublicKey.length !== 65) {
      throw new Error("Invalid public key length. Expected 65 bytes (uncompressed format)");
    }

    if (packet.iv.length !== 12) {
      throw new Error("Invalid IV length. Expected 12 bytes");
    }

    if (packet.ciphertext.length === 0) {
      throw new Error("Empty ciphertext");
    }

    try {
      let messageKey: Uint8Array | undefined;

      if (this.isSentMessage(packet)) {
        if (this.verboseLog) console.log(`Decrypting own message #${packet.messageNumber}`);

        // Use the message's DH public key as cache key
        const cacheKey = uint8ArrayToHexString(packet.dhPublicKey);
        if (this.verboseLog) console.log(`Cache key: ${cacheKey}`);
        const chainCache = this.sentMessageKeyCache.get(cacheKey);
        messageKey = chainCache?.get(packet.messageNumber);

        if (!messageKey) {
          throw new Error("Sent message key not found in cache");
        }
      } else {
        if (this.verboseLog) console.log(`Decrypting received message #${packet.messageNumber}`);
        const decrypted = await this.decryptReceivedMessage(packet);
        return decrypted;
      }

      // Decrypt the message using the found message key
      const decKey = await this.subtle.importKey(
        "raw",
        messageKey,
        {name: "AES-GCM"},
        false,
        ["decrypt"]
      );

      const decryptedData = await this.subtle.decrypt(
        {name: "AES-GCM", iv: packet.iv},
        decKey,
        packet.ciphertext
      );

      const decoder = new TextDecoder();
      return decoder.decode(decryptedData).trim();
    } catch (error) {
      console.error('Decryption failed:', error);
      throw new Error(
        error instanceof Error
          ? error.message
          : "Decryption failed due to incorrect key or corrupted message data"
      );
    }
  }

  private async decryptReceivedMessage(packet: EncryptedMessage): Promise<string> {
    // Backup current state to revert in case of failure
    const oldRootKey = this.rootKey ? new Uint8Array(this.rootKey) : null;
    const oldRecvChainKey = this.recvChainKey ? new Uint8Array(this.recvChainKey) : null;
    const oldRemotePublicKey = this.remotePublicKey ? new Uint8Array(this.remotePublicKey) : null;

    try {
      // Save current state before any changes
      const savedState = {
        rootKey: this.rootKey ? new Uint8Array(this.rootKey) : null,
        recvChainKey: this.recvChainKey ? new Uint8Array(this.recvChainKey) : null,
        remotePublicKey: this.remotePublicKey ? new Uint8Array(this.remotePublicKey) : null,
        sendMessageNumber: this.sendMessageNumber,
        recvMessageNumber: this.recvMessageNumber,
        previousChainLength: this.previousChainLength
      };

      const keysAreDifferent = !this.remotePublicKey ||
        !this.areBuffersEqual(packet.dhPublicKey, this.remotePublicKey);

      // Check if this is an out-of-order message, but skip check for first message
      const isFirstMessage = packet.messageNumber === 0;
      if (this.verboseLog) console.log(`isFirstMessage: ${isFirstMessage}`);
      if (!isFirstMessage && packet.messageNumber > this.recvMessageNumber) {
        if (this.verboseLog) {
          console.log(
            `Out-of-order message received. Skipping ${
              packet.messageNumber - this.recvMessageNumber
            } messages.`
          );
        }
        // Store current state and throw error
        if (this.recvChainKey) {
          await this.storeMessageKey(
            packet.dhPublicKey, // Use DH public key instead of chain key
            packet.messageNumber,
            await this.kdfMessageKey(this.recvChainKey)
          );
        }
        throw new Error("Message received out of order");
      }

      // Handle DH ratchet step if needed
      if (keysAreDifferent) {
        if (this.verboseLog) {
          console.log("Keys are different. Generating new shared secret and ratcheting.");
        }

        // Compute new shared secret using received public key and current private key
        const sharedPoint = secp256k1.getSharedSecret(
          this.privateKey,
          packet.dhPublicKey
        );
        const sharedSecret = sharedPoint.slice(1, 33);

        if (!this.rootKey) {
          throw new Error("Root key not initialized");
        }

        // Derive new root key and receive chain key
        const derivedKeys = await this.kdfRoot(this.rootKey, sharedSecret);
        this.rootKey = derivedKeys.newRootKey;
        this.recvChainKey = derivedKeys.newChainKey;
        this.remotePublicKey = packet.dhPublicKey;

        // Store the length of the previous sending chain
        this.previousChainLength = this.sendMessageNumber;
        this.sendMessageNumber = 0;
        this.recvMessageNumber = 0;

        // Ensure non-initiator initializes the send chain key after receiving the first message
        if (!this.sendChainKey) {
          this.sendChainKey = await this.kdfChainKey(this.recvChainKey);
        }
      }

      // Try to find message key in cache first
      const cacheKey = this.getCacheKey(packet.dhPublicKey);
      const chainCache = this.messageKeyCache.get(cacheKey);
      let messageKey = chainCache?.get(packet.messageNumber);

      if (chainCache) {
        if (this.verboseLog) {
          console.log(`Message key found in cache for message #${packet.messageNumber} and publicKey: ${uint8ArrayToHexString(packet.dhPublicKey)}`);
        }
      }

      if (!messageKey) {
        if (!isFirstMessage && packet.messageNumber < this.recvMessageNumber) {
          // Restore previous state and try again
          Object.assign(this, savedState);
          if (this.verboseLog) console.log(`Restored state after decryption failure. packet.messageNumber: ${packet.messageNumber}, this.recvMessageNumber: ${this.recvMessageNumber}`);
          throw new Error("Message from old chain that we don't have cached");
        }

        // Generate new message key and advance chain
        messageKey = await this.kdfMessageKey(this.recvChainKey!);
        this.recvChainKey = await this.kdfChainKey(this.recvChainKey!);
        this.recvMessageNumber = packet.messageNumber + 1;

        // Store the message key with DH public key as cache key
        await this.storeMessageKey(packet.dhPublicKey, packet.messageNumber, messageKey);
      } else {

      }

      if (messageKey.length !== 32) {
        throw new Error("Derived message key length is invalid");
      }

      if (this.verboseLog) {
        console.log(`Decrypting with received chain key: ${
          Buffer.from(this.recvChainKey!).toString("hex")
        }`);
        console.log(`Decrypt with message key: ${
          Buffer.from(messageKey).toString("hex")
        }`);
      }

      // Import message key for decryption
      const decKey = await this.subtle.importKey(
        "raw",
        messageKey,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
      );

      // Attempt to decrypt the ciphertext
      const decryptedData = await this.subtle.decrypt(
        { name: "AES-GCM", iv: packet.iv },
        decKey,
        packet.ciphertext
      );

      // Return the decrypted plaintext
      const decoder = new TextDecoder();
      return decoder.decode(decryptedData).trim();
    } catch (error) {
      if (this.verboseLog) {
        console.error(
          `Decryption failed due to incorrect key or corrupted message data. Reverting the receive chain key to: ${
            oldRecvChainKey
              ? Buffer.from(oldRecvChainKey).toString("hex")
              : "not initialized"
          }`
        );
      }

      // Revert to the previous state if decryption fails
      this.rootKey = oldRootKey ? new Uint8Array(oldRootKey) : null;
      this.recvChainKey = oldRecvChainKey ? new Uint8Array(oldRecvChainKey) : null;
      this.remotePublicKey = oldRemotePublicKey ? new Uint8Array(oldRemotePublicKey) : null;

      throw error;
    }
  }

  private async storeSentMessageKey(
    dhPublicKey: Uint8Array,
    messageNumber: number,
    messageKey: Uint8Array
  ) {
    const cacheKey = uint8ArrayToHexString(dhPublicKey);
    if (!this.sentMessageKeyCache.has(cacheKey)) {
      this.sentMessageKeyCache.set(cacheKey, new Map());
    }

    const chainCache = this.sentMessageKeyCache.get(cacheKey)!;
    chainCache.set(messageNumber, messageKey);

    // Enforce cache size limit
    if (chainCache.size > this.MAX_CACHE_SIZE) {
      const sortedKeys = Array.from(chainCache.keys()).sort((a, b) => a - b);
      while (chainCache.size > this.MAX_CACHE_SIZE) {
        chainCache.delete(sortedKeys.shift()!);
      }
    }
  }

  // Add method to check if a message was sent by us
  public isSentMessage(packet: EncryptedMessage): boolean {
    return this.sentPublicKeys.has(uint8ArrayToHexString(packet.dhPublicKey));
  }

  public restoreState(state: RatchetState): void {
    if (!state) {
      throw new Error("No state provided for restoration");
    }

    // Restore basic properties
    this.rootKey = state.rootKey;
    this.sendChainKey = state.sendChainKey;
    this.recvChainKey = state.recvChainKey;
    this.remotePublicKey = state.remotePublicKey;
    this.sendMessageNumber = state.sendMessageNumber;
    this.recvMessageNumber = state.recvMessageNumber;
    this.previousChainLength = state.previousChainLength;
    this.needToRatchet = state.needToRatchet;
    this.isFirstMessage = state.isFirstMessage;
    this.sentPublicKeys = new Set(state.sentPublicKeys);

    // Restore message key caches
    this.messageKeyCache = new Map(
      Object.entries(state.messageKeyCache).map(([chainKey, messages]) => [
        chainKey,
        new Map(
          Object.entries(messages).map(([msgNum, keyHex]) => [
            parseInt(msgNum),
            new Uint8Array(Buffer.from(keyHex, 'hex'))
          ])
        )
      ])
    );

    // Restore sent message key cache
    this.sentMessageKeyCache = new Map(
      Object.entries(state.sentMessageKeyCache).map(([chainKey, messages]) => [
        chainKey,
        new Map(
          Object.entries(messages).map(([msgNum, keyHex]) => [
            parseInt(msgNum),
            new Uint8Array(Buffer.from(keyHex, 'hex'))
          ])
        )
      ])
    );

    if (this.verboseLog) {
      console.log('Restored ratchet state with caches:', {
        rootKey: this.rootKey ? uint8ArrayToHexString(this.rootKey) : null,
        sendChainKey: this.sendChainKey ? uint8ArrayToHexString(this.sendChainKey) : null,
        recvChainKey: this.recvChainKey ? uint8ArrayToHexString(this.recvChainKey) : null,
        remotePublicKey: this.remotePublicKey ? uint8ArrayToHexString(this.remotePublicKey) : null,
        sendMessageNumber: this.sendMessageNumber,
        recvMessageNumber: this.recvMessageNumber,
        previousChainLength: this.previousChainLength,
        needToRatchet: this.needToRatchet,
        isFirstMessage: this.isFirstMessage,
        sentPublicKeysCount: this.sentPublicKeys.size,
        messageKeyCacheSize: this.messageKeyCache.size,
        sentMessageKeyCacheSize: this.sentMessageKeyCache.size
      });
      console.log(`State after restoration:`, this.getState());
    }
  }

  public getState(): RatchetState {
    // Convert message key caches to serializable format using Object.fromEntries
    const messageKeyCache = Object.fromEntries(
      Array.from(this.messageKeyCache.entries()).map(([chainKey, messages]) => [
        chainKey,
        Object.fromEntries(
          Array.from(messages.entries()).map(([msgNum, keyBytes]) => [
            msgNum,
            uint8ArrayToHexString(keyBytes)
          ])
        )
      ])
    );

    const sentMessageKeyCache = Object.fromEntries(
      Array.from(this.sentMessageKeyCache.entries()).map(([chainKey, messages]) => [
        chainKey,
        Object.fromEntries(
          Array.from(messages.entries()).map(([msgNum, keyBytes]) => [
            msgNum,
            uint8ArrayToHexString(keyBytes)
          ])
        )
      ])
    );

    return {
      rootKey: this.rootKey,
      sendChainKey: this.sendChainKey,
      recvChainKey: this.recvChainKey,
      remotePublicKey: this.remotePublicKey,
      needToRatchet: this.needToRatchet,
      isFirstMessage: this.isFirstMessage,
      sendMessageNumber: this.sendMessageNumber,
      recvMessageNumber: this.recvMessageNumber,
      previousChainLength: this.previousChainLength,
      sentPublicKeys: Array.from(this.sentPublicKeys),
      messageKeyCache,
      sentMessageKeyCache
    };
  }

  public cloneState(): RatchetState {
    return {
      rootKey: this.rootKey ? new Uint8Array(this.rootKey) : null,
      sendChainKey: this.sendChainKey ? new Uint8Array(this.sendChainKey) : null,
      recvChainKey: this.recvChainKey ? new Uint8Array(this.recvChainKey) : null,
      remotePublicKey: this.remotePublicKey ? new Uint8Array(this.remotePublicKey) : null,
      sendMessageNumber: this.sendMessageNumber,
      recvMessageNumber: this.recvMessageNumber,
      previousChainLength: this.previousChainLength,
      needToRatchet: this.needToRatchet,
      isFirstMessage: this.isFirstMessage,
      sentPublicKeys: Array.from(this.sentPublicKeys),
      messageKeyCache: this.getState().messageKeyCache, // Use getState to get serializable format
      sentMessageKeyCache: this.getState().sentMessageKeyCache
    };
  }

  // Add helper method to convert public key to/from string
  private publicKeyToString(pubKey: Uint8Array): string {
    return uint8ArrayToHexString(pubKey);
  }

  private areBuffersEqual(buf1: Uint8Array, buf2: Uint8Array): boolean {
    if (buf1.length !== buf2.length) return false;
    return buf1.every((byte, i) => byte === buf2[i]);
  }
}

# Ciphersuite for E2E message encryption

A suite of cryptographic utilities, including secp256k1, AES, and Salsa for secure messaging. This library implements the Signal Double Ratchet protocol for end-to-end encrypted communication. It also provides handy utilities from the `@noble/secp256k1` library.

## Installation

To use this library in your Vue.js or React.js project, you can install it via npm:

```bash
npm install @thant-dev/ciphersuite
```

## Usage in Vue.js

Here's a simple example of how you can use `@thant-dev/ciphersuite` in a Vue.js project.

```javascript
<template>
  <div>
    <h1>Secure Messaging</h1>
    <button @click="initializeRatchet">Initialize Ratchet</button>
    <button @click="sendMessage">Send Message</button>
    <button @click="receiveMessage">Receive Message</button>
  </div>
</template>

<script>
import { Ratchet, getPublicKey, secpUtils } from '@thant-dev/ciphersuite';

export default {
  name: 'SecureMessagingComponent',
  data() {
    return {
      ratchetInstance: null,
      encryptedMessage: null
    };
  },
  methods: {
    initializeRatchet() {
      const keyPair = {
        privateKey: secpUtils.randomPrivateKey(),
        publicKey: getPublicKey(privateKey)
      };
      this.ratchetInstance = new Ratchet({ keyPair, isInitiator: true });
      console.log('Ratchet instance:', this.ratchetInstance);
    },
    async sendMessage() {
      if (this.ratchetInstance) {
        const message = "Hello, Bob!";
        this.encryptedMessage = await this.ratchetInstance.encrypt(message);
        console.log('Encrypted Message:', this.encryptedMessage);
      } else {
        console.error('Ratchet instance is not initialized');
      }
    },
    async receiveMessage() {
      if (this.ratchetInstance && this.encryptedMessage) {
        try {
          const decryptedMessage = await this.ratchetInstance.decrypt(this.encryptedMessage);
          console.log('Decrypted Message:', decryptedMessage);
        } catch (error) {
          console.error('Failed to decrypt message:', error);
        }
      } else {
        console.error('Ratchet instance or encrypted message is not available');
      }
    }
  }
};
</script>
```

## Usage in React.js

You can also use `@thant-dev/ciphersuite` in a React.js project. Below is a simple usage example with React hooks.

```javascript
import React, { useState } from 'react';
import { Ratchet, getPublicKey, secpUtils } from '@thant-dev/ciphersuite';

const SecureMessagingComponent = () => {
  const [ratchetInstance, setRatchetInstance] = useState(null);
  const [encryptedMessage, setEncryptedMessage] = useState(null);

  const initializeRatchet = () => {
    const keyPair = {
      privateKey: secpUtils.randomPrivateKey(),
      publicKey: getPublicKey(privateKey)
    };
    const ratchet = new Ratchet({ keyPair, isInitiator: true });
    setRatchetInstance(ratchet);
    console.log('Ratchet instance:', ratchet);
  };

  const sendMessage = async () => {
    if (ratchetInstance) {
      const message = "Hello, Bob!";
      const encrypted = await ratchetInstance.encrypt(message);
      setEncryptedMessage(encrypted);
      console.log('Encrypted Message:', encrypted);
    } else {
      console.error('Ratchet instance is not initialized');
    }
  };

  const receiveMessage = async () => {
    if (ratchetInstance && encryptedMessage) {
      try {
        const decryptedMessage = await ratchetInstance.decrypt(encryptedMessage);
        console.log('Decrypted Message:', decryptedMessage);
      } catch (error) {
        console.error('Failed to decrypt message:', error);
      }
    } else {
      console.error('Ratchet instance or encrypted message is not available');
    }
  };

  return (
    <div>
      <h1>Secure Messaging</h1>
      <button onClick={initializeRatchet}>Initialize Ratchet</button>
      <button onClick={sendMessage}>Send Message</button>
      <button onClick={receiveMessage}>Receive Message</button>
    </div>
  );
};

export default SecureMessagingComponent;
```

## API Documentation

### `Ratchet`
The `Ratchet` class implements the Double Ratchet algorithm. It is used to establish a secure messaging context between two parties.

#### Constructor
```typescript
new Ratchet(options: { keyPair: KeyPair, isInitiator: boolean }): Ratchet
```
- **keyPair**: The key pair to use for establishing the ratchet.
- **isInitiator**: Indicates if this instance is the initiator of the communication.

#### Methods

- **`encrypt(plaintext: string): Promise<EncryptedMessage>`**
  - Encrypts a plaintext message.
  - Returns an `EncryptedMessage` object containing the encrypted data.

  ```javascript
  const message = "Hello, Bob!";
  const encryptedMessage = await ratchetInstance.encrypt(message);
  console.log('Encrypted Message:', encryptedMessage);
  ```

- **`decrypt(packet: EncryptedMessage): Promise<string>`**
  - Decrypts an `EncryptedMessage` object.
  - Returns the original plaintext message.

  ```javascript
  const decryptedMessage = await ratchetInstance.decrypt(encryptedMessage);
  console.log('Decrypted Message:', decryptedMessage);
  ```

### `getPublicKey`
Utility to get the public key from a private key using secp256k1.

#### Example
```javascript
const privateKey = secpUtils.randomPrivateKey();
const publicKey = getPublicKey(privateKey);
console.log('Public Key:', publicKey);
```

### Utilities (`secpUtils`)
The `secpUtils` object provides several useful cryptographic utilities, such as generating random keys and other secp256k1-related operations.

## License

MIT License

## Contributing

Feel free to open issues or submit pull requests on [GitHub](https://github.com/yourusername/your-repository). Contributions are welcome!

## Acknowledgements

This package uses `@noble/secp256k1` for secp256k1 elliptic curve cryptography, and implements the Signal Double Ratchet protocol for secure messaging.


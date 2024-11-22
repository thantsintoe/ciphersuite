import { getPublicKey, utils as secpUtils } from "https://esm.sh/@noble/secp256k1";
import { Ratchet } from '../dist/core/signal'; // Adjust the path if necessary

// Generate a keypair
async function generateKeyPair() {
    const privateKey = secpUtils.randomPrivateKey();
    const publicKey = getPublicKey(privateKey, true);
    return { privateKey, publicKey };
}

// Example of using Ratchet
async function demoRatchet() {
    // Generate key pairs for two parties (Alice and Bob)
    const aliceKeyPair = await generateKeyPair();
    const bobKeyPair = await generateKeyPair();

    // Initialize Ratchet instances
    const aliceRatchet = new Ratchet({ keyPair: aliceKeyPair, isInitiator: true });
    const bobRatchet = new Ratchet({ keyPair: bobKeyPair, isInitiator: false });

    // Exchange public keys to initialize
    await aliceRatchet.initialize(bobKeyPair.publicKey);
    await bobRatchet.initialize(aliceKeyPair.publicKey);

    // Alice encrypts a message
    const plaintext = 'Hello, Bob!';
    const encryptedMessage = await aliceRatchet.encrypt(plaintext);
    console.log('Encrypted Message:', encryptedMessage);

    // Bob decrypts the message
    const decryptedMessage = await bobRatchet.decrypt(encryptedMessage);
    console.log('Decrypted Message:', decryptedMessage);

    // Display results in the browser
    document.getElementById('output').textContent = `
        Encrypted: ${JSON.stringify(encryptedMessage)}
        Decrypted: ${decryptedMessage}
    `;
}

demoRatchet().catch(console.error);

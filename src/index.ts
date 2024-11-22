// src/index.ts

// Export the Ratchet class
export { Ratchet } from './core/signal';

// Import and re-export utilities from @noble/secp256k1
import { getPublicKey, utils as secpUtils } from '@noble/secp256k1';

export { getPublicKey, secpUtils };

# A-MACI Key Management Tool - Technical Overview

## Project Overview

The A-MACI Key Management Tool is a client-side application designed to facilitate secure EdDSA (Edwards-curve Digital Signature Algorithm) keypair management for the Anonymous Minimal Anti-Collusion Infrastructure (A-MACI) voting system. It implements the Ed25519 curve specification for high-security cryptographic operations while maintaining a zero-trust architecture where all cryptographic operations occur client-side.

## Technical Foundation

### Cryptographic Implementation
The system utilizes the Ed25519 curve implementation, which provides:
- 32-byte private keys offering 256 bits of security
- 32-byte public keys derived through scalar multiplication
- 64-byte deterministic signatures
- SHA-512 hashing for message preprocessing
- Curve25519 as the underlying elliptic curve

### Architecture Design

The application follows a stateful component architecture implementing:

1. **Key Management Layer**
   - Secure key generation using cryptographically secure random number generation (CSPRNG)
   - Private key encryption in memory
   - Public key derivation and validation
   - Key storage abstraction through browser's localStorage

2. **Cryptographic Operations Layer**
   - Message signing using EdDSA
   - Signature verification
   - Key validation and verification
   - Binary-to-hex conversions for key representation

3. **Data Persistence Layer**
   - Encrypted local storage implementation
   - Backup and restore functionality
   - Import/export capabilities with validation

## Core Functionalities

### 1. Key Generation
```typescript
const generateKeyPair = async (): Promise<KeyPair> => {
  const privateBytes = randomBytes(32);
  const publicKeyBytes = await ed.getPublicKey(privateBytes);
  return {
    privateKey: bytesToHex(privateBytes),
    publicKey: bytesToHex(publicKeyBytes)
  };
};
```

### 2. Message Signing
The signing process follows the EdDSA specification:
1. SHA-512 hashing of the private key
2. Key bit clamping
3. Scalar multiplication for R value
4. SHA-512 hashing of R || PK || M
5. Final signature computation

### 3. Signature Verification
Implements batch verification optimization:
```typescript
const verifySignature = async (
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array
): Promise<boolean> => {
  return await ed.verify(signature, message, publicKey);
};
```

## Security Considerations

### 1. Zero-Trust Model
- All cryptographic operations performed client-side
- No server communication for sensitive operations
- No private key transmission

### 2. Key Security
- Private keys never leave the client
- Implementation of secure key deletion
- Memory cleanup after operations
- Key encryption at rest

### 3. Validation Mechanisms
- Public key derivation verification
- Signature validation before storage
- Import format validation
- Cryptographic operation validation

## Technical Specifications

### Development Stack
- React 18+ with TypeScript
- noble-ed25519 for EdDSA operations
- shadcn/ui for component architecture
- Browser's Web Crypto API for random number generation

### State Management
```typescript
interface ApplicationState {
  keys: KeyPair[];
  selectedKey: KeyPair | null;
  signatures: SignatureRecord[];
  operationStatus: OperationStatus;
}
```

### Data Flow
1. User Input → Validation Layer
2. Validation Layer → Cryptographic Layer
3. Cryptographic Layer → State Management
4. State Management → Persistence Layer
5. State Management → UI Layer

### Performance Optimizations
- Lazy loading of cryptographic operations
- Memoized key derivation
- Batch signature verification
- Optimized state updates

## Integration with A-MACI

### Key Format Compatibility
- EdDSA key format matching A-MACI requirements
- Standardized signature format
- Compatible export formats

### Voting System Integration
- Message signing for vote casting
- Key validation for participation
- Signature verification for vote validation

This implementation provides a secure, efficient, and user-friendly interface for managing cryptographic keys in the A-MACI ecosystem while maintaining high security standards and following cryptographic best practices.
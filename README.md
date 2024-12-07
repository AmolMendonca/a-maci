# Technical Documentation - A-MACI Key Management Tool

## Technical Architecture

### Cryptographic Implementation

#### EdDSA (Ed25519)
- Uses the Ed25519 curve implementation from @noble/ed25519
- Key generation using cryptographically secure random bytes
- SHA-512 for message hashing
- 32-byte private keys
- 32-byte public keys
- 64-byte signatures

```typescript
// Key Generation Process
const privateBytes = randomBytes(32);
const privateKey = bytesToHex(privateBytes);
const publicKeyBytes = await ed.getPublicKey(privateBytes);
const publicKey = bytesToHex(publicKeyBytes);
```

### Data Structures

#### KeyPair Interface
```typescript
interface KeyPair {
  id: number;            // Unique identifier (timestamp)
  publicKey: string;     // Hex-encoded public key
  privateKey: string;    // Hex-encoded private key
  createdAt: string;     // ISO timestamp
  name: string;          // User-defined name
  description?: string;  // Optional description
  lastUsed?: string;     // Last usage timestamp
}
```

#### SignedMessage Interface
```typescript
interface SignedMessage {
  message: string;    // Original message
  signature: string;  // Hex-encoded signature
  timestamp: string;  // Signing timestamp
  keyId: number;      // Reference to signing key
}
```

### State Management

Core state variables:
```typescript
const [keys, setKeys] = useState<KeyPair[]>([]);
const [selectedKeyIndex, setSelectedKeyIndex] = useState<number | null>(null);
const [signedMessages, setSignedMessages] = useState<SignedMessage[]>([]);
```

### Storage Implementation

#### Local Storage Schema
```typescript
{
  'amaci-keys': string,       // JSON stringified KeyPair[]
  'last-backup-date': string  // ISO timestamp
}
```

### Core Operations

#### Message Signing
```typescript
const signMessage = async (message: string, keyPair: KeyPair) => {
  const messageBytes = new TextEncoder().encode(message);
  const privateBytes = hexToBytes(keyPair.privateKey);
  const signatureBytes = await ed.sign(messageBytes, privateBytes);
  return bytesToHex(signatureBytes);
};
```

#### Signature Verification
```typescript
const verifySignature = async (
  message: string,
  signature: string,
  publicKey: string
) => {
  const messageBytes = new TextEncoder().encode(message);
  const signatureBytes = hexToBytes(signature);
  const publicKeyBytes = hexToBytes(publicKey);
  return await ed.verify(signatureBytes, messageBytes, publicKeyBytes);
};
```

### Security Measures

#### Key Validation
- Cryptographic validation of imported keys
- Public key derivation check
- Duplicate key detection
```typescript
const validateKeyPair = async (privateKey: string, publicKey: string) => {
  const privateBytes = hexToBytes(privateKey);
  const derivedPublicKey = bytesToHex(await ed.getPublicKey(privateBytes));
  return derivedPublicKey === publicKey;
};
```

#### Data Integrity
- Validation of backup file format
- Signature verification before storage
- Error handling for malformed data

### Error Handling

Comprehensive error handling system:
```typescript
try {
  // Operation
} catch (err) {
  const errorMessage = err instanceof Error 
    ? err.message 
    : 'Unknown error occurred';
  setError(`Operation failed: ${errorMessage}`);
}
```

### Component Architecture

```
KeyManagementTool
├── ErrorAlert
├── BackupReminder
├── KeyGenerationForm
├── KeyList
│   └── KeyCard
│       ├── KeyInfo
│       ├── PublicKeyDisplay
│       └── PrivateKeyDisplay
└── SigningSection
    ├── MessageSigning
    └── SignatureVerification
```

### Performance Considerations

1. **Optimization Techniques**
   - Memoization of filtered keys
   - Debounced search
   - Lazy loading of crypto operations

2. **State Updates**
   - Batch updates for related state changes
   - Optimistic updates for UI responsiveness

### Integration Points

1. **A-MACI System Integration**
   - Compatible key format
   - Standard EdDSA implementation
   - Exportable signatures

2. **Browser Integration**
   - Local storage management
   - Clipboard API usage
   - File system access

### Dependencies

```json
{
  "@noble/ed25519": "^2.0.0",
  "@noble/hashes": "^1.3.2",
  "lucide-react": "^0.263.1",
  "@radix-ui/react-alert-dialog": "^1.0.5",
  "class-variance-authority": "^0.7.0"
}
```

### Build and Deployment

#### Development
```bash
npm run dev
# Runs on http://localhost:3000
```

#### Production Build
```bash
npm run build
npm run start
```

### Testing Considerations

1. **Unit Tests**
   - Cryptographic operations
   - Key validation
   - State management
   - Error handling

2. **Integration Tests**
   - Key generation flow
   - Import/export functionality
   - Signing/verification flow

3. **Security Tests**
   - Key storage security
   - Input validation
   - Error handling
   - Cryptographic implementation
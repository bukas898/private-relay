# Privacy-First Encrypted Web3 Messaging Protocol

A decentralized, end-to-end encrypted messaging system built on the Stacks blockchain using Clarity smart contracts. This protocol prioritizes user privacy, forward secrecy, and anonymous communication capabilities.

## 🔐 Key Features

### Core Privacy Features
- **End-to-End Encryption**: Messages are encrypted client-side before being stored on-chain
- **Perfect Forward Secrecy**: Ephemeral key exchanges ensure past messages remain secure even if keys are compromised
- **Anonymous Messaging**: Support for anonymous message drops without revealing sender/recipient identities
- **Self-Destructing Messages**: Ephemeral messages that automatically delete after being read
- **Privacy-Preserving Metadata**: Minimal metadata exposure with hashed identifiers

### Security Features
- **Dual Key System**: Separate encryption and signing keys for enhanced security
- **Message Integrity**: Content hashing ensures messages haven't been tampered with
- **Access Control**: Only authorized parties can access their messages
- **Expiring Messages**: Time-based message expiration for sensitive communications
- **Zero-Knowledge Ready**: Framework prepared for future ZK-proof integration

## 🏗️ Protocol Architecture

### Data Structures

#### User Key Registry
```clarity
user-public-keys: {
  encryption-key: (buff 33),    // Secp256k1 public key for encryption
  signing-key: (buff 33),       // Separate key for signatures
  key-version: uint,
  created-at: uint,
  last-updated: uint
}
```

#### Encrypted Messages
```clarity
encrypted-messages: {
  sender: principal,
  recipient: principal,
  encrypted-content: (buff 256),     // Encrypted message content
  encrypted-key: (buff 64),          // Encrypted symmetric key
  nonce: (buff 24),                  // Encryption nonce
  signature: (buff 65),              // Message signature
  content-hash: (buff 32),           // Hash for integrity
  timestamp: uint,
  expires-at: (optional uint),
  ephemeral: bool                    // Auto-delete after reading
}
```

#### Anonymous Drops
```clarity
anonymous-drops: {
  encrypted-payload: (buff 512),
  access-key-hash: (buff 32),
  created-at: uint,
  expires-at: uint,
  accessed: bool
}
```

## 🚀 Getting Started

### Prerequisites
- Stacks blockchain node or access to a Stacks API
- Clarity development environment
- Client-side encryption library (e.g., libsodium, tweetnacl)

### Deployment
1. Deploy the smart contract to the Stacks blockchain
2. Implement client-side encryption/decryption logic
3. Set up key management system

### Basic Usage Flow

#### 1. Register Your Keys
```clarity
(contract-call? .messaging-protocol register-keys encryption-key signing-key)
```

#### 2. Send an Encrypted Message
```clarity
(contract-call? .messaging-protocol send-encrypted
  recipient
  encrypted-content
  encrypted-key
  nonce
  signature
  content-hash
  (some expires-at)
  false)  // not ephemeral
```

#### 3. Retrieve Messages
```clarity
(contract-call? .messaging-protocol get-encrypted-message message-id)
```

## 📋 API Reference

### Public Functions

#### `register-keys`
Register encryption and signing keys for a user.
- **Parameters**: `encryption-key (buff 33)`, `signing-key (buff 33)`
- **Returns**: `(response bool uint)`

#### `send-encrypted`
Send an encrypted message to a recipient.
- **Parameters**: 
  - `recipient (principal)`
  - `encrypted-content (buff 256)`
  - `encrypted-key (buff 64)`
  - `nonce (buff 24)`
  - `signature (buff 65)`
  - `content-hash (buff 32)`
  - `expires-at (optional uint)`
  - `ephemeral (bool)`
- **Returns**: `(response uint uint)` - message ID on success

#### `initiate-key-exchange`
Start a key exchange for perfect forward secrecy.
- **Parameters**: 
  - `recipient (principal)`
  - `ephemeral-key (buff 33)`
  - `encrypted-session-key (buff 64)`
- **Returns**: `(response uint uint)` - exchange ID on success

#### `accept-key-exchange`
Accept a pending key exchange request.
- **Parameters**: `exchange-id (uint)`
- **Returns**: `(response bool uint)`

#### `create-anonymous-drop`
Create an anonymous message drop.
- **Parameters**:
  - `drop-id (buff 32)`
  - `encrypted-payload (buff 512)`
  - `access-key-hash (buff 32)`
  - `ttl-blocks (uint)`
- **Returns**: `(response bool uint)`

#### `access-anonymous-drop`
Access an anonymous message drop with the correct key.
- **Parameters**: `drop-id (buff 32)`, `access-key (buff 32)`
- **Returns**: `(response (buff 512) uint)` - encrypted payload on success

#### `self-destruct-message`
Delete an ephemeral message after reading.
- **Parameters**: `message-id (uint)`
- **Returns**: `(response bool uint)`

#### `mark-read-private`
Mark a message as read while preserving privacy.
- **Parameters**: `message-id (uint)`
- **Returns**: `(response bool uint)`

### Read-Only Functions

#### `get-public-keys`
Retrieve public keys for a user.
- **Parameters**: `user (principal)`
- **Returns**: `(optional {...})`

#### `get-encrypted-message`
Get encrypted message (only for sender/recipient).
- **Parameters**: `message-id (uint)`
- **Returns**: `(optional {...})`

#### `has-active-keys`
Check if a user has registered keys.
- **Parameters**: `user (principal)`
- **Returns**: `bool`

## 🔒 Security Considerations

### Client-Side Responsibilities
- **Key Generation**: Generate cryptographically secure key pairs
- **Encryption**: Encrypt messages before sending to the contract
- **Key Management**: Securely store and manage private keys
- **Signature Verification**: Verify message signatures on receipt

### Recommended Encryption Flow
1. Generate ephemeral symmetric key for each message
2. Encrypt message content with symmetric key
3. Encrypt symmetric key with recipient's public key
4. Sign the encrypted content
5. Submit to smart contract

### Privacy Best Practices
- Use different key pairs for different conversations
- Rotate keys regularly
- Use ephemeral messages for sensitive communications
- Leverage anonymous drops for whistleblowing scenarios

## 🔮 Future Enhancements

### Planned Features
- **Zero-Knowledge Proofs**: Anonymous authentication and message verification
- **Group Messaging**: Encrypted group communications
- **Message Threading**: Conversation threading while maintaining privacy
- **Cross-Chain Integration**: Interoperability with other blockchains
- **Decentralized File Sharing**: Encrypted file attachments

### ZK-Proof Integration
The protocol includes a placeholder for zero-knowledge proof verification:
```clarity
zk-proofs: {
  prover: principal,
  proof-type: (string-ascii 20),
  proof-data: (buff 128),
  verified: bool,
  created-at: uint
}
```

## 🤝 Contributing

Contributions are welcome! Please ensure all contributions maintain the privacy-first principles of this protocol.

### Development Guidelines
- All new features must preserve user privacy
- Minimize on-chain metadata exposure
- Implement proper access controls
- Include comprehensive tests
- Document security implications

## 📄 License

This project is open source. Please ensure compliance with local privacy and encryption regulations.

## ⚠️ Disclaimer

This is experimental software. Use at your own risk. Always audit smart contracts before deploying to mainnet. The authors are not responsible for any loss of funds or privacy breaches.

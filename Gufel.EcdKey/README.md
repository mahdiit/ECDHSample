# Gufel.EcdKey - Elliptic Curve Cryptography Library

A comprehensive .NET library for Elliptic Curve Diffie-Hellman (ECDH) key exchange, encryption/decryption, and digital signatures using Elliptic Curve Digital Signature Algorithm (ECDSA).

## Features

- **🔐 ECDH Key Exchange**: Secure key exchange using Elliptic Curve Diffie-Hellman
- **🔒 AES-GCM Encryption**: Authenticated encryption using derived shared keys
- **✍️ Digital Signatures**: Sign and verify data using ECDSA
- **📄 JSON Serialization**: URL-safe Base64 encoding for easy storage and transmission
- **🛡️ NIST P-256 Curve**: Uses the secure NIST P-256 elliptic curve
- **♻️ IDisposable**: Proper resource management for cryptographic keys

## Installation

Add the `Gufel.EcdKey` project to your solution or build it as a NuGet package.

```bash
dotnet add package Gufel.EcdKey
```

## Quick Start

### Basic Key Exchange and Encryption

```csharp
using Gufel.EcdKey;

// Create key pairs for Alice (sender) and Bob (receiver)
using var alice = EcdExchangeKey.Create();
using var bob = EcdExchangeKey.Create();

// Alice encrypts a message for Bob
var encrypted = EcdExchangeKey.EncryptString("Hello, Bob!", alice, bob);

// Bob decrypts the message from Alice
var decrypted = EcdExchangeKey.DecryptString(encrypted, alice, bob);
Console.WriteLine(decrypted); // Output: "Hello, Bob!"
```

### Digital Signatures

```csharp
using Gufel.EcdKey;

// Create signing key pair
using var signingKey = EcdSignKey.Create();

// Sign data
var data = "Important message";
var signature = EcdSignKey.SignData(data, signingKey);

// Verify signature
var isValid = EcdSignKey.VerifyData(data, signature, signingKey);
Console.WriteLine($"Signature valid: {isValid}"); // Output: "Signature valid: True"
```

## Core Classes

### EcdExchangeKey

Handles ECDH key exchange and encryption/decryption operations.

#### Key Creation

```csharp
// Generate new key pair
using var keyPair = EcdExchangeKey.Create();

// Create from existing private key
var privateKeyBytes = /* your private key bytes */;
using var privateKey = EcdExchangeKey.CreateFromPrivateKey(privateKeyBytes);

// Create from existing public key
var publicKeyBytes = /* your public key bytes */;
using var publicKey = EcdExchangeKey.CreateFromPublicKey(publicKeyBytes);

// Create from JSON
var jsonKey = /* JSON string */;
using var keyFromJson = EcdExchangeKey.CreateFromJson(jsonKey);
```

#### Encryption/Decryption

```csharp
using var sender = EcdExchangeKey.Create();
using var receiver = EcdExchangeKey.Create();

// Encrypt string
var encrypted = EcdExchangeKey.EncryptString("Secret message", sender, receiver);

// Encrypt byte array
byte[] data = Encoding.UTF8.GetBytes("Secret data");
var encryptedBytes = EcdExchangeKey.Encrypt(data, sender, receiver);

// Decrypt
var decryptedString = EcdExchangeKey.DecryptString(encrypted, sender, receiver);
var decryptedBytes = EcdExchangeKey.Decrypt(encryptedBytes, sender, receiver);
```

### EcdSignKey

Handles ECDSA digital signatures.

#### Key Creation

```csharp
// Generate new signing key pair
using var signingKey = EcdSignKey.Create();

// Create from existing keys
using var privateSignKey = EcdSignKey.CreateFromPrivateKey(privateKeyBytes);
using var publicSignKey = EcdSignKey.CreateFromPublicKey(publicKeyBytes);

// Create from JSON
using var signKeyFromJson = EcdSignKey.CreateFromJson(jsonString);
```

#### Signing and Verification

```csharp
using var signingKey = EcdSignKey.Create();

// Sign string data
var signature1 = EcdSignKey.SignData("Message to sign", signingKey);

// Sign byte array
byte[] dataToSign = Encoding.UTF8.GetBytes("Data to sign");
var signature2 = EcdSignKey.SignData(dataToSign, signingKey);

// Verify signatures
bool isValid1 = EcdSignKey.VerifyData("Message to sign", signature1, signingKey);
bool isValid2 = EcdSignKey.VerifyData(dataToSign, signature2, signingKey);
```

### EcdEncryptDto

Container for encrypted data with nonce and authentication tag.

```csharp
// Encryption returns EcdEncryptDto
var encrypted = EcdExchangeKey.EncryptString("Hello", sender, receiver);

// Serialize to JSON
string json = encrypted.ToJson();

// Deserialize from JSON
var encryptedFromJson = EcdEncryptDto.CreateFromJson(json);

// Access components
byte[] nonce = encrypted.Nonce;     // 12-byte nonce
byte[] cipher = encrypted.Cipher;   // Encrypted data
byte[] tag = encrypted.Tag;         // 16-byte authentication tag
```

## Complete Example

Here's a comprehensive example demonstrating key exchange, encryption, and signing:

```csharp
using Gufel.EcdKey;
using System.Text;

class Program
{
    static void Main()
    {
        // === Key Exchange and Encryption ===
        Console.WriteLine("=== ECDH Key Exchange and Encryption ===");
        
        // Alice and Bob generate their key pairs
        using var alice = EcdExchangeKey.Create();
        using var bob = EcdExchangeKey.Create();
        
        Console.WriteLine($"Alice key type: {alice.KeyType}");
        Console.WriteLine($"Bob key type: {bob.KeyType}");
        
        // Save keys to JSON (for persistence/transmission)
        string aliceJson = alice.ToJson();
        string bobJson = bob.ToJson();
        File.WriteAllText("alice-key.json", aliceJson);
        File.WriteAllText("bob-key.json", bobJson);
        
        // Alice encrypts a message for Bob
        string message = "Hello Bob, this is a secret message!";
        var encrypted = EcdExchangeKey.EncryptString(message, alice, bob);
        
        // Serialize encrypted data
        string encryptedJson = encrypted.ToJson();
        Console.WriteLine($"Encrypted data: {encryptedJson}");
        
        // Bob decrypts the message from Alice
        var decrypted = EcdExchangeKey.DecryptString(encrypted, alice, bob);
        Console.WriteLine($"Decrypted message: {decrypted}");
        
        // === Digital Signatures ===
        Console.WriteLine("\n=== Digital Signatures ===");
        
        // Alice creates a signing key
        using var aliceSignKey = EcdSignKey.Create();
        
        // Alice signs the message
        var signature = EcdSignKey.SignData(message, aliceSignKey);
        Console.WriteLine($"Signature length: {signature.Length} bytes");
        
        // Bob verifies Alice's signature (using Alice's public key)
        using var alicePublicSignKey = EcdSignKey.CreateFromPublicKey(aliceSignKey.PublicKey!);
        bool isValid = EcdSignKey.VerifyData(message, signature, alicePublicSignKey);
        Console.WriteLine($"Signature verification: {isValid}");
        
        // === Combined: Encrypt + Sign ===
        Console.WriteLine("\n=== Combined: Encryption with Signature ===");
        
        // Alice encrypts and signs
        var encryptedMessage = EcdExchangeKey.EncryptString(message, alice, bob);
        var messageSignature = EcdSignKey.SignData(message, aliceSignKey);
        
        // Bob decrypts and verifies
        var decryptedMessage = EcdExchangeKey.DecryptString(encryptedMessage, alice, bob);
        bool signatureValid = EcdSignKey.VerifyData(decryptedMessage, messageSignature, alicePublicSignKey);
        
        Console.WriteLine($"Decrypted: {decryptedMessage}");
        Console.WriteLine($"Signature valid: {signatureValid}");
        
        Console.WriteLine("\nPress any key to exit...");
        Console.ReadKey();
    }
}
```

## Key Management Best Practices

### 1. Key Storage

```csharp
// Save keys securely
using var keyPair = EcdExchangeKey.Create();
string keyJson = keyPair.ToJson();

// Store in secure location (encrypted storage recommended)
File.WriteAllText("secure-path/private-key.json", keyJson);

// Load keys
string storedKey = File.ReadAllText("secure-path/private-key.json");
using var loadedKey = EcdExchangeKey.CreateFromJson(storedKey);
```

### 2. Public Key Distribution

```csharp
// Extract public key for sharing
using var keyPair = EcdExchangeKey.Create();
using var publicOnlyKey = EcdExchangeKey.CreateFromPublicKey(keyPair.PublicKey!);

// Share public key JSON safely
string publicKeyJson = publicOnlyKey.ToJson();
```

### 3. Key Types

```csharp
// Check key capabilities
using var key = EcdExchangeKey.Create();

switch (key.KeyType)
{
    case EcdKeyType.PublicAndPrivate:
        Console.WriteLine("Can encrypt, decrypt, and derive shared keys");
        break;
    case EcdKeyType.Public:
        Console.WriteLine("Can only encrypt and verify");
        break;
    case EcdKeyType.Private:
        Console.WriteLine("Can only decrypt and sign");
        break;
}
```

## Security Considerations

1. **Key Management**: Always dispose of keys properly using `using` statements
2. **Private Key Protection**: Never share private keys; only distribute public keys
3. **Secure Storage**: Store private keys in encrypted form
4. **Nonce Uniqueness**: The library automatically generates unique nonces for each encryption
5. **Curve Security**: Uses NIST P-256, a widely accepted and secure elliptic curve
6. **Authentication**: AES-GCM provides both encryption and authentication

## API Reference

### EcdExchangeKey Methods

| Method | Description |
|--------|-------------|
| `Create()` | Generate new key pair |
| `CreateFromPrivateKey(byte[])` | Create from private key |
| `CreateFromPublicKey(byte[])` | Create from public key |
| `CreateFromJson(string)` | Create from JSON |
| `EncryptString(string, EcdExchangeKey, EcdExchangeKey)` | Encrypt string |
| `Encrypt(ReadOnlySpan<byte>, EcdExchangeKey, EcdExchangeKey)` | Encrypt bytes |
| `DecryptString(EcdEncryptDto, EcdExchangeKey, EcdExchangeKey)` | Decrypt to string |
| `Decrypt(EcdEncryptDto, EcdExchangeKey, EcdExchangeKey)` | Decrypt to bytes |
| `ToJson()` | Serialize to JSON |

### EcdSignKey Methods

| Method | Description |
|--------|-------------|
| `Create()` | Generate new signing key pair |
| `CreateFromPrivateKey(byte[])` | Create from private key |
| `CreateFromPublicKey(byte[])` | Create from public key |
| `CreateFromJson(string)` | Create from JSON |
| `SignData(string, EcdSignKey)` | Sign string data |
| `SignData(ReadOnlySpan<byte>, EcdSignKey)` | Sign byte data |
| `VerifyData(string, ReadOnlySpan<byte>, EcdSignKey)` | Verify string signature |
| `VerifyData(ReadOnlySpan<byte>, ReadOnlySpan<byte>, EcdSignKey)` | Verify byte signature |
| `ToJson()` | Serialize to JSON |

## Requirements

- .NET 9.0 or later
- System.Security.Cryptography
- System.Text.Json

## License

[Add your license information here]

## Contributing

[Add contributing guidelines here]

## Support

[Add support information here]
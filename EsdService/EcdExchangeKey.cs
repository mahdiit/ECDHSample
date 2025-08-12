using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace EcdService;

public sealed class EcdExchangeKey : EcdKey, IDisposable
{
    private EcdExchangeKey(ECDiffieHellman key, EcdKeyType keyType)
        : base(
            keyType is EcdKeyType.Private or EcdKeyType.PublicAndPrivate ? key.ExportPkcs8PrivateKey() : null,
            keyType is EcdKeyType.Public or EcdKeyType.PublicAndPrivate ? key.ExportSubjectPublicKeyInfo() : null
            )
    {
        Key = key;
    }

    [JsonIgnore]
    private ECDiffieHellman Key { get; }

    public void Dispose()
    {
        Key.Dispose();
    }

    public string ToJson()
    {
        return JsonSerializer.Serialize(this, EcdTools.KeyJsonOption);
    }

    public static EcdExchangeKey Create(byte[]? publicKey = null, byte[]? privateKey = null)
    {
        if (privateKey != null)
        {
            var key = ECDiffieHellman.Create();
            key.ImportPkcs8PrivateKey(privateKey, out _);
            return new EcdExchangeKey(key, EcdKeyType.Private);
        }

        if (publicKey != null)
        {
            var key = ECDiffieHellman.Create();
            key.ImportSubjectPublicKeyInfo(publicKey, out _);
            return new EcdExchangeKey(key, EcdKeyType.Public);
        }

        return new EcdExchangeKey(ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256), EcdKeyType.PublicAndPrivate);
    }

    public static EcdExchangeKey CreateFromPrivateKey(byte[] privateKey)
    {
        return Create(null, privateKey);
    }

    public static EcdExchangeKey CreateFromPublicKey(byte[] publicKey)
    {
        return Create(publicKey, null);
    }

    public static EcdExchangeKey CreateFromJson(string jsonKey)
    {
        var ecdKey = JsonSerializer.Deserialize<EcdKey>(jsonKey, EcdTools.KeyJsonOption);

        if (ecdKey == null)
            throw new InvalidOperationException("Cannot deserialize key");

        return Create(ecdKey.PublicKey, ecdKey.PrivateKey);
    }

    public static EcdEncryptDto Encrypt(ReadOnlySpan<byte> data, EcdExchangeKey senderKey, EcdExchangeKey receiverKey)
    {
        if (senderKey.PrivateKey == null)
            throw new ArgumentNullException(nameof(senderKey.PrivateKey),
                "Sender private key can not be null for encryption");

        if (receiverKey.PublicKey == null)
            throw new ArgumentNullException(nameof(receiverKey.PublicKey),
                "Receiver public key can not be null for encryption");

        var sharedKey = senderKey.Key.DeriveKeyMaterial(receiverKey.Key.PublicKey);
        var result = new EcdEncryptDto(data.Length);

        using var aes = new AesGcm(sharedKey, result.Tag.Length);
        aes.Encrypt(result.Nonce, data, result.Cipher, result.Tag);

        return result;
    }

    public static EcdEncryptDto EncryptString(string data, EcdExchangeKey senderKey, EcdExchangeKey receiverKey)
    {
        var dataByte = Encoding.UTF8.GetBytes(data);
        return Encrypt(dataByte, senderKey, receiverKey);
    }

    public static ReadOnlySpan<byte> Decrypt(EcdEncryptDto encrypt, EcdExchangeKey senderKey, EcdExchangeKey receiverKey)
    {
        if (senderKey.PublicKey == null)
            throw new ArgumentNullException(nameof(senderKey.PublicKey),
                "Sender public key can not be null for decryption");

        if (receiverKey.PrivateKey == null)
            throw new ArgumentNullException(nameof(receiverKey.PrivateKey),
                "Receiver private key can not be null for decryption");

        var sharedKey = receiverKey.Key.DeriveKeyMaterial(senderKey.Key.PublicKey);
        var result = new byte[encrypt.Cipher.Length];

        using var aes = new AesGcm(sharedKey, encrypt.Tag.Length);
        aes.Decrypt(encrypt.Nonce, encrypt.Cipher, encrypt.Tag, result);

        return result;
    }

    public static string DecryptString(EcdEncryptDto encrypt, EcdExchangeKey senderKey, EcdExchangeKey receiverKey)
    {
        var decrypted = Decrypt(encrypt, senderKey, receiverKey);
        return Encoding.UTF8.GetString(decrypted);
    }
}
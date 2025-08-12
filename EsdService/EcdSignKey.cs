using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace EcdService;

public sealed class EcdSignKey : EcdKey, IDisposable
{
    private EcdSignKey(ECDsa key, EcdKeyType keyType)
        : base(
            keyType is EcdKeyType.Private or EcdKeyType.PublicAndPrivate ? key.ExportPkcs8PrivateKey() : null,
            keyType is EcdKeyType.Public or EcdKeyType.PublicAndPrivate ? key.ExportSubjectPublicKeyInfo() : null
        )
    {
        Key = key;
    }

    [JsonIgnore]
    private ECDsa Key { get; }

    public void Dispose()
    {
        Key.Dispose();
    }

    public string ToJson()
    {
        return JsonSerializer.Serialize(this, EcdTools.KeyJsonOption);
    }

    public static EcdSignKey Create(byte[]? publicKey = null, byte[]? privateKey = null)
    {
        if (privateKey != null)
        {
            var key = ECDsa.Create();
            key.ImportPkcs8PrivateKey(privateKey, out _);
            return new EcdSignKey(key, EcdKeyType.Private);
        }

        if (publicKey != null)
        {
            var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(publicKey, out _);
            return new EcdSignKey(key, EcdKeyType.Public);
        }

        return new EcdSignKey(ECDsa.Create(ECCurve.NamedCurves.nistP256), EcdKeyType.PublicAndPrivate);
    }

    public static EcdSignKey CreateFromPrivateKey(byte[] privateKey)
    {
        return Create(null, privateKey);
    }

    public static EcdSignKey CreateFromPublicKey(byte[] publicKey)
    {
        return Create(publicKey, null);
    }

    public static EcdSignKey CreateFromJson(string jsonKey)
    {
        var ecdKey = JsonSerializer.Deserialize<EcdKey>(jsonKey, EcdTools.KeyJsonOption);

        if (ecdKey == null)
            throw new InvalidOperationException("Cannot deserialize key");

        return Create(ecdKey.PublicKey, ecdKey.PrivateKey);
    }

    public static ReadOnlySpan<byte> SignData(string data, EcdSignKey senderKey)
    {
        return SignData(Encoding.UTF8.GetBytes(data), senderKey);
    }

    public static ReadOnlySpan<byte> SignData(ReadOnlySpan<byte> data, EcdSignKey senderKey)
    {
        if (senderKey.PrivateKey == null)
            throw new ArgumentNullException(nameof(senderKey.PrivateKey), "Sender private key can not be null for sign");

        return senderKey.Key.SignData(data, HashAlgorithmName.SHA256);
    }

    public static bool VerifyData(string data, ReadOnlySpan<byte> signData, EcdSignKey senderKey)
    {
        return VerifyData(Encoding.UTF8.GetBytes(data), signData, senderKey);
    }

    public static bool VerifyData(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signData, EcdSignKey senderKey)
    {
        if (senderKey.PublicKey == null)
            throw new ArgumentNullException(nameof(senderKey.PublicKey), "Sender public key can not be null for verify");

        return senderKey.Key.VerifyData(data, signData, HashAlgorithmName.SHA256);
    }
}
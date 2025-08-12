using System.Security.Cryptography;
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
    public ECDiffieHellman Key { get; }

    public void Dispose()
    {
        Key.Dispose();
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

    public static EcdExchangeKey CreatePrivateKey(byte[] privateKey)
    {
        return Create(null, privateKey);
    }

    public static EcdExchangeKey CreatePublicKey(byte[] publicKey)
    {
        return Create(publicKey, null);
    }
}
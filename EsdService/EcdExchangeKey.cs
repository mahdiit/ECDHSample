using System.Security.Cryptography;
using System.Text.Json.Serialization;

namespace EcdService;

public sealed class EcdExchangeKey : EsdKey, IDisposable
{
    private EcdExchangeKey(ECDiffieHellman key, EsdKeyType keyType)
        : base(
            keyType is EsdKeyType.Private or EsdKeyType.PublicAndPrivate ? key.ExportPkcs8PrivateKey() : null,
            keyType is EsdKeyType.Public or EsdKeyType.PublicAndPrivate ? key.ExportSubjectPublicKeyInfo() : null
            )
    {
        Key = key;
    }

    public EcdExchangeKey()
        : this(ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256), EsdKeyType.PublicAndPrivate)
    {

    }

    [JsonIgnore]
    public ECDiffieHellman Key { get; }

    public void Dispose()
    {
        Key.Dispose();
    }

    private static EcdExchangeKey Create(byte[]? publicKey, byte[]? privateKey)
    {
        if (privateKey != null)
        {
            var key = ECDiffieHellman.Create();
            key.ImportPkcs8PrivateKey(privateKey, out _);
            return new EcdExchangeKey(key, EsdKeyType.Private);
        }
        else if (publicKey != null)
        {
            var key = ECDiffieHellman.Create();
            key.ImportSubjectPublicKeyInfo(publicKey, out _);
            return new EcdExchangeKey(key, EsdKeyType.Public);
        }

        throw new ArgumentNullException(nameof(publicKey), "All key is empty, must provide public or private key");
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
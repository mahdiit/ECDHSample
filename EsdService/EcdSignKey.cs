using System.Security.Cryptography;
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
    public ECDsa Key { get; }

    public void Dispose()
    {
        Key.Dispose();
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

    public static EcdSignKey CreatePrivateKey(byte[] privateKey)
    {
        return Create(null, privateKey);
    }

    public static EcdSignKey CreatePublicKey(byte[] publicKey)
    {
        return Create(publicKey, null);
    }
}
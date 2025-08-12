using System.Security.Cryptography;
using System.Text.Json.Serialization;

namespace EcdService;

public sealed class EcdSignKey : EsdKey, IDisposable
{
    private EcdSignKey(ECDsa key, EsdKeyType keyType)
        : base(
            keyType is EsdKeyType.Private or EsdKeyType.PublicAndPrivate ? key.ExportPkcs8PrivateKey() : null,
            keyType is EsdKeyType.Public or EsdKeyType.PublicAndPrivate ? key.ExportSubjectPublicKeyInfo() : null
        )
    {
        Key = key;
    }

    public EcdSignKey()
        : this(ECDsa.Create(ECCurve.NamedCurves.nistP256), EsdKeyType.PublicAndPrivate)
    {

    }

    [JsonIgnore]
    public ECDsa Key { get; }

    public void Dispose()
    {
        Key.Dispose();
    }

    private static EcdSignKey Create(byte[]? publicKey, byte[]? privateKey)
    {
        if (privateKey != null)
        {
            var key = ECDsa.Create();
            key.ImportPkcs8PrivateKey(privateKey, out _);
            return new EcdSignKey(key, EsdKeyType.Private);
        }
        else if (publicKey != null)
        {
            var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(publicKey, out _);
            return new EcdSignKey(key, EsdKeyType.Public);
        }

        throw new ArgumentNullException(nameof(publicKey), "All key is empty, must provide public or private key");
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
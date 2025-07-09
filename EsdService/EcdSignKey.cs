using System.Security.Cryptography;
using System.Text.Json.Serialization;

namespace EcdService;

public sealed class EcdSignKey(ECDsa key) : EsdKey, IDisposable
{
    public EcdSignKey()
        : this(ECDsa.Create(ECCurve.NamedCurves.nistP256))
    {
        PrivateKey = Key.ExportPkcs8PrivateKey();
        PublicKey = Key.ExportSubjectPublicKeyInfo();
    }

    [JsonIgnore]
    public ECDsa Key { get; } = key;

    public void Dispose()
    {
        Key.Dispose();
    }

    private static EcdSignKey Create(byte[]? publicKey, byte[]? privateKey)
    {
        var key = ECDsa.Create();
        if (privateKey != null)
        {
            key.ImportPkcs8PrivateKey(privateKey, out _);
        }
        else if (publicKey != null)
        {
            key.ImportSubjectPublicKeyInfo(publicKey, out _);
        }
        return new EcdSignKey(key);
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
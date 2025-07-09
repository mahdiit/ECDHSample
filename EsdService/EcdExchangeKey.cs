using System.Security.Cryptography;
using System.Text.Json.Serialization;

namespace EcdService;

public sealed class EcdExchangeKey : EsdKey, IDisposable
{
    private EcdExchangeKey(ECDiffieHellman key)
    {
        Key = key;
        PrivateKey = Key.ExportPkcs8PrivateKey();
        PublicKey = Key.ExportSubjectPublicKeyInfo();
    }

    public EcdExchangeKey()
        : this(ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256))
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
        var key = ECDiffieHellman.Create();
        if (privateKey != null)
        {
            key.ImportPkcs8PrivateKey(privateKey, out _);
        }
        else if (publicKey != null)
        {
            key.ImportSubjectPublicKeyInfo(publicKey, out _);
        }
        return new EcdExchangeKey(key);
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
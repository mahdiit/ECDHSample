using System.Security.Cryptography;
using System.Text.Json.Serialization;

namespace ECDHSample;

public sealed class EcdExchangeKey(ECDiffieHellman key) : EsdKey, IDisposable
{
    public EcdExchangeKey()
        : this(ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256))
    {
        PrivateKey = Key.ExportPkcs8PrivateKey();
        PublicKey = Key.ExportSubjectPublicKeyInfo();
    }

    [JsonIgnore]
    public ECDiffieHellman Key { get; } = key;

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

public class EsdKey
{
    public byte[] PrivateKey { get; protected init; }
    public byte[] PublicKey { get; protected init; }
}
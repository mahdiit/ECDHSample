using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Gufel.EcdKey;

public sealed class EcdSignKey : EcdKey, IDisposable
{
    private EcdSignKey(ECDsa key, EcdKeyType keyType)
        : base(keyType)
    {
        Key = key;
    }

    [JsonIgnore]
    private ECDsa Key { get; }

    public void Dispose()
    {
        Key.Dispose();
    }

    public string ToJson(EcdKeyType keyType)
    {
        if (keyType == EcdKeyType.None)
            throw new InvalidOperationException("can not export data from key type");

        EcdKeyJsonModel? keyData = null;

        switch (KeyType)
        {
            case EcdKeyType.Private:
                {
                    var ecParams = Key.ExportParameters(true);
                    keyData = new EcdKeyJsonModel
                    {
                        Curve = ecParams.Curve.Oid.FriendlyName,
                        D = ecParams.D
                    };
                    break;
                }
            case EcdKeyType.Public:
                {
                    var ecParams = Key.ExportParameters(false);
                    keyData = new EcdKeyJsonModel
                    {
                        Curve = ecParams.Curve.Oid.FriendlyName,
                        X = ecParams.Q.X,
                        Y = ecParams.Q.Y
                    };
                    break;
                }
            case EcdKeyType.PublicAndPrivate:
                {
                    var ecParams = Key.ExportParameters(true);
                    keyData = new EcdKeyJsonModel
                    {
                        Curve = ecParams.Curve.Oid.FriendlyName,
                        D = ecParams.D,
                        X = ecParams.Q.X,
                        Y = ecParams.Q.Y
                    };
                    break;
                }
        }

        return JsonSerializer.Serialize(keyData, EcdTools.KeyJsonOption);
    }

    public static EcdSignKey Create()
    {
        return new EcdSignKey(ECDsa.Create(ECCurve.NamedCurves.nistP256), EcdKeyType.PublicAndPrivate);
    }

    public static EcdSignKey CreateFromJson(string jsonKey)
    {
        var ecdKey = JsonSerializer.Deserialize<EcdKeyJsonModel>(jsonKey, EcdTools.KeyJsonOption);

        if (ecdKey is null || string.IsNullOrEmpty(ecdKey.Curve))
            throw new InvalidOperationException("Cannot deserialize key");

        var loadedParams = new ECParameters
        {
            Curve = ECCurve.CreateFromFriendlyName(ecdKey.Curve),
            D = ecdKey.D,
            Q = new ECPoint
            {
                X = ecdKey.X,
                Y = ecdKey.Y
            }
        };

        var restored = ECDsa.Create(loadedParams);
        return new EcdSignKey(restored, ecdKey.KeyType);
    }

    public static ReadOnlySpan<byte> SignData(string data, EcdSignKey senderKey)
    {
        return SignData(Encoding.UTF8.GetBytes(data), senderKey);
    }

    public static ReadOnlySpan<byte> SignData(ReadOnlySpan<byte> data, EcdSignKey senderKey)
    {
        if (senderKey.KeyType is EcdKeyType.Public or EcdKeyType.None)
            throw new ArgumentNullException(nameof(senderKey), "Sender private key can not be null for sign");

        return senderKey.Key.SignData(data, HashAlgorithmName.SHA256);
    }

    public static bool VerifyData(string data, ReadOnlySpan<byte> signData, EcdSignKey senderKey)
    {
        return VerifyData(Encoding.UTF8.GetBytes(data), signData, senderKey);
    }

    public static bool VerifyData(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signData, EcdSignKey senderKey)
    {
        return senderKey.Key.VerifyData(data, signData, HashAlgorithmName.SHA256);
    }
}
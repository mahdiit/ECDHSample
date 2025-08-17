using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Gufel.EcdKey;

public sealed class EcdExchangeKey : EcdKey, IDisposable
{
    private EcdExchangeKey(ECDiffieHellman key, EcdKeyType keyType)
        : base(keyType)
    {
        Key = key;
    }

    [JsonIgnore]
    private ECDiffieHellman Key { get; }

    public void Dispose()
    {
        Key.Dispose();
    }

    public string ToJson(EcdKeyType keyType)
    {
        if (keyType == EcdKeyType.None)
            throw new InvalidOperationException("can not export data from key type");

        EcdKeyJsonModel? keyData = null;

        switch (keyType)
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

    public static EcdExchangeKey Create()
    {
        return new EcdExchangeKey(ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256), EcdKeyType.PublicAndPrivate);
    }

    public static EcdExchangeKey CreateFromJson(string jsonKey)
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

        var restored = ECDiffieHellman.Create(loadedParams);
        return new EcdExchangeKey(restored, ecdKey.KeyType);
    }

    public static EcdEncryptDto Encrypt(ReadOnlySpan<byte> data, EcdExchangeKey senderKey, EcdExchangeKey receiverKey)
    {
        if (senderKey.KeyType is EcdKeyType.Public or EcdKeyType.None)
            throw new ArgumentNullException(nameof(senderKey),
                "Sender private key can not be null for encryption");

        if (receiverKey.KeyType is EcdKeyType.Private or EcdKeyType.None)
            throw new ArgumentNullException(nameof(receiverKey),
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
        if (senderKey.KeyType is EcdKeyType.Private or EcdKeyType.None)
            throw new ArgumentNullException(nameof(senderKey),
                "Sender public key can not be null for decryption");

        if (receiverKey.KeyType is EcdKeyType.Public or EcdKeyType.None)
            throw new ArgumentNullException(nameof(receiverKey),
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
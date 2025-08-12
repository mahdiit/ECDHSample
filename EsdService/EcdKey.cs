using System.Text.Json.Serialization;

namespace EcdService;

public class EcdKey
{
    [JsonConstructor]
    private EcdKey() { }

    public byte[]? PrivateKey { get; init; }
    public byte[]? PublicKey { get; init; }
    public EcdKeyType KeyType { get; init; }

    protected EcdKey(byte[]? privateKey, byte[]? publicKey)
    {
        if (publicKey == null && privateKey == null)
            throw new ArgumentNullException(nameof(publicKey), "All key is empty, must provide public or private key");

        PrivateKey = privateKey;
        PublicKey = publicKey;

        if (privateKey != null && publicKey != null)
            KeyType = EcdKeyType.PublicAndPrivate;
        else if (publicKey != null)
            KeyType = EcdKeyType.Public;
        else if (privateKey != null)
            KeyType = EcdKeyType.Private;

    }
}

public enum EcdKeyType : byte
{
    None = 0,
    Public = 1,
    Private = 2,
    PublicAndPrivate = 3
}
namespace EcdService;

public abstract class EsdKey
{
    public byte[]? PrivateKey { get; protected init; }
    public byte[]? PublicKey { get; protected init; }
    public EsdKeyType KeyType { get; protected init; }

    protected EsdKey(byte[]? privateKey, byte[]? publicKey)
    {
        if (publicKey == null && privateKey == null)
            throw new ArgumentNullException(nameof(publicKey), "All key is empty, must provide public or private key");

        PrivateKey = privateKey;
        PublicKey = publicKey;

        if (privateKey != null && publicKey != null)
            KeyType = EsdKeyType.PublicAndPrivate;
        else if (publicKey != null)
            KeyType = EsdKeyType.Public;
        else if (privateKey != null)
            KeyType = EsdKeyType.Private;

    }
}

public enum EsdKeyType : byte
{
    None = 0,
    Public = 1,
    Private = 2,
    PublicAndPrivate = 3
}
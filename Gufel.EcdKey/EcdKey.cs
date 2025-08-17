using System.Text.Json.Serialization;

namespace Gufel.EcdKey;

public class EcdKey
{
    [JsonConstructor]
    private EcdKey() { }

    public EcdKeyType KeyType { get; }

    protected EcdKey(EcdKeyType keyType)
    {
        KeyType = keyType;
    }
}

public enum EcdKeyType : byte
{
    None = 0,
    Public = 1,
    Private = 2,
    PublicAndPrivate = 3
}
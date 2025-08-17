using System.Text.Json.Serialization;

namespace Gufel.EcdKey;

public record EcdKeyJsonModel
{
    [JsonIgnore]
    public EcdKeyType KeyType
    {
        get
        {
            if (D == null && X != null && Y != null)
                return EcdKeyType.Public;

            if (D != null && X != null && Y != null)
                return EcdKeyType.PublicAndPrivate;

            if (D != null && X == null && Y == null)
                return EcdKeyType.Private;

            return EcdKeyType.None;
        }
    }

    public string? Curve { get; init; }
    public byte[]? D { get; init; }
    public byte[]? X { get; init; }
    public byte[]? Y { get; init; }
}
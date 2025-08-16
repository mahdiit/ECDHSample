using System.Text.Json;
using System.Text.Json.Serialization;

namespace Gufel.EcdKey;

public class UrlSafeBase64Converter : JsonConverter<byte[]?>
{
    public override byte[]? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.Null)
            return null;

        var urlSafeBase64 = reader.GetString();
        return string.IsNullOrEmpty(urlSafeBase64) ? [] : EcdTools.FromUrlSafeBase64(urlSafeBase64);
    }

    public override void Write(Utf8JsonWriter writer, byte[]? value, JsonSerializerOptions options)
    {
        if (value == null)
        {
            writer.WriteNullValue();
            return;
        }

        var urlSafeBase64 = EcdTools.ToUrlSafeBase64(value);
        writer.WriteStringValue(urlSafeBase64);
    }
}
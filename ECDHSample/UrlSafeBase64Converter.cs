using System.Text.Json;
using System.Text.Json.Serialization;

namespace ECDHSample;

public class UrlSafeBase64Converter : JsonConverter<byte[]?>
{
    public override byte[]? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.Null)
            return null;

        var urlSafeBase64 = reader.GetString();
        return string.IsNullOrEmpty(urlSafeBase64) ? [] : FromUrlSafeBase64(urlSafeBase64);
    }

    public override void Write(Utf8JsonWriter writer, byte[]? value, JsonSerializerOptions options)
    {
        if (value == null)
        {
            writer.WriteNullValue();
            return;
        }

        var urlSafeBase64 = ToUrlSafeBase64(value);
        writer.WriteStringValue(urlSafeBase64);
    }

    private static string ToUrlSafeBase64(byte[] data)
    {
        var base64 = Convert.ToBase64String(data);
        return base64.Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }

    private static byte[] FromUrlSafeBase64(string urlSafeBase64)
    {
        var base64 = urlSafeBase64
            .Replace('-', '+')
            .Replace('_', '/');

        // Pad with '=' to make length a multiple of 4
        var padding = 4 - (base64.Length % 4);
        if (padding != 4)
        {
            base64 = base64.PadRight(base64.Length + padding, '=');
        }

        return Convert.FromBase64String(base64);
    }
}
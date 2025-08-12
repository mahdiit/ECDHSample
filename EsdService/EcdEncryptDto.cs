using System.Security.Cryptography;
using System.Text.Json;

namespace EcdService;

public class EcdEncryptDto
{
    public EcdEncryptDto()
    {
        Nonce = [];
        Cipher = [];
        Tag = [];
    }

    public EcdEncryptDto(int dataLength)
    {
        Nonce = RandomNumberGenerator.GetBytes(12);
        Cipher = new byte[dataLength];
        Tag = new byte[16];
    }

    public byte[] Nonce { get; set; }

    public byte[] Cipher { get; set; }

    public byte[] Tag { get; set; }

    public string ToJson()
    {
        return JsonSerializer.Serialize(this, EcdTools.KeyJsonOption);
    }

    public static EcdEncryptDto CreateFromJson(string data)
    {
        var result = JsonSerializer.Deserialize<EcdEncryptDto>(data, EcdTools.KeyJsonOption);

        if (result == null)
            throw new InvalidOperationException("can not deserialize object");

        return result;
    }
}
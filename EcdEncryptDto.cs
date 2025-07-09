using System.Security.Cryptography;

namespace ECDHSample;

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
}
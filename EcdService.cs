using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;

namespace ECDHSample
{
    public static class EcdService
    {
        public static EcdEncryptDto EncryptFromString(string data, ECDiffieHellman senderKey, ECDiffieHellman receiverKey)
        {
            var dataByte = Encoding.UTF8.GetBytes(data);
            return Encrypt(dataByte, senderKey, receiverKey);
        }

        public static EcdEncryptDto Encrypt(ReadOnlySpan<byte> data, ECDiffieHellman senderKey, ECDiffieHellman receiverKey)
        {
            var sharedKey = senderKey.DeriveKeyMaterial(receiverKey.PublicKey);
            var result = new EcdEncryptDto(data.Length);

            using var aes = new AesGcm(sharedKey, result.Tag.Length);
            aes.Encrypt(result.Nonce, data, result.Cipher, result.Tag);

            return result;
        }

        public static ReadOnlySpan<byte> Decrypt(EcdEncryptDto encrypt, ECDiffieHellman senderKey, ECDiffieHellman receiverKey)
        {
            var sharedKey = receiverKey.DeriveKeyMaterial(senderKey.PublicKey);
            var result = new byte[encrypt.Cipher.Length];

            using var aes = new AesGcm(sharedKey, encrypt.Tag.Length);
            aes.Decrypt(encrypt.Nonce, encrypt.Cipher, encrypt.Tag, result);

            return result;
        }

        public static string DecryptToString(EcdEncryptDto encrypt, ECDiffieHellman senderKey, ECDiffieHellman receiverKey)
        {
            var decrypted = Decrypt(encrypt, senderKey, receiverKey);
            return Encoding.UTF8.GetString(decrypted);
        }

        public static ReadOnlySpan<byte> SignData(ReadOnlySpan<byte> data, ECDsa senderPrivateKey)
        {
            return senderPrivateKey.SignData(data, HashAlgorithmName.SHA256);
        }

        public static bool VerifyData(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signData, ECDsa senderPublicKey)
        {
            return senderPublicKey.VerifyData(data, signData, HashAlgorithmName.SHA256);
        }
    }

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

    public sealed class EcdSignKey(ECDsa key) : IDisposable
    {
        public EcdSignKey()
        : this(ECDsa.Create(ECCurve.NamedCurves.nistP256))
        {

        }

        [JsonIgnore]
        public ECDsa Key { get; } = key;
        public byte[] PrivateKey => Key.ExportPkcs8PrivateKey();
        public byte[] PublicKey => Key.ExportSubjectPublicKeyInfo();

        public void Dispose()
        {
            Key.Dispose();
        }

        private static EcdSignKey Create(byte[]? publicKey, byte[]? privateKey)
        {
            var key = ECDsa.Create();
            if (privateKey != null)
            {
                key.ImportPkcs8PrivateKey(privateKey, out _);
            }
            else if (publicKey != null)
            {
                key.ImportSubjectPublicKeyInfo(publicKey, out _);
            }
            return new EcdSignKey(key);
        }

        public static EcdSignKey CreatePrivateKey(byte[] privateKey)
        {
            return Create(null, privateKey);
        }

        public static EcdSignKey CreatePublicKey(byte[] publicKey)
        {
            return Create(publicKey, null);
        }
    }

    public sealed class EcdExchangeKey(ECDiffieHellman key) : IDisposable
    {
        public EcdExchangeKey()
        : this(ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256))
        {

        }

        [JsonIgnore]
        public ECDiffieHellman Key { get; } = key;
        public byte[] PrivateKey => Key.ExportPkcs8PrivateKey();
        public byte[] PublicKey => Key.ExportSubjectPublicKeyInfo();

        public void Dispose()
        {
            Key.Dispose();
        }

        private static EcdExchangeKey Create(byte[]? publicKey, byte[]? privateKey)
        {
            var key = ECDiffieHellman.Create();
            if (privateKey != null)
            {
                key.ImportPkcs8PrivateKey(privateKey, out _);
            }
            else if (publicKey != null)
            {
                key.ImportSubjectPublicKeyInfo(publicKey, out _);
            }
            return new EcdExchangeKey(key);
        }

        public static EcdExchangeKey CreatePrivateKey(byte[] privateKey)
        {
            return Create(null, privateKey);
        }

        public static EcdExchangeKey CreatePublicKey(byte[] publicKey)
        {
            return Create(publicKey, null);
        }
    }
}

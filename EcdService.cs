using System.Security.Cryptography;
using System.Text;

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
}

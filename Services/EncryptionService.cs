using Microsoft.AspNetCore.DataProtection;

namespace WebApplication1.Services
{
    public class EncryptionService : IEncryptionService
    {
        private readonly IDataProtector _protector;

        public EncryptionService(IDataProtectionProvider dataProtectionProvider)
        {
            _protector = dataProtectionProvider.CreateProtector("FreshFarmMarket.CreditCard.v1");
        }

        public string Encrypt(string plainText)
        {
            if (string.IsNullOrEmpty(plainText))
                return plainText;

            return _protector.Protect(plainText);
        }

        public string Decrypt(string cipherText)
        {
            if (string.IsNullOrEmpty(cipherText))
                return cipherText;

            try
            {
                return _protector.Unprotect(cipherText);
            }
            catch (Exception)
            {
                return "[Encrypted - Unable to decrypt]";
            }
        }
    }
}

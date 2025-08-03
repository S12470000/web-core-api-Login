using System.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace MyAuthApp.Services
{
    public static class PasswordHasher
    {
       
        public static string HashPassword(string password)
        {
            // Generate a 128-bit salt
            byte[] salt = new byte[128 / 8];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }

            // PBKDF2 hash
            byte[] hashBytes = KeyDerivation.Pbkdf2(
                password: password,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 10000,
                numBytesRequested: 256 / 8);

            // Base64 encode salt and hash
            string saltBase64 = Convert.ToBase64String(salt);
            string hashBase64 = Convert.ToBase64String(hashBytes);

            // Versioning for future upgrade support
            return $"v1.{saltBase64}.{hashBase64}";
        }

        public static bool VerifyPassword(string enteredPassword, string storedHash)
        {
            var parts = storedHash.Split('.');
            if (parts.Length != 3)
                return false; // Invalid format

            var version = parts[0];
            var salt = Convert.FromBase64String(parts[1]);
            var hash = parts[2];

            if (version != "v1")
                throw new NotSupportedException("Unsupported hash version.");

            // Hash the entered password using same salt & config
            byte[] enteredHashBytes = KeyDerivation.Pbkdf2(
                password: enteredPassword,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 10000,
                numBytesRequested: 256 / 8);

            string enteredHashBase64 = Convert.ToBase64String(enteredHashBytes);

            return hash == enteredHashBase64;
        }
    }
}

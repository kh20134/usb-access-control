using System.Security.Cryptography;

namespace UsbAccessControl.Core;

public static class PasswordHasher
{
    public const string Algorithm = "PBKDF2-HMAC-SHA256";
    public const int Iterations = 100_000;
    public const int SaltSize = 16;
    public const int HashSize = 32;
    public const int MinimumLength = 8;
    public const int MaximumLength = 128;

    public static PasswordRecord Create(string password, byte[]? salt = null)
    {
        ValidatePlaintext(password);
        salt ??= RandomNumberGenerator.GetBytes(SaltSize);
        if (salt.Length < 8)
        {
            throw new ValidationException("암호 솔트가 너무 짧습니다.");
        }

        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, HashSize);
        return new PasswordRecord
        {
            Algorithm = Algorithm,
            Iterations = Iterations,
            SaltBase64 = Convert.ToBase64String(salt),
            HashBase64 = Convert.ToBase64String(hash)
        };
    }

    public static bool Verify(PasswordRecord? record, string? password)
    {
        if (record is null || string.IsNullOrEmpty(password))
        {
            return false;
        }

        if (!string.Equals(record.Algorithm, Algorithm, StringComparison.Ordinal))
        {
            return false;
        }

        if (record.Iterations is < 10_000 or > 5_000_000)
        {
            return false;
        }

        byte[] salt;
        byte[] expected;
        try
        {
            salt = Convert.FromBase64String(record.SaltBase64);
            expected = Convert.FromBase64String(record.HashBase64);
        }
        catch (FormatException)
        {
            return false;
        }

        if (salt.Length < 8 || expected.Length is < 16 or > 64)
        {
            return false;
        }

        var actual = Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            record.Iterations,
            HashAlgorithmName.SHA256,
            expected.Length);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    public static void ValidatePlaintext(string? password)
    {
        if (string.IsNullOrEmpty(password) || password.Length < MinimumLength)
        {
            throw new ValidationException($"관리자 암호는 {MinimumLength}자 이상이어야 합니다.");
        }

        if (password.Length > MaximumLength)
        {
            throw new ValidationException($"관리자 암호는 {MaximumLength}자 이하여야 합니다.");
        }
    }
}

public static class AdminAuthorizer
{
    public static void EnsureAuthorized(PolicyDocument document, string? password)
    {
        if (document.AdminPassword is null)
        {
            return;
        }

        if (!PasswordHasher.Verify(document.AdminPassword, password))
        {
            throw new AuthorizationException("관리자 암호가 올바르지 않습니다.");
        }
    }
}

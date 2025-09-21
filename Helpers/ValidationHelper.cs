using System;
using System.Text.RegularExpressions;

namespace SafeVault.Helpers;

public enum InputType
{
    Username,
    Email,
    Password,
    Role
}

public static class ValidationHelper
{
    public static bool IsValidInput(string input, InputType type)
    {
        if (string.IsNullOrWhiteSpace(input)) return false;

        // Reject script tags and SQL injection patterns
        if (Regex.IsMatch(input, @"<script.*?>.*?</script>", RegexOptions.IgnoreCase)) return false;
        if (Regex.IsMatch(input, @"('|--|;|/\*|\*/|xp_)", RegexOptions.IgnoreCase)) return false;

        switch (type)
        {
            case InputType.Username:
                return Regex.IsMatch(input, @"^[a-zA-Z0-9_\-\.]{3,30}$");

            case InputType.Email:
                return Regex.IsMatch(input, @"^[^@\s]+@[^@\s]+\.[^@\s]+$");

            case InputType.Password:
                // Minimum 8 characters, at least one letter, one number, one special character
                return Regex.IsMatch(input, @"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$");

            case InputType.Role:
                return input == "admin" || input == "user";

            default:
                return false;
        }
    }
}
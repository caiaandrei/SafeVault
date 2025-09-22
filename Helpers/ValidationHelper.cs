using System.Text.RegularExpressions;

namespace SafeVault.Helpers
{
    public enum InputType { Username, Email, Password, Role }

    public static class ValidationHelper
    {
        public static bool IsValidInput(string input, InputType type)
        {
            if (string.IsNullOrWhiteSpace(input))
                return false;

            return type switch
            {
                InputType.Username =>
                    Regex.IsMatch(input, @"^[a-zA-Z0-9_\-]{3,30}$"),

                InputType.Email =>
                    Regex.IsMatch(input, @"^[^@\s]+@[^@\s]+\.[^@\s]+$"),

                InputType.Password =>
                    Regex.IsMatch(input,
                        @"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$"
                    ),

                InputType.Role =>
                    input == "admin" || input == "user",

                _ => false,
            };
        }
    }
}

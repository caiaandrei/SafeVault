using System;
using System.Text;
using Microsoft.Extensions.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using BCrypt.Net;
using SafeVault.Helpers;
using SafeVault.Repository;

namespace SafeVault.Services
{
    public class AuthService : IAuthService
    {
        private readonly IUserRepository _repo;
        private readonly string _securityKey;

        public AuthService(IUserRepository repo, IConfiguration config)
        {
            _repo = repo;
            _securityKey = config["SecurityKey"]
                ?? throw new ArgumentNullException(nameof(config), "Missing SecurityKey configuration");
        }

        public string AuthenticateUser(string username, string password)
        {
            // whitelist‐based validation
            if (!ValidationHelper.IsValidInput(username, InputType.Username) ||
                !ValidationHelper.IsValidInput(password, InputType.Password))
            {
                return string.Empty;
            }

            var creds = _repo.GetUserCredentials(username);
            if (creds == null || !BCrypt.Net.BCrypt.Verify(password, creds.Value.PasswordHash))
            {
                return string.Empty;
            }

            return GenerateJwtToken(username, creds.Value.Role);
        }

        public bool RegisterUser(string username, string email, string password, string role)
        {
            if (!ValidationHelper.IsValidInput(username, InputType.Username) ||
                !ValidationHelper.IsValidInput(email, InputType.Email) ||
                !ValidationHelper.IsValidInput(password, InputType.Password) ||
                !ValidationHelper.IsValidInput(role, InputType.Role))
            {
                return false;
            }

            var hashedPassword = BCrypt.Net.BCrypt.HashPassword(password);
            return _repo.AddUser(username, email, hashedPassword, role);
        }

        private string GenerateJwtToken(string username, string role)
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.Name, username),
                new Claim(ClaimTypes.Role, role)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_securityKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: "SafeVault",
                audience: "SafeVaultUsers",
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(30),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}

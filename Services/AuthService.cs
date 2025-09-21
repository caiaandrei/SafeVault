using SafeVault.Helpers;
using SafeVault.Repository;
using MySql.Data.MySqlClient;
using BCrypt.Net;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace SafeVault.Services;

public class AuthService {
    private readonly IUserRepository _repo;
    private readonly string _securityKey;

    public AuthService(IUserRepository repo, IConfiguration config) {
        _repo = repo;
        _securityKey = config["SecurityKey"] ?? string.Empty;
    }

    public string AuthenticateUser(string username, string password) {
        // ✅ Validate username
        if (!ValidationHelper.IsValidInput(username, InputType.Username))
            return string.Empty;

        // ✅ Validate password (basic non-empty check)
        if (string.IsNullOrWhiteSpace(password))
            return string.Empty;

        var creds = _repo.GetUserCredentials(username);
        if (creds == null || !BCrypt.Net.BCrypt.Verify(password, creds.Value.PasswordHash)) {
            return string.Empty;
        }

        return GenerateJwtToken(username, creds.Value.Role);
    }

    public bool RegisterUser(string username, string email, string password, string role) {
        // ✅ Validate all inputs
        if (!ValidationHelper.IsValidInput(username, InputType.Username) ||
            !ValidationHelper.IsValidInput(email, InputType.Email) ||
            string.IsNullOrWhiteSpace(password) ||
            !IsValidRole(role))
            return false;

        string hashedPassword = BCrypt.Net.BCrypt.HashPassword(password);
        return _repo.AddUser(username, email, hashedPassword, role);
    }

    private string GenerateJwtToken(string username, string role) {
        var claims = new[] {
            new Claim(ClaimTypes.Name, username),
            new Claim(ClaimTypes.Role, role)
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_securityKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: "SafeVault",
            audience: "SafeVaultUsers",
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(1),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private bool IsValidRole(string role) {
        // ✅ Restrict to known roles only
        return role == "admin" || role == "user";
    }
}

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using NUnit.Framework;
using SafeVault.Services;

namespace SafeVault.Tests;

public class AuthServiceValidation
{
    private AuthService _auth;
    private MockUserRepository _repo;

    [SetUp]
    public void Setup()
    {
        _repo = new MockUserRepository();
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string> {
                { "SecurityKey", "YourSuperSecretKey123!asdasdasd222asdasd" }
            }).Build();

        _auth = new AuthService(_repo, config);
    }

    [Test]
    public void AuthenticateUser_ValidCredentials_ReturnsToken()
    {
        string hash = BCrypt.Net.BCrypt.HashPassword("Secure@123");
        _repo.AddUser("andrei", "andrei@example.com", hash, "admin");

        string token = _auth.AuthenticateUser("andrei", "Secure@123");
        Assert.That(token, Is.Not.Empty);
    }

    [Test]
    public void AuthenticateUser_InvalidUsernameFormat_ShouldFail()
    {
        string token = _auth.AuthenticateUser("<script>", "Secure@123");
        Assert.That(token, Is.Empty);
    }

    [Test]
    public void AuthenticateUser_InvalidPassword_ShouldFail()
    {
        string hash = BCrypt.Net.BCrypt.HashPassword("Secure@123");
        _repo.AddUser("andrei", "andrei@example.com", hash, "admin");

        string token = _auth.AuthenticateUser("andrei", "wrongpass");
        Assert.That(token, Is.Empty);
    }

    [Test]
    public void RegisterUser_ValidInput_ShouldSucceed()
    {
        bool result = _auth.RegisterUser("validUser", "valid@example.com", "Secure@123", "user");
        Assert.That(result, Is.True);
    }

    [Test]
    public void RegisterUser_InvalidEmail_ShouldFail()
    {
        bool result = _auth.RegisterUser("validUser", "invalid-email", "Secure@123", "user");
        Assert.That(result, Is.False);
    }

    [Test]
    public void RegisterUser_InvalidRole_ShouldFail()
    {
        bool result = _auth.RegisterUser("validUser", "valid@example.com", "Secure@123", "superadmin");
        Assert.That(result, Is.False);
    }

    [Test]
    public void RegisterUser_XSSInjection_ShouldFail()
    {
        bool result = _auth.RegisterUser("<script>", "valid@example.com", "Secure@123", "user");
        Assert.That(result, Is.False);
    }

    [Test]
    public void Token_ShouldContainCorrectRole()
    {
        _auth.RegisterUser("rolecheck", "role@example.com", "Secure@123", "admin");
        string token = _auth.AuthenticateUser("rolecheck", "Secure@123");

        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);
        var roleClaim = jwt.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;

        Assert.That(roleClaim, Is.EqualTo("admin"));
    }

    [Test]
    public void Token_ShouldExpireCorrectly()
    {
        _auth.RegisterUser("expiringUser", "exp@example.com", "Secure@123", "user");
        string token = _auth.AuthenticateUser("expiringUser", "Secure@123");

        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);
        Assert.That(jwt.ValidTo <= DateTime.UtcNow.AddMinutes(1));
    }
}

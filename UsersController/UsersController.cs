using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NUnit.Framework;
using SafeVault.Models;
using SafeVault.Repository;
using SafeVault.Services;

namespace SafeVault.UsersController
{
    [Route("[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly string? _connectionString;
        private readonly AuthService _authService;

        public UsersController(IConfiguration config)
        {
            var userRepo = new MySqlUserRepository(config);
            _authService = new AuthService(userRepo, config);
        }

        [HttpPost("/register")]
        public IActionResult Register([FromForm] RegisterUser user)
        {
            if (_authService.RegisterUser(user.Username, user.Email, user.Password, user.Role))
            {
                return Redirect("/login.html");
            }

            return Redirect("/register.html");
        }

        [HttpPost("/login")]
        public IActionResult Login([FromForm] User user)
        {
            var token = _authService.AuthenticateUser(user.Username, user.Password);
            if (!string.IsNullOrEmpty(token))
            {
                return Ok(new { token = token });
            }

            return Unauthorized("Invalid Credentials");
        }

        [Authorize(Roles = "admin")]
        [HttpGet("/admin/dashboard")]
        public IActionResult AdminDashboard()
        {
            string path = Path.Combine(Directory.GetCurrentDirectory(), "ProtectedViews", "admin.html");
            return PhysicalFile(path, "text/html");
        }

        [Authorize]
        [HttpGet("/user/dashboard")]
        public IActionResult UserDashboard()
        {
            string path = Path.Combine(Directory.GetCurrentDirectory(), "ProtectedViews", "user.html");
            return PhysicalFile(path, "text/html");
        }
    }
}

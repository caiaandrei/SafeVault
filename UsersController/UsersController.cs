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

        private readonly ILogger<UsersController> _logger;

        public UsersController(IConfiguration config, ILogger<UsersController> logger)
        {
            var userRepo = new MySqlUserRepository(config);
            _authService = new AuthService(userRepo, config);
            _logger = logger;
        }


        [HttpPost("/register")]
        public IActionResult Register([FromForm] RegisterUser user)
        {
            var ctx = GetRequestContext();
            _logger.LogInformation("Registration attempt at {Timestamp} from IP: {IP}, UA: {UA}, Username: {Username}, Role: {Role}",
                ctx.Timestamp, ctx.Ip, ctx.UserAgent, user.Username, user.Role);

            if (_authService.RegisterUser(user.Username, user.Email, user.Password, user.Role))
            {
                _logger.LogInformation("Registration successful at {Timestamp} for user: {Username} from IP: {IP}, UA: {UA}",
                    ctx.Timestamp, user.Username, ctx.Ip, ctx.UserAgent);
                return Redirect("/login.html");
            }

            _logger.LogWarning("Registration failed at {Timestamp} for user: {Username} from IP: {IP}, UA: {UA}",
                ctx.Timestamp, user.Username, ctx.Ip, ctx.UserAgent);
            return Redirect("/register.html");
        }

        [HttpPost("/login")]
        public IActionResult Login([FromForm] User user)
        {
            var ctx = GetRequestContext();
            _logger.LogInformation("Login attempt at {Timestamp} from IP: {IP}, UA: {UA}, Username: {Username}",
                ctx.Timestamp, ctx.Ip, ctx.UserAgent, user.Username);

            var token = _authService.AuthenticateUser(user.Username, user.Password);
            if (!string.IsNullOrEmpty(token))
            {
                _logger.LogInformation("Login successful at {Timestamp} for user: {Username} from IP: {IP}, UA: {UA}",
                    ctx.Timestamp, user.Username, ctx.Ip, ctx.UserAgent);
                return Ok(new { token = token });
            }

            _logger.LogWarning("Login failed at {Timestamp} for user: {Username} from IP: {IP}, UA: {UA}",
                ctx.Timestamp, user.Username, ctx.Ip, ctx.UserAgent);
            return Unauthorized("Invalid Credentials");
        }

        [Authorize(Roles = "admin")]
        [HttpGet("/admin/dashboard")]
        public IActionResult AdminDashboard()
        {
            var ctx = GetRequestContext();
            _logger.LogInformation("Admin dashboard accessed at {Timestamp} by: {User} from IP: {IP}, UA: {UA}",
                ctx.Timestamp, User.Identity?.Name, ctx.Ip, ctx.UserAgent);

            string path = Path.Combine(Directory.GetCurrentDirectory(), "ProtectedViews", "admin.html");
            return PhysicalFile(path, "text/html");
        }

        [Authorize]
        [HttpGet("/user/dashboard")]
        public IActionResult UserDashboard()
        {
            var ctx = GetRequestContext();
            _logger.LogInformation("User dashboard accessed at {Timestamp} by: {User} from IP: {IP}, UA: {UA}",
                ctx.Timestamp, User.Identity?.Name, ctx.Ip, ctx.UserAgent);

            string path = Path.Combine(Directory.GetCurrentDirectory(), "ProtectedViews", "user.html");
            return PhysicalFile(path, "text/html");
        }

        private (string Ip, string Timestamp, string UserAgent) GetRequestContext()
        {
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss");
            var userAgent = Request.Headers["User-Agent"].ToString() ?? "unknown";
            return (ip, timestamp, userAgent);
        }

    }
}

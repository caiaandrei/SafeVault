using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Models;
using SafeVault.Repository;
using SafeVault.Services;

namespace SafeVault.UsersController
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly ILogger<UsersController> _logger;

        public UsersController(IConfiguration config, ILogger<UsersController> logger, IAuthService authService)
        {
            _authService = authService;
            _logger = logger;
        }

        [HttpPost("register")]
        public IActionResult Register([FromBody] RegisterUser user)
        {
            var ctx = GetRequestContext();
            _logger.LogInformation(
                "Registration attempt at {Timestamp} from IP: {IP}, UA: {UA}, Username: {Username}, Role: {Role}",
                ctx.Timestamp, ctx.Ip, ctx.UserAgent, user.Username, user.Role);

            if (_authService.RegisterUser(user.Username, user.Email, user.Password, user.Role))
            {
                _logger.LogInformation(
                    "Registration successful at {Timestamp} for user: {Username} from IP: {IP}, UA: {UA}",
                    ctx.Timestamp, user.Username, ctx.Ip, ctx.UserAgent);

                // Optionally return the created user’s ID or details
                return Created("", new { message = "User registered successfully" });
            }

            _logger.LogWarning(
                "Registration failed at {Timestamp} for user: {Username} from IP: {IP}, UA: {UA}",
                ctx.Timestamp, user.Username, ctx.Ip, ctx.UserAgent);

            return BadRequest(new { message = "Registration failed. Username or email may already exist." });
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] User user)
        {
            var ctx = GetRequestContext();
            _logger.LogInformation(
                "Login attempt at {Timestamp} from IP: {IP}, UA: {UA}, Username: {Username}",
                ctx.Timestamp, ctx.Ip, ctx.UserAgent, user.Username);

            var token = _authService.AuthenticateUser(user.Username, user.Password);
            if (!string.IsNullOrEmpty(token))
            {
                _logger.LogInformation(
                    "Login successful at {Timestamp} for user: {Username} from IP: {IP}, UA: {UA}",
                    ctx.Timestamp, user.Username, ctx.Ip, ctx.UserAgent);

                return Ok(new { token });
            }

            _logger.LogWarning(
                "Login failed at {Timestamp} for user: {Username} from IP: {IP}, UA: {UA}",
                ctx.Timestamp, user.Username, ctx.Ip, ctx.UserAgent);

            return Unauthorized(new { message = "Invalid credentials" });
        }

        [Authorize(Roles = "admin")]
        [HttpGet("admin")]
        public IActionResult AdminInfo()
        {
            var ctx = GetRequestContext();
            _logger.LogInformation(
                "Admin info accessed at {Timestamp} by: {User} from IP: {IP}, UA: {UA}",
                ctx.Timestamp, User.Identity?.Name, ctx.Ip, ctx.UserAgent);

            return Ok("Admin connected!");
        }

        [Authorize]
        [HttpGet("user")]
        public IActionResult UserInfo()
        {
            var ctx = GetRequestContext();
            _logger.LogInformation(
                "User info accessed at {Timestamp} by: {User} from IP: {IP}, UA: {UA}",
                ctx.Timestamp, User.Identity?.Name, ctx.Ip, ctx.UserAgent);

            return Ok("User Connected!");
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

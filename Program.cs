using System.Text;
using Microsoft.IdentityModel.Tokens;
using SafeVault.Repository;
using SafeVault.Services;


var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSingleton<IUserRepository, MySqlUserRepository>();
builder.Services.AddSingleton<IAuthService, AuthService>();

builder.Services.AddAuthentication("Bearer").AddJwtBearer("Bearer", options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = "SafeVault",
        ValidAudience = "SafeVaultUsers",
        IssuerSigningKey = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(builder.Configuration["SecurityKey"]))
    };
});
builder.Services.AddAuthorization();
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

var app = builder.Build();

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.Run();

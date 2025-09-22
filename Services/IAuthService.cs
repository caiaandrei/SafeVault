namespace SafeVault.Services
{
    public interface IAuthService
    {
        string AuthenticateUser(string username, string password);
        bool RegisterUser(string username, string email, string password, string role);
    }
}

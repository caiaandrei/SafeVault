namespace SafeVault.Repository;

public interface IUserRepository
{
    (string PasswordHash, string Role)? GetUserCredentials(string username);
    bool AddUser(string username, string email, string passwordHash, string role);
}
using SafeVault.Repository;

namespace SafeVault.Tests;

public class MockUserRepository : IUserRepository
{
    private readonly Dictionary<string, (string Hash, string Role)> _users = new();

    public (string PasswordHash, string Role)? GetUserCredentials(string username)
    {
        return _users.TryGetValue(username, out var data) ? data : null;
    }

    public bool AddUser(string username, string email, string passwordHash, string role)
    {
        _users[username] = (passwordHash, role);
        return true;
    }
}

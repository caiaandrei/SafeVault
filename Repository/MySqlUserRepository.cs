using MySql.Data.MySqlClient;

namespace SafeVault.Repository;
public class MySqlUserRepository : IUserRepository
{
    private readonly string _connectionString;

    public MySqlUserRepository(IConfiguration config)
    {
        _connectionString = config.GetConnectionString("DefaultConnection") ?? string.Empty;
    }

    public (string PasswordHash, string Role)? GetUserCredentials(string username)
    {
        string query = "SELECT Password, Role FROM Users WHERE Username = @Username";

        using var conn = new MySqlConnection(_connectionString);
        using var cmd = new MySqlCommand(query, conn);
        cmd.Parameters.AddWithValue("@Username", username);

        conn.Open();
        using var reader = cmd.ExecuteReader();
        if (!reader.Read()) return null;

        return (reader.GetString("Password"), reader.GetString("Role"));
    }

    public bool AddUser(string username, string email, string passwordHash, string role)
    {
        string query = @"
            INSERT INTO Users (Username, Email, Password, Role)
            VALUES (@Username, @Email, @Password, @Role)";

        using var conn = new MySqlConnection(_connectionString);
        using var cmd = new MySqlCommand(query, conn);
        cmd.Parameters.AddWithValue("@Username", username);
        cmd.Parameters.AddWithValue("@Email", email);
        cmd.Parameters.AddWithValue("@Password", passwordHash);
        cmd.Parameters.AddWithValue("@Role", role);

        conn.Open();
        return cmd.ExecuteNonQuery() > 0;
    }
}

namespace JwtWebApiTutorial;

public class User
{
    public string Username { get; set; } = string.Empty;
    public byte[] PasswordHash { get; set; } = null!;
    public byte[] PasswordSalt { get; set; } = null!;
}
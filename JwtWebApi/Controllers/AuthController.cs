using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace JwtWebApiTutorial.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthController : ControllerBase
{
    private new static readonly User User = new();
    private readonly IConfiguration _configuration;

    public AuthController(IConfiguration configuration)
    {
        _configuration = configuration;
    }


    [HttpPost("Register")]
    public Task<ActionResult<User>> Register(UserDto request)
    {
        CreatePasswordHash(request.Password, out var passwordHash, out var passwordSalt);
        User.Username = request.Username;
        User.PasswordHash = passwordHash;
        User.PasswordSalt = passwordSalt;
        return Task.FromResult<ActionResult<User>>(Ok(User));
    }

    [HttpPost("Login")]
    public Task<ActionResult<string>> Login(UserDto request)
    {
        if (User.Username != request.Username ||
            !VerifyPasswordHash(request.Password, User.PasswordHash, User.PasswordSalt))
            return Task.FromResult<ActionResult<string>>(Unauthorized("Incorrect username or password"));

        var token = CreateToken(User);
        return Task.FromResult<ActionResult<string>>(Ok(token));
    }

    private string CreateToken(User user)
    {
        List<Claim> claims = new()
        {
            new Claim(ClaimTypes.Name, user.Username)
        };
        var key = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(_configuration.GetSection("AppSettings:Token").Value));

        var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
        var token = new JwtSecurityToken(claims: claims, signingCredentials: cred);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static bool VerifyPasswordHash(string requestPassword, IEnumerable<byte> userPasswordHash, byte[] userPasswordSalt)
    {
        using var hmac = new HMACSHA512(userPasswordSalt);
        var computeHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(requestPassword));
        return computeHash.SequenceEqual(userPasswordHash);
    }


    private static void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
    {
        using var hmac = new HMACSHA512();
        passwordSalt = hmac.Key;
        passwordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
    }
}
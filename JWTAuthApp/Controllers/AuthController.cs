using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using JWTAuthApp.DTOs;
using Microsoft.AspNetCore.Authorization;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly UserRepository _userRepository;
    private readonly IConfiguration _configuration;

    public AuthController(UserRepository userRepository, IConfiguration configuration)
    {
        _userRepository = userRepository;
        _configuration = configuration;
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
    {   
        var user = await _userRepository.GetUserByUsernameAsync(loginDto.Username);
        if (user == null || !BCrypt.Net.BCrypt.Verify(loginDto.Password, user.PasswordHash))
        {
            return Unauthorized("Invalid credentials.");
        }

        var token = GenerateJwtToken(user);

        return Ok(new { Token = token });
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
    {
        var existingUser = await _userRepository.GetUserByUsernameAsync(registerDto.Username);
        if (existingUser != null)
        {
            return BadRequest("User already exists.");
        }

        var user = new User
        {
            Username = registerDto.Username,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(registerDto.Password),
            Roles = new List<string> { "User" } // Default role for new users
        };

        await _userRepository.CreateUserAsync(user);
        return Ok("User registered successfully.");
    }

    [HttpPost("assign-role")]
    public async Task<IActionResult> AssignRole([FromBody] RoleAssignmentDto roleAssignmentDto)
    {
        await _userRepository.AddRoleAsync(roleAssignmentDto.Username, roleAssignmentDto.Role);
        return Ok("Role assigned successfully.");
    }

    // Secured endpoint for Admins only
    [Authorize(Roles = "Admin")]
    [HttpGet("admin-data")]
    public IActionResult GetAdminData()
    {
        return Ok("This is admin-only data.");
    }

    // Secured endpoint for Users only
    [Authorize(Roles = "User")]
    [HttpGet("user-data")]
    public IActionResult GetUserData()
    {
        return Ok("This is user-only data.");
    }

    private string GenerateJwtToken(User user)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        
        var key = Convert.FromBase64String(_configuration["JWT:Secret"]);


        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.Username),
        };

        // Add roles to the claims
        foreach (var role in user.Roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddDays(7),

            Issuer = _configuration["JWT:ValidIssuer"],
            Audience = _configuration["JWT:ValidAudience"],

            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }
}

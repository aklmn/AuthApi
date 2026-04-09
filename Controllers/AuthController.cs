using AuthApi.Services;
using Microsoft.AspNetCore.Mvc;

namespace AuthApi.Controllers;

[Route("api/auth")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;

    public AuthController(IAuthService authService)
    {
        _authService = authService;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        try
        {
            var (access, refresh) = await _authService.RegisterAsync(request.Email, request.Password, request.Role);
            return Ok(new { accessToken = access, refreshToken = refresh });
        }
        catch (Exception ex)
        {
            return BadRequest(ex.Message);
        }
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        try
        {
            var (access, refresh) = await _authService.LoginAsync(request.Email, request.Password);
            return Ok(new { accessToken = access, refreshToken = refresh });
        }
        catch (Exception ex)
        {
            return Unauthorized(ex.Message);
        }
    }

    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh([FromBody] RefreshRequest request)
    {
        try
        {
            var (access, refresh) = await _authService.RefreshTokenAsync(request.AccessToken, request.RefreshToken);
            return Ok(new { accessToken = access, refreshToken = refresh });
        }
        catch (Exception ex)
        {
            return Unauthorized(ex.Message);
        }
    }
}

public class RegisterRequest { public string Email { get; set; } = string.Empty; public string Password { get; set; } = string.Empty; public string Role { get; set; } = "User"; }
public class LoginRequest { public string Email { get; set; } = string.Empty; public string Password { get; set; } = string.Empty; }
public class RefreshRequest { public string AccessToken { get; set; } = string.Empty; public string RefreshToken { get; set; } = string.Empty; }
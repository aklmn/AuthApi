using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using AuthApi.Data; 
using AuthApi.Models;


namespace AuthApi.Services;

public class AuthService
{
    private readonly AppDbContext _context;
    private readonly ITokenService _tokenService;
    private readonly JwtSettings _jwtSettings;

    public AuthService(
        AppDbContext context,
        ITokenService tokenService,
        IOptions<JwtSettings> jwtSettings)
    {
        _context = context;
        _tokenService = tokenService;
        _jwtSettings = jwtSettings.Value;
    }

    /// <summary>
    /// Register user baru + langsung login (mengembalikan token)
    /// </summary>
    public async Task<(string AccessToken, string RefreshToken)> RegisterAsync(string email, string password)
    {
        if (await _context.Users.AnyAsync(u => u.Email == email))
            throw new Exception("Email sudah terdaftar");

        var user = new User
        {
            Email = email,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(password)
        };

        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        // Reuse LoginAsync supaya kode lebih bersih
        return await LoginAsync(email, password);
    }

    /// <summary>
    /// Login user dan buat Access Token + Refresh Token baru
    /// </summary>
    public async Task<(string AccessToken, string RefreshToken)> LoginAsync(string email, string password)
    {
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
        if (user == null || !BCrypt.Net.BCrypt.Verify(password, user.PasswordHash))
            throw new Exception("Email atau password salah");

        var accessToken = _tokenService.GenerateAccessToken(user);
        var refreshTokenStr = _tokenService.GenerateRefreshToken();

        var refreshToken = new RefreshToken
        {
            UserId = user.Id,
            Token = refreshTokenStr,
            Expires = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpiryDays)
        };

        await _tokenService.SaveRefreshTokenAsync(refreshToken);

        return (accessToken, refreshTokenStr);
    }

    /// <summary>
    /// REFRESH TOKEN FLOW (intinya ada di sini)
    /// </summary>
    public async Task<(string AccessToken, string RefreshToken)> RefreshTokenAsync(string accessToken, string refreshToken)
    {
        // 1. Ambil Refresh Token dari database (beserta User-nya)
        var rt = await _tokenService.GetRefreshTokenAsync(refreshToken);

        if (rt == null || rt.IsRevoked || rt.Expires < DateTime.UtcNow)
            throw new Exception("Refresh token tidak valid, telah dicabut, atau sudah expired");

        // (Opsional) Anda bisa validasi accessToken di sini jika ingin ekstra security
        // Contoh: pastikan accessToken memang milik user yang sama dengan refresh token.
        // Untuk sekarang kita skip karena refresh token sudah cukup aman.

        // 2. Revoke Refresh Token lama (security best practice)
        await _tokenService.RevokeRefreshTokenAsync(refreshToken);

        // 3. Buat Access Token baru
        var newAccessToken = _tokenService.GenerateAccessToken(rt.User);

        // 4. Buat Refresh Token baru
        var newRefreshTokenStr = _tokenService.GenerateRefreshToken();

        var newRefreshToken = new RefreshToken
        {
            UserId = rt.UserId,
            Token = newRefreshTokenStr,
            Expires = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpiryDays)
        };

        // 5. Simpan Refresh Token baru
        await _tokenService.SaveRefreshTokenAsync(newRefreshToken);

        // 6. Kembalikan kedua token baru ke client
        return (newAccessToken, newRefreshTokenStr);
    }
}
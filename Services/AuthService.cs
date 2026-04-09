using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using AuthApi.Data; 
using AuthApi.Models;
using System.Text;

namespace AuthApi.Services;
public class AuthService: IAuthService
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
    public async Task<(string AccessToken, string RefreshToken)> RegisterAsync1(string email, string password)
    {
        if (await _context.Users.AnyAsync(u => u.Email == email))
            throw new Exception("Email sudah terdaftar");

        var user = new User
        {
            Email = email,
            PasswordHash = HashMd5(password)
        };

        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        // Reuse LoginAsync supaya kode lebih bersih
        return await LoginAsync(email, password);
    }

    public async Task<(string AccessToken, string RefreshToken)> RegisterAsync(string email, string password, string role = "User")
    {
        if (await _context.Users.AnyAsync(u => u.Email == email))
            throw new Exception("Email sudah terdaftar");

        var user = new User
        {
            Email = email,
            PasswordHash = HashMd5(password)
        };

        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        // Assign default role "User"
        var userRole = await _context.Roles.FirstOrDefaultAsync(r => r.Name == role);
        if (userRole == null) 
        {            
            userRole = await _context.Roles.FirstOrDefaultAsync(r => r.Name == "User");
        }
        if (userRole != null)
        {
            _context.UserRoles.Add(new UserRole { UserId = user.Id, RoleId = userRole.Id });
            await _context.SaveChangesAsync();
        }

        return await LoginAsync(email, password); // login otomatis
    }

    /// <summary>
    /// Login user dan buat Access Token + Refresh Token baru
    /// </summary>
    public async Task<(string AccessToken, string RefreshToken)> LoginAsync2(string email, string password)
    {
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
        if (user == null || HashMd5(password) != user.PasswordHash)    
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

    public async Task<(string AccessToken, string RefreshToken)> LoginAsync(string email, string password)
    {
        var user = await _context.Users
            .Include(u => u.UserRoles)
                .ThenInclude(ur => ur.Role)
                    .ThenInclude(r => r.RolePermissions)
                        .ThenInclude(rp => rp.Permission)
            .FirstOrDefaultAsync(u => u.Email == email);

        if (user == null || HashMd5(password) != user.PasswordHash)
            throw new Exception("Email atau password salah");

        var accessToken = _tokenService.GenerateAccessToken(user);
        var refreshTokenStr = _tokenService.GenerateRefreshToken();

        var refreshToken = new RefreshToken
        {
            UserId = user.Id,
            Token = refreshTokenStr,
            Expires = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpiryDays)
        };

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

    private static string HashMd5(string input)
    {
        var bytes = MD5.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes).ToLower();
    }

    
}
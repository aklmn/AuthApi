using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AuthApi.Data;
using AuthApi.Models;
using Microsoft.IdentityModel.Tokens;

namespace AuthApi.Services;
public class TokenService : ITokenService
{
    private readonly JwtSettings _jwtSettings;
    private readonly AppDbContext _context;

    public TokenService(IOptions<JwtSettings> jwtSettings, AppDbContext context)
    {
        _jwtSettings = jwtSettings.Value;
        _context = context;
    }

    // ==================== GENERATE TOKEN ====================
    public string GenerateAccessToken(User user)
    {
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Email, user.Email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Secret));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _jwtSettings.Issuer,
            audience: _jwtSettings.Audience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenExpiryMinutes),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public string GenerateRefreshToken() => Guid.NewGuid().ToString();

    // ==================== METHOD YANG DIMINTA ====================

    /// <summary>
    /// Mengambil RefreshToken beserta User-nya (Include navigation property)
    /// </summary>
    public async Task<RefreshToken?> GetRefreshTokenAsync(string token)
    {
        return await _context.RefreshTokens
            .Include(rt => rt.User)                    // penting agar bisa pakai rt.User saat refresh
            .FirstOrDefaultAsync(rt => rt.Token == token);
    }

    /// <summary>
    /// Menyimpan RefreshToken baru ke database
    /// </summary>
    public async Task SaveRefreshTokenAsync(RefreshToken refreshToken)
    {
        await _context.RefreshTokens.AddAsync(refreshToken);
        await _context.SaveChangesAsync();
    }

    /// <summary>
    /// Revoke (menonaktifkan) RefreshToken
    /// </summary>
    public async Task RevokeRefreshTokenAsync(string token)
    {
        var refreshToken = await _context.RefreshTokens
            .FirstOrDefaultAsync(rt => rt.Token == token);

        if (refreshToken != null && !refreshToken.IsRevoked)
        {
            refreshToken.IsRevoked = true;
            await _context.SaveChangesAsync();
        }
    }
}
using AuthApi.Models;

namespace AuthApi.Services;
public interface ITokenService
{
    string GenerateAccessToken(User user);
    string GenerateRefreshToken();
    Task<RefreshToken?> GetRefreshTokenAsync(string token);
    Task SaveRefreshTokenAsync(RefreshToken refreshToken);
    Task RevokeRefreshTokenAsync(string token);
}
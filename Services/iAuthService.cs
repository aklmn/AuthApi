namespace AuthApi.Services;
public interface IAuthService
{
    Task<(string AccessToken, string RefreshToken)> RegisterAsync(string email, string password, string role = "User");
    Task<(string AccessToken, string RefreshToken)> LoginAsync(string email, string password);
    Task<(string AccessToken, string RefreshToken)> RefreshTokenAsync(string accessToken, string refreshToken);
}
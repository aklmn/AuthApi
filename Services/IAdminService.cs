namespace AuthApi.Services;
public interface IAdminService
{
    Task<List<UserResponse>> GetAllUsersAsync();
    Task<ApiResponse> CreateUserAsync(CreateUserRequest request);
    Task<ApiResponse> DeleteUserAsync(Guid userId);
}

public class CreateUserRequest
{
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string RoleName { get; set; } = "User";   // default User
}

public class UserResponse
{
    public Guid Id { get; set; }
    public string Email { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
    public List<string> Roles { get; set; } = new();
}

public class ApiResponse
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public object? Data { get; set; }
}
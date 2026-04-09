using Microsoft.EntityFrameworkCore;
using AuthApi.Data;
using AuthApi.Models;

namespace AuthApi.Services; 

public class AdminService : IAdminService
{
    private readonly AppDbContext _context;
    private readonly ITokenService _tokenService;

    public AdminService(AppDbContext context, ITokenService tokenService)
    {
        _context = context;
        _tokenService = tokenService;
    }

    public async Task<List<UserResponse>> GetAllUsersAsync()
    {
        return await _context.Users
            .Include(u => u.UserRoles)
                .ThenInclude(ur => ur.Role)
            .Select(u => new UserResponse
            {
                Id = u.Id,
                Email = u.Email,
                CreatedAt = u.CreatedAt,
                Roles = u.UserRoles.Select(ur => ur.Role.Name).ToList()
            })
            .ToListAsync();
    }

    public async Task<ApiResponse> CreateUserAsync(CreateUserRequest request)
    {
        if (await _context.Users.AnyAsync(u => u.Email == request.Email))
            return new ApiResponse { Success = false, Message = "Email sudah terdaftar" };

        // Cek role yang diminta
        var role = await _context.Roles.FirstOrDefaultAsync(r => r.Name == request.RoleName);
        if (role == null)
            return new ApiResponse { Success = false, Message = $"Role '{request.RoleName}' tidak ditemukan" };

        var user = new User
        {
            Email = request.Email,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password)
        };

        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        // Assign role
        _context.UserRoles.Add(new UserRole
        {
            UserId = user.Id,
            RoleId = role.Id
        });
        await _context.SaveChangesAsync();

        return new ApiResponse 
        { 
            Success = true, 
            Message = "User berhasil dibuat", 
            Data = new { user.Id, user.Email, Role = role.Name } 
        };
    }

    public async Task<ApiResponse> DeleteUserAsync(Guid userId)
    {
        var user = await _context.Users
            .Include(u => u.UserRoles)
            .FirstOrDefaultAsync(u => u.Id == userId);

        if (user == null)
            return new ApiResponse { Success = false, Message = "User tidak ditemukan" };

        // Revoke semua refresh token user ini
        var refreshTokens = await _context.RefreshTokens
            .Where(rt => rt.UserId == userId)
            .ToListAsync();

        foreach (var rt in refreshTokens)
            rt.IsRevoked = true;

        // Hapus user roles
        _context.UserRoles.RemoveRange(user.UserRoles);

        // Hapus user
        _context.Users.Remove(user);

        await _context.SaveChangesAsync();

        return new ApiResponse 
        { 
            Success = true, 
            Message = $"User {user.Email} berhasil dihapus beserta semua token-nya" 
        };
    }
}
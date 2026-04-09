using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using AuthApi.Data;
using AuthApi.Models;
using AuthApi.Services;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("Jwt"));

builder.Services.AddScoped<ITokenService, TokenService>();
// ===== ADMIN SERVICE =====
builder.Services.AddScoped<IAdminService, AdminService>();

builder.Services.AddScoped<IAuthService, AuthService>();

// AppDbContext sudah di-register sebelumnya, jadi otomatis ter-inject
builder.Services.AddControllers();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Secret"]!))
        };
    });

//builder.Services.AddAuthorization();
builder.Services.AddAuthorization(options =>
{
    // Role-based (bisa langsung pakai [Authorize(Roles = "Admin")])
    options.AddPolicy("RequireAdmin", policy => policy.RequireRole("Admin"));

    // Permission-based
    options.AddPolicy("CanCreateUser", policy => policy.RequireClaim("permission", "users.create"));
    options.AddPolicy("CanReadUser",   policy => policy.RequireClaim("permission", "users.read"));
    options.AddPolicy("CanUpdateUser", policy => policy.RequireClaim("permission", "users.update"));
    options.AddPolicy("CanDeleteUser", policy => policy.RequireClaim("permission", "users.delete"));
    options.AddPolicy("RequireAdminAccess", policy => policy.RequireClaim("permission", "admin.access"));
    options.AddPolicy("CanManageUsers",     policy => policy.RequireClaim("permission", "admin.access", "users.create", "users.delete"));
});

builder.Services.AddEndpointsApiExplorer();
 builder.Services.AddSwaggerGen( options =>
 {
        options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
        {
            In = ParameterLocation.Header,
            Description = "Please enter a valid token",
            Name = "Authorization",
            Type = SecuritySchemeType.Http,
            Scheme = "Bearer"
        });
        options.AddSecurityRequirement(new OpenApiSecurityRequirement
        {
            {
                new OpenApiSecurityScheme
                {
                    Reference = new OpenApiReference
                    {
                        Type = ReferenceType.SecurityScheme,
                        Id = "Bearer"
                    }
                },
                Array.Empty<string>()
            }
        });
        options.SwaggerDoc("v1", new OpenApiInfo { Title = "Auth API", Version = "v1" });  

 }   ); // This registers ISwaggerProvider

var app = builder.Build();

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

if (app.Environment.IsDevelopment())
{
    using var scope = app.Services.CreateScope();
    var context = scope.ServiceProvider.GetRequiredService<AppDbContext>();

    if (!context.Roles.Any())
    {
        var adminRole = new Role { Name = "Admin" };
        var userRole = new Role { Name = "User" };

        context.Roles.AddRange(adminRole, userRole);
        await context.SaveChangesAsync();

        // Buat permission
        var permissions = new[]
        {
            "users.create", "users.read", "users.update", "users.delete",
            "admin.access"
        };

        var permEntities = new List<Permission>();
        foreach (var p in permissions)
        {
            var perm = new Permission { Name = p };
            context.Permissions.Add(perm);
            permEntities.Add(perm);
        }
        await context.SaveChangesAsync();

        // Admin dapat SEMUA permission
        foreach (var perm in permEntities)
        {
            context.RolePermissions.Add(new RolePermission 
            { 
                RoleId = adminRole.Id, 
                PermissionId = perm.Id 
            });
        }

        // User hanya bisa read
        var readPerm = permEntities.First(p => p.Name == "users.read");
        context.RolePermissions.Add(new RolePermission 
        { 
            RoleId = userRole.Id, 
            PermissionId = readPerm.Id 
        });

        await context.SaveChangesAsync();
    }
}
app.Run();
namespace AuthApi.Models;
public class Permission
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = string.Empty; // "users.create", "users.delete", "admin.access", dll

    public ICollection<RolePermission> RolePermissions { get; set; } = new List<RolePermission>();
}
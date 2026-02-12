namespace WebApplication1.Services
{
    public interface IAuditService
    {
        Task LogAsync(string userId, string action, bool success, string? ipAddress = null, string? details = null);
        Task LogLoginAttemptAsync(string userId, bool success, string? ipAddress = null);
        Task LogRegistrationAsync(string userId, string? ipAddress = null);
        Task LogPasswordChangeAsync(string userId, bool success, string? ipAddress = null);
        Task LogLogoutAsync(string userId, string? ipAddress = null);
    }
}

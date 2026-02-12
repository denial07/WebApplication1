using WebApplication1.Model;

namespace WebApplication1.Services
{
    public class AuditService : IAuditService
    {
        private readonly AuthDbContext _context;
        private readonly ILogger<AuditService> _logger;

        public AuditService(AuthDbContext context, ILogger<AuditService> logger)
        {
            _context = context;
            _logger = logger;
        }

        public async Task LogAsync(string userId, string action, bool success, string? ipAddress = null, string? details = null)
        {
            try
            {
                var auditLog = new AuditLog
                {
                    UserId = userId,
                    Action = action,
                    Success = success,
                    IpAddress = ipAddress,
                    Timestamp = DateTime.UtcNow,
                    Details = details
                };

                _context.AuditLogs.Add(auditLog);
                await _context.SaveChangesAsync();

                _logger.LogInformation("Audit: {Action} by {UserId} - Success: {Success} from IP: {IpAddress}",
                    action, userId, success, ipAddress);
            }
            catch (Exception ex)
            {
                // Audit logging should never crash the application
                _logger.LogError(ex, "Failed to write audit log for {Action} by {UserId}", action, userId);
            }
        }

        public async Task LogLoginAttemptAsync(string userId, bool success, string? ipAddress = null)
        {
            var details = success ? "Successful login" : "Failed login attempt";
            await LogAsync(userId, "Login", success, ipAddress, details);
        }

        public async Task LogRegistrationAsync(string userId, string? ipAddress = null)
        {
            await LogAsync(userId, "Registration", true, ipAddress, "New account registered");
        }

        public async Task LogPasswordChangeAsync(string userId, bool success, string? ipAddress = null)
        {
            var details = success ? "Password changed successfully" : "Password change failed";
            await LogAsync(userId, "PasswordChange", success, ipAddress, details);
        }

        public async Task LogLogoutAsync(string userId, string? ipAddress = null)
        {
            await LogAsync(userId, "Logout", true, ipAddress, "User logged out");
        }
    }
}

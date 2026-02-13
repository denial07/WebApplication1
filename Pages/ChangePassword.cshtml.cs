using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using WebApplication1.Model;
using WebApplication1.Services;
using WebApplication1.ViewModels;

namespace WebApplication1.Pages
{
    [Authorize]
    public class ChangePasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IAuditService _auditService;
        private readonly AuthDbContext _dbContext;

        [BindProperty]
        public ChangePassword CPModel { get; set; }

        [TempData]
        public string StatusMessage { get; set; }

        public ChangePasswordModel(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IAuditService auditService,
            AuthDbContext dbContext)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _auditService = auditService;
            _dbContext = dbContext;
        }

        public async Task<IActionResult> OnGet()
        {
            // Validate session exists
            var sessionUser = HttpContext.Session.GetString("SessionUser");
            if (string.IsNullOrEmpty(sessionUser))
            {
                await _signInManager.SignOutAsync();
                return RedirectToPage("/Login", new { reason = "session_timeout" });
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null || sessionUser != user.Id)
            {
                await _signInManager.SignOutAsync();
                HttpContext.Session.Clear();
                return RedirectToPage("/Login", new { reason = "another_login" });
            }

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToPage("Login");
            }

            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();

            // Check minimum password age (1 minute)
            if (user.PasswordLastChanged.HasValue)
            {
                var minutesSinceLastChange = (DateTime.UtcNow - user.PasswordLastChanged.Value).TotalMinutes;
                if (minutesSinceLastChange < 1)
                {
                    var secondsRemaining = Math.Ceiling((1 - minutesSinceLastChange) * 60);
                    ModelState.AddModelError(string.Empty,
                        $"You can only change your password once every 1 minute. Please try again in {secondsRemaining} second(s).");
                    await _auditService.LogPasswordChangeAsync(user.Id, false, ipAddress);
                    return Page();
                }
            }

            // Check password history (last 2 passwords)
            var recentPasswords = await _dbContext.PasswordHistories
                .Where(ph => ph.UserId == user.Id)
                .OrderByDescending(ph => ph.CreatedAt)
                .Take(2)
                .ToListAsync();

            var passwordHasher = new PasswordHasher<ApplicationUser>();
            foreach (var oldPassword in recentPasswords)
            {
                var verifyResult = passwordHasher.VerifyHashedPassword(user, oldPassword.PasswordHash, CPModel.NewPassword);
                if (verifyResult != PasswordVerificationResult.Failed)
                {
                    ModelState.AddModelError(string.Empty,
                        "You cannot reuse your last 2 passwords. Please choose a different password.");
                    await _auditService.LogPasswordChangeAsync(user.Id, false, ipAddress);
                    return Page();
                }
            }

            var changePasswordResult = await _userManager.ChangePasswordAsync(user, CPModel.CurrentPassword, CPModel.NewPassword);

            if (!changePasswordResult.Succeeded)
            {
                await _auditService.LogPasswordChangeAsync(user.Id, false, ipAddress);
                foreach (var error in changePasswordResult.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
                return Page();
            }

            // Save current password hash to history
            _dbContext.PasswordHistories.Add(new PasswordHistory
            {
                UserId = user.Id,
                PasswordHash = user.PasswordHash ?? string.Empty,
                CreatedAt = DateTime.UtcNow
            });

            // Update password last changed timestamp
            user.PasswordLastChanged = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);
            await _dbContext.SaveChangesAsync();

            await _auditService.LogPasswordChangeAsync(user.Id, true, ipAddress);

            // Invalidate all other sessions after password change
            await _userManager.UpdateSecurityStampAsync(user);
            await _signInManager.RefreshSignInAsync(user);

            // Re-establish session for current user
            HttpContext.Session.Clear();
            HttpContext.Session.SetString("SessionUser", user.Id);
            HttpContext.Session.SetString("SessionStart", DateTime.UtcNow.ToString("o"));

            StatusMessage = "Your password has been changed successfully.";

            return RedirectToPage("Dashboard");
        }
    }
}

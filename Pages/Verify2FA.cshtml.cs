using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApplication1.Model;
using WebApplication1.Services;

namespace WebApplication1.Pages
{
    public class Verify2FAModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IEmailService _emailService;
        private readonly IAuditService _auditService;
        private readonly ILogger<Verify2FAModel> _logger;

        [BindProperty]
        public string OtpCode { get; set; } = string.Empty;

        [TempData]
        public string? StatusMessage { get; set; }

        [TempData]
        public string? ErrorMessage { get; set; }

        public Verify2FAModel(
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager,
            IEmailService emailService,
            IAuditService auditService,
            ILogger<Verify2FAModel> logger)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _emailService = emailService;
            _auditService = auditService;
            _logger = logger;
        }

        public async Task<IActionResult> OnGetAsync()
        {
            // Ensure we have a user from a 2FA login attempt
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                _logger.LogWarning("2FA page accessed without a valid 2FA session — redirecting to Login");
                return RedirectToPage("Login");
            }

            _logger.LogInformation("Generating 2FA token for user {UserId}", user.Id);

            // Generate and send the email token
            var token = await _userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);
            _logger.LogInformation("2FA token generated for user {UserId}", user.Id);

            try
            {
                await _emailService.SendEmailAsync(
                    user.Email!,
                    "Your Fresh Farm Market Verification Code",
                    $@"<div style='font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px;'>
                        <h2 style='color: #2d7a3e;'>Fresh Farm Market</h2>
                        <p>Your verification code is:</p>
                        <div style='background: #f0f9f1; border: 2px solid #2d7a3e; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0;'>
                            <span style='font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #2d7a3e;'>{token}</span>
                        </div>
                        <p style='color: #666; font-size: 14px;'>This code will expire in 10 minutes. If you did not request this code, please ignore this email.</p>
                    </div>");
                _logger.LogInformation("2FA email sent successfully for user {UserId}", user.Id);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send 2FA email for user {UserId}", user.Id);
                ErrorMessage = "Failed to send verification email. Please try the Resend button or contact support.";
            }

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                return RedirectToPage("Login");
            }

            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();

            var result = await _signInManager.TwoFactorSignInAsync(TokenOptions.DefaultEmailProvider, OtpCode.Trim(), false, false);

            if (result.Succeeded)
            {
                await _auditService.LogAsync(user.Id, "2FAVerification", true, ipAddress, "Email 2FA verification successful");

                // Enforce single-session: update security stamp to invalidate other sessions
                await _userManager.UpdateSecurityStampAsync(user);
                await _signInManager.RefreshSignInAsync(user);

                // Set up secure session
                HttpContext.Session.Clear();
                HttpContext.Session.SetString("SessionUser", user.Id);
                HttpContext.Session.SetString("SessionStart", DateTime.UtcNow.ToString("o"));
                
                // Check max password age (90 days) after 2FA
                if (user.PasswordLastChanged.HasValue)
                {
                    var daysSinceChange = (DateTime.UtcNow - user.PasswordLastChanged.Value).TotalDays;
                    if (daysSinceChange > 90)
                    {
                        return RedirectToPage("ChangePassword");
                    }
                }

                return RedirectToPage("Dashboard");
            }

            if (result.IsLockedOut)
            {
                await _auditService.LogAsync(user.Id, "2FALockout", false, ipAddress, "Account locked after failed 2FA attempts");
                ModelState.AddModelError(string.Empty, "Account locked out. Please try again later.");
            }
            else
            {
                await _auditService.LogAsync(user.Id, "2FAVerification", false, ipAddress, "Invalid 2FA code entered");
                ModelState.AddModelError(string.Empty, "Invalid verification code. Please try again.");
            }

            return Page();
        }

        public async Task<IActionResult> OnPostResendAsync()
        {
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                return RedirectToPage("Login");
            }

            var token = await _userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);
            _logger.LogInformation("Resend: 2FA token generated for user {UserId}", user.Id);

            try
            {
                await _emailService.SendEmailAsync(
                    user.Email!,
                    "Your Fresh Farm Market Verification Code",
                    $@"<div style='font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px;'>
                        <h2 style='color: #2d7a3e;'>Fresh Farm Market</h2>
                        <p>Your new verification code is:</p>
                        <div style='background: #f0f9f1; border: 2px solid #2d7a3e; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0;'>
                            <span style='font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #2d7a3e;'>{token}</span>
                        </div>
                        <p style='color: #666; font-size: 14px;'>This code will expire in 10 minutes.</p>
                    </div>");

                _logger.LogInformation("Resend: 2FA email sent successfully for user {UserId}", user.Id);
                StatusMessage = "A new verification code has been sent to your email.";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Resend: Failed to send 2FA email for user {UserId}", user.Id);
                ErrorMessage = "Failed to resend verification email. Please try again later or contact support.";
            }

            return Page();
        }
    }
}

using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApplication1.Model;
using WebApplication1.Services;
using WebApplication1.ViewModels;

namespace WebApplication1.Pages
{
    public class LoginModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IRecaptchaService _recaptchaService;
        private readonly IConfiguration _configuration;
        private readonly IAuditService _auditService;

        [BindProperty]
        public Login LModel { get; set; }

        [BindProperty]
        public string RecaptchaToken { get; set; }

        public string RecaptchaSiteKey { get; set; }

        public string ReturnUrl { get; set; }

        public LoginModel(
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager,
            IRecaptchaService recaptchaService,
            IConfiguration configuration,
            IAuditService auditService)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _recaptchaService = recaptchaService;
            _configuration = configuration;
            _auditService = auditService;
        }

        public void OnGet(string? returnUrl = null)
        {
            RecaptchaSiteKey = _configuration["GoogleRecaptcha:SiteKey"] ?? "";
            ReturnUrl = returnUrl ?? Url.Content("~/");
        }

        public async Task<IActionResult> OnPostAsync(string? returnUrl = null)
        {
            returnUrl ??= Url.Content("~/");

            RecaptchaSiteKey = _configuration["GoogleRecaptcha:SiteKey"] ?? "";

            // Verify reCAPTCHA token server-side
            var recaptchaValid = await _recaptchaService.VerifyTokenAsync(RecaptchaToken, "login");
            if (!recaptchaValid)
            {
                ModelState.AddModelError(string.Empty, "reCAPTCHA verification failed. Please try again.");
                return Page();
            }

            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(
                    LModel.Email,
                    LModel.Password,
                    LModel.RememberMe,
                    lockoutOnFailure: true);

                var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
                var user = await _userManager.FindByEmailAsync(LModel.Email);
                var userId = user?.Id ?? LModel.Email;

                if (result.Succeeded)
                {
                    await _auditService.LogLoginAttemptAsync(userId, true, ipAddress);

                    // Enforce single-session: update security stamp to invalidate other sessions
                    if (user != null)
                    {
                        await _userManager.UpdateSecurityStampAsync(user);
                        await _signInManager.RefreshSignInAsync(user);
                    }

                    // Set up secure session
                    HttpContext.Session.Clear();
                    HttpContext.Session.SetString("SessionUser", userId);
                    HttpContext.Session.SetString("SessionStart", DateTime.UtcNow.ToString("o"));

                    // Check max password age (90 days)
                    if (user != null && user.PasswordLastChanged.HasValue)
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
                    await _auditService.LogAsync(userId, "LoginLockout", false, ipAddress, "Account locked after multiple failed attempts");
                    ModelState.AddModelError(string.Empty, "Account locked due to multiple failed login attempts. Please try again in 15 minutes.");
                }
                else if (result.RequiresTwoFactor)
                {
                    return RedirectToPage("Verify2FA");
                }
                else if (result.IsNotAllowed)
                {
                    // Email not confirmed yet
                    ModelState.AddModelError(string.Empty, "You must confirm your email before signing in. Please check your inbox.");
                }
                else
                {
                    await _auditService.LogLoginAttemptAsync(userId, false, ipAddress);
                    ModelState.AddModelError(string.Empty, "Invalid email or password.");
                }
            }

            return Page();
        }
    }
}

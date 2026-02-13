using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApplication1.Model;
using WebApplication1.Services;

namespace WebApplication1.Pages
{
    [Authorize]
    public class DashboardModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IEncryptionService _encryptionService;

        public ApplicationUser CurrentUser { get; set; }
        public string UserEmail { get; set; }
        public string FullName { get; set; }
        public string Gender { get; set; }
        public string MobileNo { get; set; }
        public string DeliveryAddress { get; set; }
        public string? PhotoPath { get; set; }
        public string? AboutMe { get; set; }
        public bool EmailConfirmed { get; set; }
        public DateTimeOffset? LockoutEnd { get; set; }
        public bool TwoFactorEnabled { get; set; }
        public int AccessFailedCount { get; set; }
        public string MaskedCreditCard { get; set; } = string.Empty;

        public DashboardModel(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IEncryptionService encryptionService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _encryptionService = encryptionService;
        }

        public async Task<IActionResult> OnGetAsync()
        {
            // Validate session exists — redirect to login if expired
            var sessionUser = HttpContext.Session.GetString("SessionUser");
            if (string.IsNullOrEmpty(sessionUser))
            {
                await _signInManager.SignOutAsync();
                return RedirectToPage("/Login");
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToPage("Login");
            }

            // Ensure session belongs to this user
            if (sessionUser != user.Id)
            {
                await _signInManager.SignOutAsync();
                HttpContext.Session.Clear();
                return RedirectToPage("/Login");
            }

            // Password aging: force password change if password is older than 1 minute
            if (user.PasswordLastChanged.HasValue)
            {
                var minutesSinceLastChange = (DateTime.UtcNow - user.PasswordLastChanged.Value).TotalMinutes;
                if (minutesSinceLastChange >= 1)
                {
                    TempData["StatusMessage"] = "Your password has expired. Please change your password.";
                    return RedirectToPage("/ChangePassword");
                }
            }
            else
            {
                // If PasswordLastChanged is not set, force a password change
                TempData["StatusMessage"] = "Your password has expired. Please change your password.";
                return RedirectToPage("/ChangePassword");
            }

            CurrentUser = user;
            UserEmail = user.Email;
            FullName = user.FullName;
            Gender = user.Gender;
            MobileNo = user.MobileNo;
            DeliveryAddress = user.DeliveryAddress;
            PhotoPath = user.PhotoPath;
            AboutMe = user.AboutMe;
            EmailConfirmed = user.EmailConfirmed;
            LockoutEnd = user.LockoutEnd;
            TwoFactorEnabled = user.TwoFactorEnabled;
            AccessFailedCount = user.AccessFailedCount;

            // Decrypt credit card for display
            try
            {
                var decryptedCard = _encryptionService.Decrypt(user.CreditCardNo);
                if (decryptedCard.Length >= 4)
                {
                    var lastFour = decryptedCard.Substring(decryptedCard.Length - 4);
                    MaskedCreditCard = "**** **** **** " + lastFour;
                }
                else
                {
                    MaskedCreditCard = "****";
                }
            }
            catch
            {
                MaskedCreditCard = "[Decryption Error]";
            }

            return Page();
        }
    }
}

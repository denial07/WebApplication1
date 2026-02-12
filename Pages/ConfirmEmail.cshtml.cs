using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApplication1.Model;

namespace WebApplication1.Pages
{
    public class ConfirmEmailModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<ConfirmEmailModel> _logger;

        public string? StatusMessage { get; set; }
        public bool Confirmed { get; set; }

        public ConfirmEmailModel(UserManager<ApplicationUser> userManager, ILogger<ConfirmEmailModel> logger)
        {
            _userManager = userManager;
            _logger = logger;
        }

        public async Task<IActionResult> OnGetAsync(string? userId, string? token)
        {
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token))
            {
                StatusMessage = "Invalid email confirmation link.";
                Confirmed = false;
                return Page();
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                StatusMessage = "Unable to find user.";
                Confirmed = false;
                return Page();
            }

            var result = await _userManager.ConfirmEmailAsync(user, token);
            if (result.Succeeded)
            {
                _logger.LogInformation("Email confirmed for user {Email}", user.Email);
                StatusMessage = "Your email has been confirmed successfully! You can now sign in.";
                Confirmed = true;
            }
            else
            {
                _logger.LogWarning("Email confirmation failed for user {Email}", user.Email);
                StatusMessage = "Error confirming your email. The link may have expired.";
                Confirmed = false;
            }

            return Page();
        }
    }
}

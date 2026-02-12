using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using WebApplication1.Model;
using WebApplication1.Services;

namespace WebApplication1.Pages
{
    public class ResetPasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IAuditService _auditService;
        private readonly AuthDbContext _dbContext;

        [BindProperty]
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [BindProperty]
        [Required(ErrorMessage = "Password is required")]
        [DataType(DataType.Password)]
        [StringLength(100, MinimumLength = 12, ErrorMessage = "Password must be at least 12 characters")]
        public string Password { get; set; } = string.Empty;

        [BindProperty]
        [Required(ErrorMessage = "Please confirm your password")]
        [DataType(DataType.Password)]
        [Compare(nameof(Password), ErrorMessage = "Passwords do not match")]
        [Display(Name = "Confirm Password")]
        public string ConfirmPassword { get; set; } = string.Empty;

        [BindProperty]
        public string Token { get; set; } = string.Empty;

        public bool ResetSucceeded { get; set; }

        public ResetPasswordModel(
            UserManager<ApplicationUser> userManager,
            IAuditService auditService,
            AuthDbContext dbContext)
        {
            _userManager = userManager;
            _auditService = auditService;
            _dbContext = dbContext;
        }

        public IActionResult OnGet(string? token = null, string? email = null)
        {
            if (token == null || email == null)
            {
                return RedirectToPage("Login");
            }

            Token = token;
            Email = email;
            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            var user = await _userManager.FindByEmailAsync(Email);
            if (user == null)
            {
                // Don't reveal that user doesn't exist
                ResetSucceeded = true;
                return Page();
            }

            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();

            var result = await _userManager.ResetPasswordAsync(user, Token, Password);

            if (result.Succeeded)
            {
                // Save to password history
                _dbContext.PasswordHistories.Add(new PasswordHistory
                {
                    UserId = user.Id,
                    PasswordHash = user.PasswordHash ?? string.Empty,
                    CreatedAt = DateTime.UtcNow
                });

                user.PasswordLastChanged = DateTime.UtcNow;
                await _userManager.UpdateAsync(user);
                await _dbContext.SaveChangesAsync();

                await _auditService.LogAsync(user.Id, "PasswordReset", true, ipAddress, "Password reset via email link");
                ResetSucceeded = true;
                return Page();
            }

            await _auditService.LogAsync(user.Id, "PasswordReset", false, ipAddress, "Password reset failed");

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return Page();
        }
    }
}

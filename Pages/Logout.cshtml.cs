using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApplication1.Model;
using WebApplication1.Services;

namespace WebApplication1.Pages
{
    public class LogoutModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IAuditService _auditService;

        public LogoutModel(
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager,
            IAuditService auditService)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _auditService = auditService;
        }

        public void OnGet()
        {
            // Display logout confirmation page (POST-only logout for CSRF protection)
        }

        public async Task<IActionResult> OnPostAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user != null)
            {
                var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
                await _auditService.LogLogoutAsync(user.Id, ipAddress);

                // Update security stamp to invalidate all cookies/sessions for this user
                await _userManager.UpdateSecurityStampAsync(user);
            }

            await _signInManager.SignOutAsync();

            // Clear and abandon session completely
            HttpContext.Session.Clear();

            // Delete session cookie explicitly
            HttpContext.Response.Cookies.Delete(".AspNetCore.Session");

            return RedirectToPage("Index");
        }
    }
}

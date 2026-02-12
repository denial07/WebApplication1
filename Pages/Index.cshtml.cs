using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace WebApplication1.Pages
{
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;

        public bool IsAuthenticated { get; set; }
        public string UserEmail { get; set; }

        public IndexModel(ILogger<IndexModel> logger)
        {
            _logger = logger;
        }

        public void OnGet()
        {
            IsAuthenticated = User.Identity?.IsAuthenticated ?? false;
            UserEmail = User.Identity?.Name ?? string.Empty;
        }
    }
}

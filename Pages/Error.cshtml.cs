using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Diagnostics;

namespace WebApplication1.Pages
{
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    [IgnoreAntiforgeryToken]
    public class ErrorModel : PageModel
    {
        public string? RequestId { get; set; }

        public bool ShowRequestId => !string.IsNullOrEmpty(RequestId);

        public new int StatusCode { get; set; }

        public string ErrorTitle { get; set; } = "Something went wrong";

        public string ErrorMessage { get; set; } = "An unexpected error occurred while processing your request.";

        private readonly ILogger<ErrorModel> _logger;

        public ErrorModel(ILogger<ErrorModel> logger)
        {
            _logger = logger;
        }

        public void OnGet(int? statusCode = null)
        {
            RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier;
            StatusCode = statusCode ?? HttpContext.Response.StatusCode;

            switch (StatusCode)
            {
                case 400:
                    ErrorTitle = "Bad Request";
                    ErrorMessage = "The request could not be understood by the server.";
                    break;
                case 401:
                    ErrorTitle = "Unauthorized";
                    ErrorMessage = "You are not authorized to access this resource. Please sign in.";
                    break;
                case 403:
                    ErrorTitle = "Access Denied";
                    ErrorMessage = "You do not have permission to access this resource.";
                    break;
                case 404:
                    ErrorTitle = "Page Not Found";
                    ErrorMessage = "The page you are looking for doesn't exist or has been moved.";
                    break;
                case 500:
                    ErrorTitle = "Server Error";
                    ErrorMessage = "An internal server error occurred. Please try again later.";
                    break;
                default:
                    ErrorTitle = "Error";
                    ErrorMessage = "An unexpected error occurred while processing your request.";
                    break;
            }

            _logger.LogWarning("Error page displayed. StatusCode: {StatusCode}, RequestId: {RequestId}",
                StatusCode, RequestId);
        }
    }
}

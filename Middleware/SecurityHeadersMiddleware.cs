namespace WebApplication1.Middleware
{
    public class SecurityHeadersMiddleware
    {
        private readonly RequestDelegate _next;

        public SecurityHeadersMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // Prevent clickjacking
            context.Response.Headers["X-Frame-Options"] = "DENY";

            // Prevent MIME type sniffing
            context.Response.Headers["X-Content-Type-Options"] = "nosniff";

            // Enable XSS filter in older browsers
            context.Response.Headers["X-XSS-Protection"] = "1; mode=block";

            // Referrer policy
            context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";

            // Permissions policy (restrict browser features)
            context.Response.Headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()";

            // Content Security Policy
            context.Response.Headers["Content-Security-Policy"] =
                "default-src 'self'; " +
                "script-src 'self' 'unsafe-inline' https://www.google.com https://www.gstatic.com; " +
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
                "font-src 'self' https://fonts.gstatic.com; " +
                "img-src 'self' data:; " +
                "frame-src https://www.google.com; " +
                "connect-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com https://www.google.com;";

            // Strict Transport Security (HSTS)
            context.Response.Headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains";

            // Prevent caching of sensitive pages
            if (context.Request.Path.StartsWithSegments("/Login") ||
                context.Request.Path.StartsWithSegments("/Register") ||
                context.Request.Path.StartsWithSegments("/Dashboard") ||
                context.Request.Path.StartsWithSegments("/ChangePassword"))
            {
                context.Response.Headers["Cache-Control"] = "no-store, no-cache, must-revalidate";
                context.Response.Headers["Pragma"] = "no-cache";
                context.Response.Headers["Expires"] = "0";
            }

            await _next(context);
        }
    }

    public static class SecurityHeadersMiddlewareExtensions
    {
        public static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<SecurityHeadersMiddleware>();
        }
    }
}

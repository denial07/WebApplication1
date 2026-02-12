using Microsoft.AspNetCore.Identity;
using WebApplication1.Model;
using WebApplication1.Services;
using WebApplication1.Middleware;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();

builder.Services.AddDbContext<AuthDbContext>();
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    // Strong password policy
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequiredLength = 12;

    // User requirements
    options.User.RequireUniqueEmail = true;

    // Require email confirmation before login
    options.SignIn.RequireConfirmedEmail = true;

    // Lockout policy
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    options.Lockout.MaxFailedAccessAttempts = 3;
    options.Lockout.AllowedForNewUsers = true;
})
.AddEntityFrameworkStores<AuthDbContext>()
.AddDefaultTokenProviders();

// Configure authentication cookie security
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
    options.SlidingExpiration = true;
    options.LoginPath = "/Login";
    options.LogoutPath = "/Logout";
    options.AccessDeniedPath = "/Error";
});

// Validate security stamp frequently to enforce single-session policy
// When a user logs in on another device, the security stamp changes,
// invalidating the cookie on the first device within this interval.
builder.Services.Configure<SecurityStampValidatorOptions>(options =>
{
    options.ValidationInterval = TimeSpan.FromMinutes(1);
});

// Session management
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(20);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
});

// Data Protection API for encryption
builder.Services.AddDataProtection();

// Register encryption service
builder.Services.AddScoped<IEncryptionService, WebApplication1.Services.EncryptionService>();

// Register reCAPTCHA service with HttpClient
builder.Services.AddHttpClient<IRecaptchaService, RecaptchaService>();

// Register audit logging service
builder.Services.AddScoped<IAuditService, AuditService>();

// Register email service
builder.Services.AddTransient<IEmailService, EmailService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseStaticFiles();

// Custom error pages for status codes (404, 403, etc.)
app.UseStatusCodePagesWithReExecute("/Error", "?statusCode={0}");

app.UseRouting();

// Security headers (CSP, X-Frame-Options, etc.) - after routing so only page requests get CSP
app.UseSecurityHeaders();

// Session must be before Authentication so session is available during auth
app.UseSession();

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();

app.Run();

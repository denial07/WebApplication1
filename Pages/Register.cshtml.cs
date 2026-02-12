using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using System.Text.Encodings.Web;
using WebApplication1.Model;
using WebApplication1.Services;
using WebApplication1.ViewModels;


namespace WebApplication1.Pages
{
    public class RegisterModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IWebHostEnvironment _environment;
        private readonly IEncryptionService _encryptionService;
        private readonly IRecaptchaService _recaptchaService;
        private readonly IConfiguration _configuration;
        private readonly IAuditService _auditService;
        private readonly AuthDbContext _dbContext;
        private readonly IEmailService _emailService;

        [BindProperty]
        public Register RModel { get; set; }

        [BindProperty]
        [Display(Name = "Profile Photo")]
        public IFormFile? Photo { get; set; }

        [BindProperty]
        public string RecaptchaToken { get; set; }

        public string RecaptchaSiteKey { get; set; }

        public RegisterModel(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IWebHostEnvironment environment,
            IEncryptionService encryptionService,
            IRecaptchaService recaptchaService,
            IConfiguration configuration,
            IAuditService auditService,
            AuthDbContext dbContext,
            IEmailService emailService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _environment = environment;
            _encryptionService = encryptionService;
            _recaptchaService = recaptchaService;
            _configuration = configuration;
            _auditService = auditService;
            _dbContext = dbContext;
            _emailService = emailService;
        }

        public void OnGet()
        {
            RecaptchaSiteKey = _configuration["GoogleRecaptcha:SiteKey"] ?? "";
        }

        public async Task<IActionResult> OnPostAsync()
        {
            RecaptchaSiteKey = _configuration["GoogleRecaptcha:SiteKey"] ?? "";

            // Verify reCAPTCHA token server-side
            var recaptchaValid = await _recaptchaService.VerifyTokenAsync(RecaptchaToken, "register");
            if (!recaptchaValid)
            {
                ModelState.AddModelError(string.Empty, "reCAPTCHA verification failed. Please try again.");
                return Page();
            }

            if (ModelState.IsValid)
            {
                // Validate photo file
                string? photoPath = null;
                if (Photo != null && Photo.Length > 0)
                {
                    // Check file extension
                    var extension = Path.GetExtension(Photo.FileName).ToLowerInvariant();
                    var allowedExtensions = new[] { ".jpg", ".jpeg", ".png", ".pdf", ".docx" };
                    if (!allowedExtensions.Contains(extension))
                    {
                        ModelState.AddModelError("Photo", "Only .JPG, .JPEG, .PNG, .PDF, and .DOCX files are allowed.");
                        return Page();
                    }

                    // Verify MIME type matches extension (prevent spoofing)
                    var allowedMimeTypes = new Dictionary<string, string[]>
                    {
                        { ".jpg", new[] { "image/jpeg" } },
                        { ".jpeg", new[] { "image/jpeg" } },
                        { ".png", new[] { "image/png" } },
                        { ".pdf", new[] { "application/pdf" } },
                        { ".docx", new[] { "application/vnd.openxmlformats-officedocument.wordprocessingml.document" } }
                    };

                    if (allowedMimeTypes.ContainsKey(extension) &&
                        !allowedMimeTypes[extension].Contains(Photo.ContentType.ToLowerInvariant()))
                    {
                        ModelState.AddModelError("Photo", "File content does not match its extension. Upload rejected.");
                        return Page();
                    }

                    // Verify file signature (magic bytes) for images
                    if (extension == ".jpg" || extension == ".jpeg" || extension == ".png")
                    {
                        using var headerStream = Photo.OpenReadStream();
                        var headerBytes = new byte[8];
                        await headerStream.ReadAsync(headerBytes, 0, headerBytes.Length);

                        bool validSignature = false;
                        if (extension == ".jpg" || extension == ".jpeg")
                        {
                            // JPEG magic bytes: FF D8 FF
                            validSignature = headerBytes[0] == 0xFF && headerBytes[1] == 0xD8 && headerBytes[2] == 0xFF;
                        }
                        else if (extension == ".png")
                        {
                            // PNG magic bytes: 89 50 4E 47
                            validSignature = headerBytes[0] == 0x89 && headerBytes[1] == 0x50 &&
                                             headerBytes[2] == 0x4E && headerBytes[3] == 0x47;
                        }

                        if (!validSignature)
                        {
                            ModelState.AddModelError("Photo", "File appears to be corrupted or is not a valid image.");
                            return Page();
                        }
                    }

                    // Check file size (max 2MB)
                    if (Photo.Length > 2 * 1024 * 1024)
                    {
                        ModelState.AddModelError("Photo", "File size must not exceed 2MB.");
                        return Page();
                    }

                    // Save photo
                    var uploadsFolder = Path.Combine(_environment.WebRootPath, "uploads", "photos");
                    Directory.CreateDirectory(uploadsFolder);
                    
                    // Generate safe filename (GUID) to prevent path traversal
                    var uniqueFileName = $"{Guid.NewGuid()}{extension}";
                    var filePath = Path.Combine(uploadsFolder, uniqueFileName);
                    
                    using (var stream = new FileStream(filePath, FileMode.Create))
                    {
                        await Photo.CopyToAsync(stream);
                    }
                    
                    photoPath = $"/uploads/photos/{uniqueFileName}";
                }

                // Encrypt credit card number using Data Protection API
                var encryptedCreditCard = _encryptionService.Encrypt(RModel.CreditCardNo);

                var user = new ApplicationUser()
                {
                    UserName = RModel.Email,
                    Email = RModel.Email,
                    FullName = HtmlEncoder.Default.Encode(RModel.FullName),
                    CreditCardNo = encryptedCreditCard,
                    Gender = RModel.Gender,
                    MobileNo = HtmlEncoder.Default.Encode(RModel.MobileNo),
                    DeliveryAddress = HtmlEncoder.Default.Encode(RModel.DeliveryAddress),
                    PhotoPath = photoPath,
                    AboutMe = RModel.AboutMe != null ? HtmlEncoder.Default.Encode(RModel.AboutMe) : null
                };

                var result = await _userManager.CreateAsync(user, RModel.Password);
                
                if (result.Succeeded)
                {
                    var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
                    await _auditService.LogRegistrationAsync(user.Id, ipAddress);

                    // Enable 2FA by default (mandatory)
                    await _userManager.SetTwoFactorEnabledAsync(user, true);

                    // Save initial password to history and set PasswordLastChanged
                    _dbContext.PasswordHistories.Add(new PasswordHistory
                    {
                        UserId = user.Id,
                        PasswordHash = user.PasswordHash ?? string.Empty,
                        CreatedAt = DateTime.UtcNow
                    });
                    user.PasswordLastChanged = DateTime.UtcNow;
                    await _userManager.UpdateAsync(user);
                    await _dbContext.SaveChangesAsync();

                    // Generate email confirmation token and send confirmation email
                    var emailToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    var confirmationLink = Url.Page(
                        "/ConfirmEmail",
                        pageHandler: null,
                        values: new { userId = user.Id, token = emailToken },
                        protocol: Request.Scheme);

                    await _emailService.SendEmailAsync(
                        user.Email!,
                        "Confirm Your Email - Fresh Farm Market",
                        $@"<div style='font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px;'>
                            <h2 style='color: #2d7a3e;'>Fresh Farm Market</h2>
                            <p>Hello {HtmlEncoder.Default.Encode(RModel.FullName)},</p>
                            <p>Thank you for registering! Please confirm your email address by clicking the button below:</p>
                            <div style='text-align: center; margin: 30px 0;'>
                                <a href='{confirmationLink}' style='background: #2d7a3e; color: white; padding: 14px 28px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;'>Confirm Email</a>
                            </div>
                            <p style='color: #666; font-size: 14px;'>If you did not create this account, please ignore this email.</p>
                            <p style='color: #999; font-size: 12px;'>If the button doesn't work, copy and paste this link into your browser:<br/>{confirmationLink}</p>
                        </div>");

                    // Do NOT auto sign-in — user must confirm email first
                    TempData["SuccessMessage"] = "Registration successful! Please check your email to confirm your account before signing in.";
                    return RedirectToPage("Login");
                }
                
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }
            }
            return Page();
        }

    }
}

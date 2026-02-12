using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;

namespace WebApplication1.Services
{
    public class EmailService : IEmailService
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<EmailService> _logger;

        public EmailService(IConfiguration configuration, ILogger<EmailService> logger)
        {
            _configuration = configuration;
            _logger = logger;
        }

        public async Task SendEmailAsync(string toEmail, string subject, string htmlBody)
        {
            var smtpHost = _configuration["EmailSettings:SmtpHost"] ?? "smtp.sendgrid.net";
            var smtpPort = int.Parse(_configuration["EmailSettings:SmtpPort"] ?? "587");
            var smtpUser = _configuration["EmailSettings:SmtpUser"] ?? "";
            var smtpPass = _configuration["EmailSettings:SmtpPass"] ?? "";
            var fromEmail = _configuration["EmailSettings:FromEmail"] ?? smtpUser;
            var fromName = _configuration["EmailSettings:FromName"] ?? "Fresh Farm Market";

            _logger.LogInformation("Attempting to send email via {Host}:{Port}", smtpHost, smtpPort);

            var message = new MimeMessage();
            message.From.Add(new MailboxAddress(fromName, fromEmail));
            message.To.Add(MailboxAddress.Parse(toEmail));
            message.Subject = subject;

            message.Body = new TextPart("html")
            {
                Text = htmlBody
            };

            using var client = new MailKit.Net.Smtp.SmtpClient();
            try
            {
                await client.ConnectAsync(smtpHost, smtpPort, SecureSocketOptions.StartTls);
                _logger.LogInformation("Connected to SMTP server {Host}", smtpHost);

                await client.AuthenticateAsync(smtpUser, smtpPass);
                _logger.LogInformation("Authenticated with SMTP server");

                await client.SendAsync(message);
                _logger.LogInformation("Email sent successfully");

                await client.DisconnectAsync(true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send email. Host={Host}, Port={Port}",
                    smtpHost, smtpPort);
                throw;
            }
        }
    }
}

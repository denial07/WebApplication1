using System.Text.Json;

namespace WebApplication1.Services
{
    public class RecaptchaService : IRecaptchaService
    {
        private readonly HttpClient _httpClient;
        private readonly string _secretKey;
        private readonly ILogger<RecaptchaService> _logger;

        public RecaptchaService(IConfiguration configuration, HttpClient httpClient, ILogger<RecaptchaService> logger)
        {
            _httpClient = httpClient;
            _secretKey = configuration["GoogleRecaptcha:SecretKey"] 
                ?? throw new InvalidOperationException("reCAPTCHA SecretKey is not configured.");
            _logger = logger;
        }

        public async Task<bool> VerifyTokenAsync(string token, string expectedAction)
        {
            // Skip verification if secret key is not configured (development)
            if (_secretKey == "YOUR_RECAPTCHA_V3_SECRET_KEY" || string.IsNullOrEmpty(_secretKey))
            {
                _logger.LogWarning("reCAPTCHA is not configured. Skipping verification.");
                return true;
            }

            if (string.IsNullOrEmpty(token))
            {
                _logger.LogWarning("reCAPTCHA token is null or empty.");
                return false;
            }

            try
            {
                var content = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("secret", _secretKey),
                    new KeyValuePair<string, string>("response", token)
                });

                var response = await _httpClient.PostAsync(
                    "https://www.google.com/recaptcha/api/siteverify", content);

                var json = await response.Content.ReadAsStringAsync();
                var result = JsonSerializer.Deserialize<RecaptchaResponse>(json);

                if (result == null)
                {
                    _logger.LogWarning("reCAPTCHA response deserialization returned null.");
                    return false;
                }

                if (!result.Success)
                {
                    _logger.LogWarning("reCAPTCHA verification failed. Errors: {Errors}",
                        string.Join(", ", result.ErrorCodes ?? Array.Empty<string>()));
                    return false;
                }

                // Verify the action matches what we expect
                if (!string.Equals(result.Action, expectedAction, StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogWarning("reCAPTCHA action mismatch. Expected: {Expected}, Got: {Actual}",
                        expectedAction, result.Action);
                    return false;
                }

                // Check score threshold (0.5 is Google's recommended threshold)
                if (result.Score < 0.5)
                {
                    _logger.LogWarning("reCAPTCHA score too low: {Score} for action: {Action}",
                        result.Score, result.Action);
                    return false;
                }

                _logger.LogInformation("reCAPTCHA verified successfully. Score: {Score}, Action: {Action}",
                    result.Score, result.Action);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verifying reCAPTCHA token.");
                return false;
            }
        }

        private class RecaptchaResponse
        {
            [System.Text.Json.Serialization.JsonPropertyName("success")]
            public bool Success { get; set; }

            [System.Text.Json.Serialization.JsonPropertyName("score")]
            public float Score { get; set; }

            [System.Text.Json.Serialization.JsonPropertyName("action")]
            public string? Action { get; set; }

            [System.Text.Json.Serialization.JsonPropertyName("challenge_ts")]
            public string? ChallengeTimestamp { get; set; }

            [System.Text.Json.Serialization.JsonPropertyName("hostname")]
            public string? Hostname { get; set; }

            [System.Text.Json.Serialization.JsonPropertyName("error-codes")]
            public string[]? ErrorCodes { get; set; }
        }
    }
}

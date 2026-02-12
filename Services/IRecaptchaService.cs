namespace WebApplication1.Services
{
    public interface IRecaptchaService
    {
        Task<bool> VerifyTokenAsync(string token, string expectedAction);
    }
}

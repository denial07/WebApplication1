using Microsoft.AspNetCore.Identity;

namespace WebApplication1.Model
{
    public class ApplicationUser : IdentityUser
    {
        public string FullName { get; set; }
        
        public string CreditCardNo { get; set; } // Encrypted
        
        public string Gender { get; set; }
        
        public string MobileNo { get; set; }
        
        public string DeliveryAddress { get; set; }
        
        public string? PhotoPath { get; set; }
        
        public string? AboutMe { get; set; }

        public DateTime? PasswordLastChanged { get; set; }
    }
}

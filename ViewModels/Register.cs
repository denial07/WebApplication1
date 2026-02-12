using System.ComponentModel.DataAnnotations;

namespace WebApplication1.ViewModels
{
    public class Register
    {
        [Required(ErrorMessage = "Full Name is required")]
        [Display(Name = "Full Name")]
        [StringLength(100, ErrorMessage = "Full Name cannot exceed 100 characters")]
        [RegularExpression(@"^[a-zA-Z\s\-']+$", ErrorMessage = "Full Name can only contain letters, spaces, hyphens, and apostrophes")]
        public string FullName { get; set; }

        [Required(ErrorMessage = "Credit Card Number is required")]
        [Display(Name = "Credit Card Number")]
        [CreditCard(ErrorMessage = "Please enter a valid credit card number")]
        public string CreditCardNo { get; set; }

        [Required(ErrorMessage = "Gender is required")]
        [RegularExpression(@"^(Male|Female|Other)$", ErrorMessage = "Invalid gender selection")]
        public string Gender { get; set; }

        [Required(ErrorMessage = "Mobile Number is required")]
        [Display(Name = "Mobile Number")]
        [Phone(ErrorMessage = "Please enter a valid mobile number")]
        [RegularExpression(@"^[\+]?[0-9\s\-\(\)]{8,20}$", ErrorMessage = "Mobile number format is invalid")]
        public string MobileNo { get; set; }

        [Required(ErrorMessage = "Delivery Address is required")]
        [Display(Name = "Delivery Address")]
        [StringLength(500, ErrorMessage = "Delivery Address cannot exceed 500 characters")]
        public string DeliveryAddress { get; set; }

        [Required(ErrorMessage = "Email is required")]
        [DataType(DataType.EmailAddress)]
        [EmailAddress(ErrorMessage = "Please enter a valid email address")]
        [StringLength(256, ErrorMessage = "Email cannot exceed 256 characters")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is required")]
        [DataType(DataType.Password)]
        [StringLength(100, MinimumLength = 12, ErrorMessage = "Password must be between 12 and 100 characters")]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z\d]).{12,}$",
            ErrorMessage = "Password must contain at least one uppercase, one lowercase, one digit, and one special character")]
        public string Password { get; set; }

        [Required(ErrorMessage = "Please confirm your password")]
        [DataType(DataType.Password)]
        [Compare(nameof(Password), ErrorMessage = "Password and confirmation password do not match")]
        [Display(Name = "Confirm Password")]
        public string ConfirmPassword { get; set; }

        [Display(Name = "About Me")]
        [StringLength(1000, ErrorMessage = "About Me cannot exceed 1000 characters")]
        public string AboutMe { get; set; }
    }
}

using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace WebApplication1.Model
{
    public class AuthDbContext : IdentityDbContext<ApplicationUser>
    {
        private readonly IConfiguration _configuration;

        public DbSet<AuditLog> AuditLogs { get; set; }

        public DbSet<PasswordHistory> PasswordHistories { get; set; }

        public AuthDbContext(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            string connectionString = _configuration.GetConnectionString("AuthConnectionString");
            optionsBuilder.UseSqlServer(connectionString);
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.Entity<ApplicationUser>(entity =>
            {
                entity.Property(e => e.FullName).HasMaxLength(100);
                entity.Property(e => e.CreditCardNo).HasMaxLength(256); // Encrypted value
                entity.Property(e => e.Gender).HasMaxLength(10);
                entity.Property(e => e.MobileNo).HasMaxLength(20);
                entity.Property(e => e.DeliveryAddress).HasMaxLength(500);
                entity.Property(e => e.PhotoPath).HasMaxLength(256);
                entity.Property(e => e.AboutMe).HasMaxLength(1000);
            });

            builder.Entity<AuditLog>(entity =>
            {
                entity.HasIndex(e => e.UserId);
                entity.HasIndex(e => e.Timestamp);
                entity.HasIndex(e => e.Action);
            });

            builder.Entity<PasswordHistory>(entity =>
            {
                entity.HasIndex(e => e.UserId);
                entity.HasIndex(e => e.CreatedAt);
            });
        }
    }
}

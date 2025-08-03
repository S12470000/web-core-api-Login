using Microsoft.EntityFrameworkCore;
using Login.Models;

namespace Login.Data
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
        public DbSet<PasswordResetToken> PasswordResetTokens => Set<PasswordResetToken>();

        public DbSet<User> Users => Set<User>();
    }
}

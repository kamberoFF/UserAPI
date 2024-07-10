using Microsoft.EntityFrameworkCore;

namespace UserAPI.Models.User
{
    public class UserContext : DbContext
    {
        public DbSet<UserBaseModel> Users { get; set; }

        public UserContext(DbContextOptions<UserContext> options) : base(options)
        {
        }
    }
}

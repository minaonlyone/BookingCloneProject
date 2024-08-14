using Microsoft.AspNetCore.Identity;
using System;

namespace BookingClone.Domain.Entities
{
    public class ApplicationUser : IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public DateTime DateOfBirth { get; set; }
        public string UserType { get; set; } // Can be "Agent", "SubAgent", "Admin", or "Customer"
        public DateTime CreatedAt { get; set; }
        public DateTime? LastLoginAt { get; set; }

        public ApplicationUser()
        {
            CreatedAt = DateTime.UtcNow;
        }
    }
}

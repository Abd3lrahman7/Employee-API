using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace EmployeeApi.Authorization
{
    // This authorization handler enforces the ownership rule for student resources.
    // It checks whether the current user is either:
    // - An Admin (full access), OR
    // - The owner of the student record being requested
    public class EmployeeOwnerOrAdminHandler:AuthorizationHandler<EmployeeOwnerOrAdminRequirement,int>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, EmployeeOwnerOrAdminRequirement requirement, int studentId)
        {
            // Admin override
            if (context.User.IsInRole("Admin"))
            {
                context.Succeed(requirement);
                return Task.CompletedTask;
            }

            // Ownership check
            var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);

            if (int.TryParse(userId, out int authenticatedStudentId) && authenticatedStudentId == studentId)
            {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }
    }
}

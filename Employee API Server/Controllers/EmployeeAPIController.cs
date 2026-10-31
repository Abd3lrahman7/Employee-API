using EmployeeApi.DataSimulation;
using EmployeeApi.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc; 
using System.Collections.Generic;
using System.ComponentModel;
using System.Security.Claims;

namespace EmployeeApi.Controllers 
{
    [Authorize] //This means: Every endpoint inside this controller Requires a valid JWT
    [ApiController] // Marks the class as a Web API controller with enhanced features.
        //  [Route("[controller]")] // Sets the route for this controller to "Employees", based on the controller name.
    [Route("api/Employees")]

    public class EmployeesController : ControllerBase // Declare the controller class inheriting from ControllerBase.
    {
        private readonly ILogger<EmployeesController> _logger;


        public EmployeesController(ILogger<EmployeesController> logger)
        {
            _logger = logger;
        }

        [Authorize(Roles ="Admin")]
        [HttpGet("All", Name = "GetAllEmployees")] // Marks this method to respond to HTTP GET requests.
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public ActionResult<IEnumerable<Employee>> GetAllEmployees() // Define a method to get all Employees.
        {
            //EmployeeDataSimulation.EmployeesList.Clear();

            if (EmployeeDataSimulation.EmployeesList.Count == 0) 
            {
                return NotFound("No Employees Found!");
            }
            return Ok(EmployeeDataSimulation.EmployeesList); // Returns the list of Employees.
        }

        [AllowAnonymous]
        [HttpGet("Old",Name = "GetOldEmployees")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        // Method to get all Employees whith age > 45
        public ActionResult<IEnumerable<Employee>> GetOldEmployees()

        {
            var oldEmployees = EmployeeDataSimulation.EmployeesList.Where(Employees => Employees.Age >= 45).ToList();
            //oldEmployees.Clear();

            if (oldEmployees.Count == 0)
            {
                return NotFound("No  old employees");
            }


            return Ok(oldEmployees); // Return the list of old Employees.
        }

        [AllowAnonymous]
        [HttpGet("AverageSalary", Name = "GetAverageSalary")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public ActionResult<double> GetAverageSalary()
        {

            //   EmployeeDataSimulation.EmployeesList.Clear();

            if (EmployeeDataSimulation.EmployeesList.Count == 0)
            {
                return NotFound("No Employees found.");
            }

            var averageGrade = EmployeeDataSimulation.EmployeesList.Average(Employee => Employee.Salary);
            return Ok(averageGrade);
        }


        [HttpGet("{id}", Name = "GetEmployeeById")]  
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        public async Task<ActionResult<Employee>> GetEmployeeById(int id, [FromServices] IAuthorizationService authorizationService)
        {

            if (id < 1)
            {
                return BadRequest($"Not accepted ID {id}");
            }

            var Employee = EmployeeDataSimulation.EmployeesList.FirstOrDefault(e => e.Id == id);
            if (Employee == null)
            {
                return NotFound($"Employee with ID {id} not found.");
            }

            var authResult = await authorizationService.AuthorizeAsync(User, id,"EmployeeOwnerOrAdmin");

            if (!authResult.Succeeded)
                return Forbid(); // 403


            return Ok(Employee);
        }

        [Authorize(Roles = "Admin")]
        //for add new we use Http Post
        [HttpPost(Name = "AddEmployee")]
        [ProducesResponseType(StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public ActionResult<Employee> AddEmployee(Employee newEmployee)
        {
            //we validate the data here
            if (newEmployee == null || string.IsNullOrEmpty(newEmployee.Name) || newEmployee.Age < 0 || newEmployee.Salary < 0)
            {
                return BadRequest("Invalid Employee data.");
            }

            newEmployee.Id = EmployeeDataSimulation.EmployeesList.Count > 0 ? EmployeeDataSimulation.EmployeesList.Max(e => e.Id) + 1 : 1;
            EmployeeDataSimulation.EmployeesList.Add(newEmployee);
            
            //we dont return Ok here,we return createdAtRoute: this will be status code 201 created.
            return CreatedAtRoute("GetEmployeeById", new { id = newEmployee.Id }, newEmployee);

        }

        [Authorize(Roles = "Admin")]
        //here we use HttpDelete method
        [HttpDelete("{id}", Name = "DeleteEmployee")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public ActionResult DeleteEmployee(int id)
        {
            // ✅ Capture IP once for tracing (helps investigations later)
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

            // ✅ Identify the admin who is performing the action
            // ClaimTypes.NameIdentifier is what you put in JWT during login.
            var adminId = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? "unknown";

            // ===============================
            // Validation: invalid ID
            // ===============================
            if (id < 1)
            {
                // ✅ Audit attempt (invalid input) - still useful signal
                _logger.LogWarning(
                    "Admin action blocked (invalid id). AdminId={AdminId}, Action=DeleteEmployee, TargetId={TargetId}, IP={IP}",
                    adminId,
                    id,
                    ip
                );

                return BadRequest($"Not accepted ID {id}");
            }

            // ===============================
            // Find employee
            // ===============================
            var employee = EmployeeDataSimulation.EmployeesList.FirstOrDefault(s => s.Id == id);

            if (employee == null)
            {
                // ✅ Audit: admin attempted to delete a non-existing employee
                _logger.LogWarning(
                    "Admin action failed (target not found). AdminId={AdminId}, Action=DeleteEmployee, TargetId={TargetId}, IP={IP}",
                    adminId,
                    id,
                    ip
                );

                return NotFound($"Employee with ID {id} not found.");
            }

            // ===============================
            // Audit BEFORE deleting (recommended)
            // ===============================
            // ✅ Why before?
            // If delete throws or fails later, you still have the audit record of the attempt.
            _logger.LogInformation(
                "Admin action started. AdminId={AdminId}, Action=DeleteEmployee, TargetId={TargetId}, TargetEmail={TargetEmail}, IP={IP}",
                adminId,
                employee.Id,
                employee.Email,
                ip
            );

            // Perform deletion
            EmployeeDataSimulation.EmployeesList.Remove(employee);

            // ===============================
            // Audit AFTER deleting (optional, confirms success)
            // ===============================
            _logger.LogInformation(
                "Admin action succeeded. AdminId={AdminId}, Action=DeleteEmployee, TargetId={TargetId}, IP={IP}",
                adminId,
                id,
                ip
            );

            return Ok($"Employee with ID {id} has been deleted.");
        }

        [Authorize(Roles ="Admin")]
        //here we use http put method for update
        [HttpPut("{id}", Name = "UpdateEmployee")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public ActionResult<Employee> UpdateEmployee(int id, Employee updatedEmployee)
        {
            if (id < 1 || updatedEmployee == null || string.IsNullOrEmpty(updatedEmployee.Name) || updatedEmployee.Age < 0 || updatedEmployee.Salary < 0)
            {
                return BadRequest("Invalid Employee data.");
            }

            var Employee = EmployeeDataSimulation.EmployeesList.FirstOrDefault(s => s.Id == id);
            if (Employee == null)
            {
                return NotFound($"Student with ID {id} not found.");
            }

            Employee.Name = updatedEmployee.Name;
            Employee.Age = updatedEmployee.Age;
            Employee.Salary = updatedEmployee.Salary;

            return Ok(Employee);
        }


    }
}

using BCrypt.Net;
using EmployeeApi.Models;

namespace EmployeeApi.DataSimulation
{
    public class EmployeeDataSimulation
    {

        // Static list of employees, acting as an in-memory data store, you can change it later on to retrieve students from Database.
        public static readonly List<Employee> EmployeesList = new List<Employee>
        {
            // Initialize the list with some student objects.
            new Employee {
                Id = 1, Name = "Ali Ahmed", Age = 20, Salary = 4000 ,
                Email = "ali.ahmed1@employee.com",
                PasswordHash = BCrypt.Net.BCrypt.HashPassword("password1"),
                Role = "Employee"

            },
            new Employee { 
                Id = 2, Name = "Fadi Khalid", Age = 22,Salary=5000,
                Email = "fadi.khalid2@employee.com",
                PasswordHash = BCrypt.Net.BCrypt.HashPassword("password2"),
                Role = "Employee"
            },
            new Employee {
                Id = 3, Name = "Ola Jaber", Age = 21, Salary = 4400,
                Email = "ola.jaber3@employee.com",
                PasswordHash = BCrypt.Net.BCrypt.HashPassword("password3"),
                Role = "Employee"
            },
            new Employee {
                Id = 4, Name = "Alia Maher", Age = 19, Salary = 3500,
                Email = "alia.maher1@admin.com",
                PasswordHash = BCrypt.Net.BCrypt.HashPassword("admin1"),
                Role = "Admin"
            },
            new Employee {
                Id = 5, Name = "Mai Khalid", Age = 45, Salary = 7500,
                Email = "mai.khaled4@employee.com",
                PasswordHash = BCrypt.Net.BCrypt.HashPassword("password4"),
                Role = "Employee"
            },
            new Employee {
                Id = 6, Name = "Omar Rashed", Age = 52, Salary = 9000,
                Email = "omar.rashed2@admin.com",
                PasswordHash = BCrypt.Net.BCrypt.HashPassword("admin2"),
                Role = "Admin"
            }
        };

    }
}

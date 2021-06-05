using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace DotNetProject.Controllers
{

    [Authorize (Roles="SuperAdmin, Admin, SubAdmin")]
    public class RoleController : Controller
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        public RoleController(RoleManager<IdentityRole> roleManager)
        {
            _roleManager = roleManager;
        }
        public async Task<IActionResult> Index()
        {
            var roles = await _roleManager.Roles.ToListAsync();
            return View(roles);
        }

        [Authorize(Policy = "CreateRolePolicy")]
        [HttpPost]
        public async Task<IActionResult> AddRole(string roleName)
        {
            if (roleName != null)
            {
                await _roleManager.CreateAsync(new IdentityRole(roleName.Trim()));
            }
            return RedirectToAction("Index");
        }


        public async Task<IActionResult> DeleteRole()        {            var roles = await _roleManager.Roles.ToListAsync();            return View(roles);        }        [HttpPost]
        [Authorize(Policy = "DeleteRolePolicy")]        public async Task<IActionResult> DeleteRole(string id)        {            var role = await _roleManager.FindByIdAsync(id);            if (role == null)            {                ViewBag.ErrorMessage = $"Role with ID = {id} cannot be found";                return View("NotFound");            }            else            {                var result = await _roleManager.DeleteAsync(role);                if (result.Succeeded)                {                    return RedirectToAction("Index");                }                foreach (var error in result.Errors)                {                    ModelState.AddModelError("", error.Description);                }                return View("Index");            }        }


    }
}
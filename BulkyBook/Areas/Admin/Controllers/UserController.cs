using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using BulkyBook.DataAccess.Data;
using BulkyBook.DataAccess.Repository.IRepository;
using BulkyBook.Models;
using BulkyBook.Utility;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
namespace BulkyBook.Areas.Admin.Controllers
{
    [Area("Admin")]
    [Authorize(Roles = SD.Role_Admin + "," + SD.Role_Employee)]
    public class UserController : Controller
    {
        //======= !!! NOTE !!! ==================
        //for an example here we are using dbcontext instead of repository pattern
        //in production don't cross-use both
        private readonly ApplicationDbContext _db;
        private UserManager<IdentityUser> userManager { get; }
       

        public UserController(ApplicationDbContext db, UserManager<IdentityUser> userManager)
        {
            _db = db;
            this.userManager = userManager;
        }

        public IActionResult Index()
        {
            int? currentUserCount = HttpContext.Session.GetInt32("regCount");
            int? userCountStart = HttpContext.Session.GetInt32("regCountStart");
            ViewBag.userCount = currentUserCount;
            ViewBag.userCountStart = userCountStart;
            string alrmTxt = "Only Admins!";
            ViewBag.alarmText1 = alrmTxt;
           // ViewBag.alarmText2 = "You can create only one new user!";

            var userList = _db.ApplicationUsers.Include(u => u.Company).ToList();
            var userRole = _db.UserRoles.ToList();
            var roles = _db.Roles.ToList();
            foreach (var user in userList)
            {
                var roleId = userRole.FirstOrDefault(u => u.UserId == user.Id).RoleId;
                user.Role = roles.FirstOrDefault(u => u.Id == roleId).Name;
                if (user.Company == null)
                {
                    user.Company = new Company()
                    {
                        Name = ""
                    };
                }
            }
            return View(userList);
        }



        #region API CALLS

        [HttpGet]
        public IActionResult GetAll()
        {
            var userList = _db.ApplicationUsers.Include(u => u.Company).ToList();
            var userRole = _db.UserRoles.ToList();
            var roles = _db.Roles.ToList();
            
            foreach (var user in userList)
            {
                var roleId = userRole.FirstOrDefault(u => u.UserId == user.Id).RoleId;
                user.Role = roles.FirstOrDefault(u => u.Id == roleId).Name;
                if (user.Company == null)
                {
                    user.Company = new Company()
                    {
                        Name = ""
                    };
                }
            }
            return Json(new { data = userList });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult LockUnlock([FromBody] string id)
        {
            var objFromDb = _db.ApplicationUsers.FirstOrDefault(u => u.Id == id);
            if (objFromDb == null)
            {
                return Json(new { success = false, message = "Error while Locking/Unlocking" });
            }
            if (objFromDb.LockoutEnd != null && objFromDb.LockoutEnd > DateTime.Now)
            {
                //user is currently locked, we will unlock them
                objFromDb.LockoutEnd = DateTime.Now;
            }
            else
            {
                objFromDb.LockoutEnd = DateTime.Now.AddYears(1000);
            }
            _db.SaveChanges();
            return Json(new { success = true, message = "Operation Successful." });
        }

        [Authorize(Roles = SD.Role_Admin)]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult>Delete(string id)
        {
            if (id == null)
            {
                return NotFound();
            }            
            var tempUser = await userManager.FindByIdAsync(id); //_db.Users FirstOrDefaultAsync(s => s.Id == id);
            if (await userManager.IsInRoleAsync(tempUser, SD.Role_Admin))
            {
                return RedirectToAction(nameof(Index));
            }
            if (tempUser == null)
            {
                return NotFound();
            }
            else
            {
                await userManager.DeleteAsync(tempUser);
            }

            return RedirectToAction("Index");
        }

        
        #endregion
    }
}
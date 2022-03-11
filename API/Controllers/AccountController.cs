using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController : BaseApiController
    {
        private readonly DataContext _context;
        private readonly ITokenService _tokenService;
        public AccountController(DataContext context, ITokenService tokenService)
        {
            _tokenService = tokenService;
            _context = context;
        }

        [HttpPost("register")]
        public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto)
        {
            //we are able to return BadRequest because it is part of ActionResult
            if(await UserExists(registerDto.Username)) return BadRequest("Username is taken");

            using var hmac = new HMACSHA512();

            var user = new AppUser
            {
                UserName = registerDto.Username.ToLower(), //all username should be saved as lowercase

                //the PasswordHash is bytes type, so we have to convert string password into bytes type. 
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
                //the PasswordSalt 
                PasswordSalt = hmac.Key
            };
            _context.Users.Add(user); //this not adding anything to the database but adding a tracker entity framework
            await _context.SaveChangesAsync(); //this actually save the changes into database

            return new UserDto
            {
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)
            };
        }

        [HttpPost("login")]
        public async Task<ActionResult<UserDto>> Login(LoginDto loginDto)
        {
            var user = await _context.Users.SingleOrDefaultAsync(x => x.UserName == loginDto.Username);

            if (user == null) return Unauthorized("Invalid username");
            
            using var hmac = new HMACSHA512(user.PasswordSalt); //create a hmac with existing PasswordSalt as key
            var computeHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password)); //hash the login request password with the passwordsalt key
                                                                                            // so we can compare this with the stored computeHash password.
            //compare the password by compare each element of the two string 
            for(int i = 0; i < computeHash.Length; i++)
            {
                if (computeHash[i] != user.PasswordHash[i]) return Unauthorized("Invalid password");
            }

            //if the passwords are match then
            return new UserDto
            {
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)
            };

        }

        // making username unique since we will use usernames for many other things
        private async Task<bool> UserExists(string username)
        {
            //we are returning true or false
            //AnyAsync mean check to see any user in the database has the username
            //make sure to lowercase username 
            return await _context.Users.AnyAsync(x => x.UserName == username.ToLower());
        }
    }
}
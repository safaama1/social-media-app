using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using API.Entities;
using API.Interfaces;
using Microsoft.IdentityModel.Tokens;

namespace API.Services
{
    public class TokenService : ITokenService
    {
        // * a symmetric key is one that is used both to encrypt and decrypt token
        private readonly SymmetricSecurityKey _key;
        public TokenService(IConfiguration config)
        {
            _key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["TokenKey"]));
        }

        public string CreateToken(AppUser user)
        {
            // * claims => data to store in the token 
            var claims = new List<Claim>{
                // * NameId : "$Username"
                new Claim(JwtRegisteredClaimNames.NameId, user.UserName)
            };


            var creds = new SigningCredentials(_key, SecurityAlgorithms.HmacSha512Signature);

            // * tokenDescriptor -> what the token contains  
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims), // * data 
                Expires = DateTime.Now.AddDays(7), // * expiration date of the token
                SigningCredentials = creds
            };

            var tokenHandler = new JwtSecurityTokenHandler();

            var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
        }
    }
}
using LearnWeb.Attributes;
using LearnWeb.BL;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace LearnWeb.Controllers
{
    
    [Route("api/[controller]")]
    [ApiController]
    public class TestController : ControllerBase
    {
        private ITest _iTest;
        public TestController (ITest test)
        {
            _iTest = test;
        }

 
        
        [HttpGet("get")]
        public string Get()
        {
            string test = string.Empty;
            if (HttpContext.Request.Headers.ContainsKey("Test"))
            {
                test = HttpContext.Request.Headers["Test"];
            }

            test = "Dũng đẹp trai";

            //return _iTest.Get();
            return test;

        }

        [HttpPost("genToken")]
        public string GenToken([FromQuery] string userName , [FromQuery] string pass)
        {
            string test = _iTest.GenToken(userName, pass);
            return test;

        }

        [HttpPost("verify")]
        public string VerifyToken([FromQuery] string token)
        {
            string key = string.Empty;
            if (HttpContext.Request.Headers.ContainsKey("key"))
            {
                key = HttpContext.Request.Headers["key"];
            }
            string test = _iTest.Decode(token, key,true);
            return test;

        }
    }
}

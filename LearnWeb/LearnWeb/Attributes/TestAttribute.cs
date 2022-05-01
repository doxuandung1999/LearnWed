using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace LearnWeb.Attributes
{
    [AttributeUsage(AttributeTargets.All)]
    public class TestAttribute : Attribute, IAuthorizationFilter
    {
        public void OnAuthorization(AuthorizationFilterContext filterContext)
        {
            var hasClaim = filterContext.HttpContext.User.Identities.FirstOrDefault().Claims;
            if (filterContext.HttpContext.User.Identity.IsAuthenticated)
            {
                return;
            }
            else
            {

                filterContext.Result = new ObjectResult(new { success = false, subCode = 401 });
                return;

            }
        }



    }
}

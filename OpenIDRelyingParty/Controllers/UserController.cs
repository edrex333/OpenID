using System;
using System.Web.Mvc;
using System.Web.Security;
using DotNetOpenAuth.Messaging;
using DotNetOpenAuth.OpenId;
using DotNetOpenAuth.OpenId.Extensions.AttributeExchange;
using DotNetOpenAuth.OpenId.RelyingParty;

namespace OpenIDRelyingParty.Controllers
{
    public class UserController : Controller
    {
        private static readonly OpenIdRelyingParty openId = new OpenIdRelyingParty();

        /// <summary>
        /// Indexes this instance.
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        public ActionResult Index()
        {
            return View();
        }

        /// <summary>
        /// Logs the off.
        /// </summary>
        /// <returns></returns>
        public ActionResult LogOff()
        {
            FormsAuthentication.SignOut();

            return RedirectToAction("Index", "Home");
        }

        /// <summary>
        /// Authenticates this instance.
        /// </summary>
        /// <param name="returnUrl">The return URL.</param>
        /// <returns></returns>
        public ActionResult Authenticate(string returnUrl)
        {
            var response = openId.GetResponse();

            if (response == null)
            {
                return this.HandleNullOpenIdResponse();
            }

            return this.HandleOpenIdResponse(response, returnUrl);
        }

        /// <summary>
        /// Handles the null open id response.
        /// </summary>
        /// <returns></returns>
        private ActionResult HandleNullOpenIdResponse()
        {
            var openIdIdentifier = this.Request.Form["openid_identifier"];

            Identifier identifier;
            if (Identifier.TryParse(openIdIdentifier, out identifier))
            {
                try
                {
                    var request = this.CreateOpenIdRequest(identifier);
                    return request.RedirectingResponse.AsActionResult();
                }
                catch (Exception e)
                {
                    ViewBag.ErrorMessage = e.Message;
                    return this.View("Index");
                }
            }
            ViewBag.ErrorMessage = string.Format("Invalid identifier: {0}", openIdIdentifier);
            return this.View("Index");
        }

        /// <summary>
        /// Creates the open id request.
        /// </summary>
        /// <param name="identifier">The identifier.</param>
        /// <returns></returns>
        private IAuthenticationRequest CreateOpenIdRequest(Identifier identifier)
        {
            var request = openId.CreateRequest(identifier);
            var fetchRequest = CreateFetchRequest();
            request.AddExtension(fetchRequest);
            return request;
        }

        /// <summary>
        /// Creates the fetch request.
        /// </summary>
        /// <returns></returns>
        private static FetchRequest CreateFetchRequest()
        {
            var fetchRequest = new FetchRequest();
            fetchRequest.Attributes.AddRequired(WellKnownAttributes.Contact.Email);
            fetchRequest.Attributes.AddRequired(WellKnownAttributes.Name.FullName);
            return fetchRequest;
        }

        /// <summary>
        /// Handles the open id response.
        /// </summary>
        /// <param name="response">The response.</param>
        /// <param name="returnUrl">The return URL.</param>
        /// <returns></returns>
        private ActionResult HandleOpenIdResponse(IAuthenticationResponse response, string returnUrl)
        {
            switch (response.Status)
            {
                case AuthenticationStatus.Authenticated:
                    var fetchResponse = response.GetExtension<FetchResponse>();

                    var fullName = "";
                    var emailAddress = "";

                    if (fetchResponse != null)
                    {
                        if (fetchResponse.Attributes.Contains(WellKnownAttributes.Name.FullName))
                        {
                            fullName = fetchResponse.Attributes[WellKnownAttributes.Name.FullName].Values[0];
                        }

                        if (fetchResponse.Attributes.Contains(WellKnownAttributes.Contact.Email))
                        {
                            emailAddress = fetchResponse.Attributes[WellKnownAttributes.Contact.Email].Values[0];
                        }
                    }

                    if (!string.IsNullOrEmpty(fullName))
                    {
                        FormsAuthentication.SetAuthCookie(fullName, false);
                    }
                    else if (!string.IsNullOrEmpty(emailAddress))
                    {
                        FormsAuthentication.SetAuthCookie(emailAddress, false);
                    }
                    else
                    {
                        FormsAuthentication.SetAuthCookie(response.ClaimedIdentifier, false);
                    }

                    Session["ProviderURL"] = response.FriendlyIdentifierForDisplay;
                    Session["ClaimedIdentifier"] = response.ClaimedIdentifier.ToString();
                    Session["FetchResponse"] = fetchResponse;

                    if (!string.IsNullOrEmpty(returnUrl))
                    {
                        return this.Redirect(returnUrl);
                    }
                    return this.RedirectToAction("Index", "Home");

                case AuthenticationStatus.Canceled:
                    ViewBag.ErrorMessage = "User canceled at provider.";
                    return this.View("Index");

                case AuthenticationStatus.Failed:
                    ViewBag.ErrorMessage = response.Exception.Message;
                    return this.View("Index");

                default:
                    return new EmptyResult();
            }
        }
    }
}

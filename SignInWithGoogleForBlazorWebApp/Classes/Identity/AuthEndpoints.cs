using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;
using Google.Apis.Auth;

namespace SignInWithGoogleForBlazorWebApp.Classes.Identity;

public static class AuthEndpoints
{
    public static IEndpointRouteBuilder MapSigninWithGoogleEndpoints(this IEndpointRouteBuilder app, IConfiguration configuration)
    {
        var googleClientId = configuration["Authentication:Google:ClientId"];

        app.MapPost("/auth/callback", async (HttpContext httpContext) =>
        {
            var credential = httpContext.Request.Form["credential"];

            if (string.IsNullOrEmpty(credential))
            {
                var form = await httpContext.Request.ReadFormAsync();
                form.TryGetValue("credential", out credential);
            }

            if (!string.IsNullOrEmpty(credential))
            {
                var payload = await ValidateGoogleTokenAsync(credential, googleClientId);

                // Store the claims or user info temporarily, e.g., in a session or as a URL parameter
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.PrimarySid, payload.Subject),
                    new Claim(ClaimTypes.Email, payload.Email),
                    new Claim(ClaimTypes.Name, payload.Name),
                    new Claim(ClaimTypes.GivenName, payload.GivenName),
                    new Claim(ClaimTypes.Surname, payload.FamilyName),
                    new Claim(ClaimTypes.Actor, payload.Picture),
                    new Claim(ClaimTypes.NameIdentifier, payload.JwtId),
                };

                var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var principal = new ClaimsPrincipal(identity);

                // Sign in the user
                await httpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

                return Results.Redirect("/", true);
            }

            // Get the email claim from Google's response
            return Results.Redirect("/", true);
        });

        app.MapGet("/auth/logout", async (HttpContext httpContext) =>
        {
            await httpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            return Results.Redirect("/", true);
        });

        return app;
    }

    private static async Task<GoogleJsonWebSignature.Payload?> ValidateGoogleTokenAsync(string idToken, string? googleClientId)
    {
        try
        {
            var settings = new GoogleJsonWebSignature.ValidationSettings()
            {
                Audience = new[] { googleClientId }
            };
            var payload = await GoogleJsonWebSignature.ValidateAsync(idToken, settings);
            return payload;
        }
        catch (Exception ex)
        {
            await Console.Error.WriteLineAsync($"Token validation failed: {ex.Message}");
            return null;
        }
    }
}
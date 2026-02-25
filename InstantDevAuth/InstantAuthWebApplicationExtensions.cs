using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace InstantDevAuth;

/// <summary>
/// Extension methods for configuring InstantDevAuth middleware and endpoints.
/// </summary>
public static class InstantAuthWebApplicationExtensions
{
    /// <summary>
    /// Adds authentication and authorization middlewares, emits a startup warning, and maps
    /// the token generation endpoint.
    /// </summary>
    /// <param name="app">The web application.</param>
    public static WebApplication UseInstantDevAuth(this WebApplication app)
    {
        // Startup warning
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("⚠️  WARNING: InstantDevAuth is active. Do not use in Production.");
        Console.ResetColor();

        app.UseAuthentication();
        app.UseAuthorization();

        var options = app.Services.GetRequiredService<InstantDevAuthOptions>();

        app.MapPost(options.TokenRoute, (TokenGenerationRequest request) =>
        {
            var keyBytes = Encoding.UTF8.GetBytes(options.SecretKey!);
            var signingCredentials = new SigningCredentials(
                new SymmetricSecurityKey(keyBytes),
                SecurityAlgorithms.HmacSha256);

            var expiresInMinutes = request.ExpiresInMinutes ?? options.DefaultExpiresInMinutes;
            var expiresAt = DateTime.UtcNow.AddMinutes(expiresInMinutes);

            var claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub, request.Username),
                new(JwtRegisteredClaimNames.UniqueName, request.Username),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            foreach (var role in request.Roles)
            {
                claims.Add(new Claim("role", role));
            }

            foreach (var (key, value) in request.ExtraClaims)
            {
                claims.Add(new Claim(key, value));
            }

            var tokenDescriptor = new JwtSecurityToken(
                issuer: options.Issuer,
                audience: options.Audience,
                claims: claims,
                expires: expiresAt,
                signingCredentials: signingCredentials);

            var tokenString = new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);

            return Results.Ok(new
            {
                token = tokenString,
                expiresAt
            });
        })
        .WithName("GenerateDevToken")
        .WithTags("InstantDevAuth")
        .AllowAnonymous();

        return app;
    }
}

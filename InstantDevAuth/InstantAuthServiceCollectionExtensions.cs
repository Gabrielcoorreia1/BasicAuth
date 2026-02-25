using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

namespace InstantDevAuth;

/// <summary>
/// Extension methods for registering InstantDevAuth services.
/// </summary>
public static class InstantAuthServiceCollectionExtensions
{
    /// <summary>
    /// Registers JWT authentication and Swagger (with JWT security UI) for rapid prototyping.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Optional delegate to configure <see cref="InstantDevAuthOptions"/>.</param>
    public static IServiceCollection AddInstantDevAuth(
        this IServiceCollection services,
        Action<InstantDevAuthOptions>? configure = null)
    {
        var options = new InstantDevAuthOptions();
        configure?.Invoke(options);

        // Zero-config: generate a random key if none is provided
        if (string.IsNullOrWhiteSpace(options.SecretKey))
        {
            options.SecretKey = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
        }

        // Store options as a singleton so the endpoint handler can access them
        services.AddSingleton(options);

        var keyBytes = Encoding.UTF8.GetBytes(options.SecretKey);
        var signingKey = new SymmetricSecurityKey(keyBytes);

        services
            .AddAuthentication(authOptions =>
            {
                authOptions.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                authOptions.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(jwtOptions =>
            {
                jwtOptions.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = signingKey,
                    ValidateIssuer = true,
                    ValidIssuer = options.Issuer,
                    ValidateAudience = true,
                    ValidAudience = options.Audience,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero,
                    // Map standard JWT claim names to .NET ClaimTypes
                    NameClaimType = "unique_name",
                    RoleClaimType = "role"
                };
            });

        services.AddAuthorization();

        services.AddEndpointsApiExplorer();
        services.AddSwaggerGen(swaggerOptions =>
        {
            var securityScheme = new OpenApiSecurityScheme
            {
                Name = "Authorization",
                Description = "Enter the Bearer token: **Bearer {your token}**",
                In = ParameterLocation.Header,
                Type = SecuritySchemeType.ApiKey,
                Scheme = JwtBearerDefaults.AuthenticationScheme,
                BearerFormat = "JWT"
            };

            swaggerOptions.AddSecurityDefinition(JwtBearerDefaults.AuthenticationScheme, securityScheme);

            swaggerOptions.AddSecurityRequirement(new OpenApiSecurityRequirement
            {
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type = ReferenceType.SecurityScheme,
                            Id = JwtBearerDefaults.AuthenticationScheme
                        }
                    },
                    Array.Empty<string>()
                }
            });
        });

        return services;
    }
}

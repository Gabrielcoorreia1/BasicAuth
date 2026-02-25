namespace InstantDevAuth;

/// <summary>
/// Configuration options for InstantDevAuth.
/// </summary>
public class InstantDevAuthOptions
{
    /// <summary>
    /// Secret key used to sign JWT tokens. If null or empty, a random GUID-based key is
    /// generated at startup and lost on restart (zero-config mode).
    /// </summary>
    public string? SecretKey { get; set; }

    /// <summary>
    /// Issuer claim for generated tokens. Defaults to "InstantDevAuth".
    /// </summary>
    public string Issuer { get; set; } = "InstantDevAuth";

    /// <summary>
    /// Audience claim for generated tokens. Defaults to "InstantDevAuthAudience".
    /// </summary>
    public string Audience { get; set; } = "InstantDevAuthAudience";

    /// <summary>
    /// Route for the token generation endpoint. Defaults to "/api/dev/token".
    /// </summary>
    public string TokenRoute { get; set; } = "/api/dev/token";

    /// <summary>
    /// Default token expiration in minutes when not specified in the request. Defaults to 120.
    /// </summary>
    public int DefaultExpiresInMinutes { get; set; } = 120;
}

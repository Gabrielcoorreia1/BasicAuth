namespace InstantDevAuth;

/// <summary>
/// Request body for the token generation endpoint.
/// </summary>
public class TokenGenerationRequest
{
    /// <summary>
    /// Username to embed in the token's <c>sub</c> and <c>unique_name</c> claims.
    /// </summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// Roles to assign in the token's <c>role</c> claim.
    /// </summary>
    public List<string> Roles { get; set; } = new();

    /// <summary>
    /// Additional custom claims to embed in the token.
    /// </summary>
    public Dictionary<string, string> ExtraClaims { get; set; } = new();

    /// <summary>
    /// Token lifetime in minutes. If null, the value from <see cref="InstantDevAuthOptions.DefaultExpiresInMinutes"/> is used.
    /// </summary>
    public int? ExpiresInMinutes { get; set; }
}

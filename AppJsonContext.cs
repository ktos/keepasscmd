using System.Text.Json.Serialization;

record CredentialsOutput(
    [property: JsonPropertyName("username")] string Username,
    [property: JsonPropertyName("password")] string Password
);

[JsonSerializable(typeof(Pairing))]
[JsonSerializable(typeof(CredentialsOutput))]
internal partial class AppJsonContext : JsonSerializerContext;

using System.Net.WebSockets;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

record Pairing(string Username, string Key);

record EntryCredentials(string Username, string Password);

// KeePassRPC's SRP, challenge/response and encrypted JSON-RPC wire formats.
sealed class KeePassRpcClient : IDisposable
{
    const int Version = (2 << 16) | 2;

    static readonly BigInteger N = Number(
        "D4C7F8A2B32C11B8FBA9581EC4BA4F1B04215642EF7355E37C0FC0443EF756EA2C6B8EEB755A1C723027663CAA265EF785B8FF6A9B35227A52D86633DBDFCA43"
    );

    readonly ClientWebSocket socket = new();

    byte[]? key;

    public async Task Connect()
    {
        // this custom origin should be configured in KeePassRPC
        socket.Options.SetRequestHeader("Origin", "keepasscmd://localhost");
        await socket.ConnectAsync(new Uri("ws://127.0.0.1:12546/"), CancellationToken.None);
    }

    public async Task<Pairing> Pair()
    {
        var username = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var a = new BigInteger(RandomNumberGenerator.GetBytes(32), true, true);
        var A = BigInteger.ModPow(2, a, N);

        var identify = IdentityMessage();
        identify["srp"] = new JsonObject
        {
            ["stage"] = "identifyToServer",
            ["I"] = username,
            ["A"] = Hex(A),
            ["securityLevel"] = 2,
        };

        await Send(identify);

        var response = await Receive();
        var srp = Setup(response, "srp");
        if (Text(srp, "stage") != "identifyToClient")
            throw new InvalidOperationException("Unexpected SRP response.");

        var B = Number(Text(srp, "B"));
        if (B <= 0 || B % N == 0)
            throw new InvalidOperationException("Invalid server SRP value.");
        Console.Error.Write("Enter the one-time code displayed by KeePass: ");

        var password = Console.ReadLine();
        if (string.IsNullOrWhiteSpace(password))
            throw new InvalidOperationException("No authorization code entered.");

        var x = HashNumber(Text(srp, "s") + password.Trim());
        var u = HashNumber(Hex(A) + Hex(B));
        var paddedGenerator = new byte[64];
        paddedGenerator[^1] = 2;

        var k = new BigInteger(
            SHA1.HashData(N.ToByteArray(true, true).Concat(paddedGenerator).ToArray()),
            true,
            true
        );

        var basis = ((B - k * BigInteger.ModPow(2, x, N)) % N + N) % N;
        var S = BigInteger.ModPow(basis, a + u * x, N);
        var mBytes = SHA256.HashData(Encoding.UTF8.GetBytes(Hex(A) + Hex(B) + Hex(S)));
        var expected = HashNumber(Hex(A) + Convert.ToHexString(mBytes).ToLowerInvariant() + Hex(S));

        await Send(
            new JsonObject
            {
                ["protocol"] = "setup",
                ["version"] = Version,
                ["srp"] = new JsonObject
                {
                    ["stage"] = "proofToServer",
                    ["M"] = Convert.ToHexString(mBytes),
                    ["securityLevel"] = 2,
                },
            }
        );

        srp = Setup(await Receive(), "srp");
        if (Text(srp, "stage") != "proofToClient" || Number(Text(srp, "M2")) != expected)
            throw new InvalidOperationException("KeePass SRP proof verification failed.");

        key = SHA256.HashData(Encoding.UTF8.GetBytes(Hex(S)));

        return new Pairing(username, Convert.ToHexString(key).ToLowerInvariant());
    }

    public async Task Authenticate(Pairing pairing)
    {
        var secret = pairing.Key;
        key = Convert.FromHexString(secret);
        if (key.Length != 32)
            throw new InvalidOperationException("Invalid pairing key. Run 'auth' again.");

        var identify = IdentityMessage();
        identify["key"] = new JsonObject { ["username"] = pairing.Username, ["securityLevel"] = 2 };

        await Send(identify);

        var challenge = Setup(await Receive(), "key");
        var sc = Text(challenge, "sc");
        var cc = Convert
            .ToHexString(RandomNumberGenerator.GetBytes(32))
            .ToLowerInvariant()
            .TrimStart('0');

        string Digest(string prefix) =>
            Convert
                .ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(prefix + secret + sc + cc)))
                .ToLowerInvariant();

        await Send(
            new JsonObject
            {
                ["protocol"] = "setup",
                ["version"] = Version,
                ["key"] = new JsonObject
                {
                    ["cc"] = cc,
                    ["cr"] = Digest("1"),
                    ["securityLevel"] = 2,
                },
            }
        );

        var result = Setup(await Receive(), "key");
        if (
            !CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(Text(result, "sr")),
                Encoding.ASCII.GetBytes(Digest("0"))
            )
        )
            throw new InvalidOperationException(
                "KeePass key proof verification failed. Run 'auth' again."
            );
    }

    public async Task<EntryCredentials> GetEntry(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            throw new InvalidOperationException("Entry name cannot be empty.");

        var request = Encoding.UTF8.GetBytes(
            new JsonObject
            {
                ["method"] = "FindLogins",
                ["params"] = new JsonArray(
                    new JsonArray(),
                    "",
                    "",
                    "LSTall",
                    false,
                    "",
                    "",
                    name,
                    ""
                ),
                ["id"] = 1,
            }.ToJsonString()
        );

        using var aes = Aes.Create();
        aes.Key = key!;
        aes.GenerateIV();

        var ciphertext = aes.EncryptCbc(request, aes.IV);
        byte[] Mac(byte[] c, byte[] iv) =>
            SHA1.HashData(SHA1.HashData(key!).Concat(c).Concat(iv).ToArray());

        await Send(
            new JsonObject
            {
                ["protocol"] = "jsonrpc",
                ["version"] = Version,
                ["jsonrpc"] = new JsonObject
                {
                    ["message"] = Convert.ToBase64String(ciphertext),
                    ["iv"] = Convert.ToBase64String(aes.IV),
                    ["hmac"] = Convert.ToBase64String(Mac(ciphertext, aes.IV)),
                },
            }
        );

        while (true)
        {
            var envelope = await Receive();
            var jsonrpc = Setup(envelope, "jsonrpc");
            var c = Convert.FromBase64String(Text(jsonrpc, "message"));
            var iv = Convert.FromBase64String(Text(jsonrpc, "iv"));
            var mac = Convert.FromBase64String(Text(jsonrpc, "hmac"));

            if (!CryptographicOperations.FixedTimeEquals(mac, Mac(c, iv)))
                throw new InvalidOperationException("KeePass message authentication failed.");

            using var document = JsonDocument.Parse(aes.DecryptCbc(c, iv));
            var result = document.RootElement;

            if (
                !result.TryGetProperty("id", out var id)
                || id.ValueKind != JsonValueKind.Number
                || id.GetInt32() != 1
            )
                continue;
            if (
                result.TryGetProperty("error", out var error)
                && error.ValueKind != JsonValueKind.Null
            )
                throw new InvalidOperationException("KeePass RPC error: " + error);

            var entries = result.GetProperty("result");
            if (entries.ValueKind != JsonValueKind.Array)
                throw new InvalidOperationException(
                    "KeePass database is not open or returned no results."
                );

            var matches = entries.EnumerateArray().Where(e => Text(e, "title") == name).ToArray();
            if (matches.Length == 0)
                throw new InvalidOperationException("No entry with that exact title was found.");
            if (matches.Length > 1)
                throw new InvalidOperationException(
                    "Multiple entries have that title; refusing to choose one."
                );

            string? username = null,
                password = null;

            foreach (var field in matches[0].GetProperty("formFieldList").EnumerateArray())
            {
                var type = Text(field, "type");
                if (
                    username == null
                    && type.Equals("FFTusername", StringComparison.OrdinalIgnoreCase)
                )
                    username = Text(field, "value");
                if (
                    password == null
                    && type.Equals("FFTpassword", StringComparison.OrdinalIgnoreCase)
                )
                    password = Text(field, "value");
            }

            if (password == null)
                throw new InvalidOperationException(
                    "Entry has no password field available through KeePassRPC."
                );

            return new EntryCredentials(username ?? "", password);
        }
    }

    static JsonObject IdentityMessage() =>
        new()
        {
            ["protocol"] = "setup",
            ["version"] = Version,
            ["clientTypeID"] = "keepasscmd",
            ["clientDisplayName"] = "KeePassCmd",
            ["clientDisplayDescription"] = "Local command-line client",
        };

    async Task Send(JsonObject message) =>
        await socket.SendAsync(
            Encoding.UTF8.GetBytes(message.ToJsonString()),
            WebSocketMessageType.Text,
            true,
            CancellationToken.None
        );

    async Task<JsonElement> Receive()
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        WebSocketReceiveResult result;

        do
        {
            result = await socket.ReceiveAsync(
                new ArraySegment<byte>(chunk),
                CancellationToken.None
            );

            if (result.MessageType == WebSocketMessageType.Close)
                throw new InvalidOperationException(
                    "KeePass closed the connection. Check the plugin origin configuration and authorization."
                );

            buffer.Write(chunk, 0, result.Count);

            if (buffer.Length > 16 * 1024 * 1024)
                throw new InvalidOperationException("KeePass response exceeds 16 MB.");
        } while (!result.EndOfMessage);

        using var document = JsonDocument.Parse(buffer.ToArray());

        return document.RootElement.Clone();
    }

    static JsonElement Setup(JsonElement envelope, string property)
    {
        if (
            envelope.TryGetProperty("error", out var error)
            && error.ValueKind != JsonValueKind.Null
        )
            throw new InvalidOperationException("KeePassRPC error: " + error);
        if (
            !envelope.TryGetProperty(property, out var value)
            || value.ValueKind != JsonValueKind.Object
        )
            throw new InvalidOperationException("Unexpected KeePassRPC response.");
        return value;
    }

    static string Text(JsonElement value, string property) =>
        value.GetProperty(property).GetString() ?? "";

    static BigInteger Number(string hex) =>
        new(Convert.FromHexString(hex.Length % 2 == 0 ? hex : "0" + hex), true, true);

    static string Hex(BigInteger number) =>
        Convert.ToHexString(number.ToByteArray(true, true)).TrimStart('0') is { Length: > 0 } hex
            ? hex
            : "0";

    static BigInteger HashNumber(string text) =>
        new(SHA256.HashData(Encoding.UTF8.GetBytes(text)), true, true);

    public void Dispose()
    {
        if (key != null)
            CryptographicOperations.ZeroMemory(key);
        socket.Dispose();
    }
}

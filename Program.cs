using System.CommandLine;
using System.Security.Cryptography;
using System.Text.Json;

var root = new RootCommand("Retrieve passwords from a running KeePassRPC instance.");
var auth = new Command("auth", "Authorize this application in KeePass.");
var get = new Command("get", "Print the password for an exact entry title.");
var name = new Argument<string>("name") { Description = "Exact KeePass entry title" };
var json = new Option<bool>("--json") { Description = "Print username and password as JSON" };
get.Arguments.Add(name);
get.Options.Add(json);
root.Subcommands.Add(auth);
root.Subcommands.Add(get);

auth.SetAction(async _ =>
    await Run(async () =>
    {
        if (!OperatingSystem.IsWindows())
            throw new InvalidOperationException("Pairing storage requires Windows DPAPI.");

        using var client = new KeePassRpcClient();
        await client.Connect();
        var pairing = await client.Pair();
        var path = PairingPath();
        
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var data = JsonSerializer.SerializeToUtf8Bytes(pairing, AppJsonContext.Default.Pairing);
        await File.WriteAllBytesAsync(
            path,
            ProtectedData.Protect(data, null, DataProtectionScope.CurrentUser)
        );
        
        CryptographicOperations.ZeroMemory(data);
        Console.Error.WriteLine("Authorization saved.");
    })
);

get.SetAction(async parse =>
    await Run(async () =>
    {
        if (!OperatingSystem.IsWindows())
            throw new InvalidOperationException("Pairing storage requires Windows DPAPI.");

        var path = PairingPath();
        if (!File.Exists(path))
            throw new InvalidOperationException("Not authorized. Run 'auth' first.");
        
        var data = ProtectedData.Unprotect(
            await File.ReadAllBytesAsync(path),
            null,
            DataProtectionScope.CurrentUser
        );
        
        Pairing pairing;
        try
        {
            pairing = JsonSerializer.Deserialize(data, AppJsonContext.Default.Pairing)
                ?? throw new InvalidOperationException("Invalid pairing data.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(data);
        }
        
        using var client = new KeePassRpcClient();
        await client.Connect();
        await client.Authenticate(pairing);
        
        var entry = await client.GetEntry(parse.GetValue(name)!);
        
        Console.WriteLine(
            parse.GetValue(json)
                ? JsonSerializer.Serialize(
                    new CredentialsOutput(entry.Username, entry.Password),
                    AppJsonContext.Default.CredentialsOutput
                )
                : entry.Password
        );
    })
);
return await root.Parse(args).InvokeAsync();

static string PairingPath() =>
    Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "KeePassCmd",
        "pairing.dat"
    );

static async Task<int> Run(Func<Task> action)
{
    try
    {
        await action();
        return 0;
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Error: {ex.Message}");
        return 1;
    }
}

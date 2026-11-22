# AGENTS.md

## Project

KeePassCmd is a small Windows-only .NET CLI (`net11.0`) that fetches passwords from a running KeePass via the KeePassRPC WebSocket plugin (`ws://127.0.0.1:12546/`). See `README.md` for user-facing setup and usage.

## Layout

- `Program.cs`: top-level statements. Defines the `System.CommandLine` commands (`auth`, `get [--json]`), pairing storage, and the `Run` error wrapper.
- `KeePassRpcClient.cs`: the KeePassRPC protocol client (SRP pairing, key challenge/response authentication, AES-CBC + SHA1-MAC encrypted JSON-RPC `FindLogins`). Also holds the `Pairing` and `EntryCredentials` records.
- `AppJsonContext.cs`: System.Text.Json source-generated context and `CredentialsOutput`. Any type serialized with `JsonSerializer` must be registered here.
- `bin/` and `obj/` are build output; don't edit them.

## Build and run

- Build: `dotnet build`
- Run: `dotnet run -- auth` or `dotnet run -- get "Entry title" [--json]`
- There are no tests or linter configuration. Verify changes by building. Real behavior needs a running KeePass with KeePassRPC and a paired client.

## Conventions

- Nullable reference types and implicit usings are enabled.
- Use the source-generated `AppJsonContext.Default.*` for (de)serialization, not reflection-based overloads.
- Output contract: the password (or JSON with `username` and `password`) goes to stdout only. Prompts, status, and errors go to stderr. Errors are reported as `Error: <message>` with exit code 1, by throwing `InvalidOperationException` inside the `Run` wrapper.
- Secrets handling: pairing data is encrypted with DPAPI (`ProtectedData`, CurrentUser) at `%LOCALAPPDATA%\KeePassCmd\pairing.dat`. Zero sensitive byte buffers with `CryptographicOperations.ZeroMemory` after use. Never log passwords, keys or pairing data.
- Entry lookup must stay strict: exact, case-sensitive title match, and fail if there are zero or multiple matches.
- The WebSocket `Origin` header is `keepasscmd://localhost`. It must match the permitted origins documented in the README. Update both together if it changes.
- The protocol code mirrors KeePassRPC's wire format (protocol version 2.2, security level 2). Change crypto or message shapes with care, since they can't be tested without a live KeePass.
- Keep the README in sync with any change to commands, options or behavior.

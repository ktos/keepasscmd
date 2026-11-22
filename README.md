# KeePassCmd

This is a small utility to get passwords from KeePass to commandline via [KeePassRPC](https://github.com/kee-org/keepassrpc).

Because I was already using Kee for accessing my KeePass passwords in the web browsers, I've built a console client to get passwords in CLI (especially to use in scripts).

## KeePass Configuration

1. KeePassRPC restricts WebSocket origins. With KeePass closed, add the following item to the `<Custom>` section of `KeePass.config.xml`, then restart KeePass. Preserve any other origins you already use (if any):

   ```xml
   <Item>
     <Key>KeePassRPC.webSocket.permittedOrigins</Key>
     <Value>resource://gre-resources,ms-browser-extension://,safari-web-extension://,moz-extension://,chrome-extension://,keepasscmd://</Value>
   </Item>
   ```

   See [KeePassRPC origin configuration](https://forum.kee.pm/t/configuring-keepassrpc-permitted-websocket-origins/3041). The client uses `ws://127.0.0.1:12546/`.

## Usage

1. Run `keepasscmd auth`, then enter the one-time code shown by KeePass. The code is visible as you type. Pairing is saved in `%LOCALAPPDATA%\KeePassCmd\pairing.dat`, encrypted with Windows DPAPI for the current user. Run `auth` again if the authorization expires or is revoked.
2. Run `keepasscmd get "Entry title"`. The exact, case-sensitive title must identify a single entry across the accessible open databases. The password is printed to standard output, it can be piped further; errors go to standard error and return a nonzero exit code.

You can use `keepasscmd get "Entry title" --json` to print an object with `username` and `password` properties instead. If the entry has no username field, `username` is an empty string.

Only entries exposed by KeePassRPC are accessible. The pairing grants access to passwords, so the Windows account must be protected.

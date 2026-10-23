# Security

ScoutWall runs with administrator (Windows) or network-capture (Linux) privileges and stores sensitive information
about the computer it watches, so security reports are very welcome.

## Reporting a vulnerability

Please **don't open a public issue**. Use GitHub's private vulnerability reporting instead: the **Security** tab of
this repository, then **Report a vulnerability**. Include what you found, how to reproduce it and the version
(`scoutwall version`). You'll get a reply as soon as possible, and credit in the release notes if you'd like it.

## Design notes for reviewers

- The web console listens on `localhost` only and runs under its own low-privilege account; the sensor runs as
  LocalSystem (Windows) or with only `CAP_NET_RAW`/`CAP_NET_ADMIN`/`CAP_NET_BIND_SERVICE` (Linux).
- The data folder is limited to SYSTEM, Administrators and the console's account (Windows) or the `scoutwall`
  account (Linux). Secrets in settings are encrypted (DPAPI on Windows, AES-GCM with a local key file on Linux).
- The presence agent talks to the sensor over a named pipe; the sensor takes the caller's session and account from
  the pipe, not from the message.
- The assistant's database queries run on a read-only connection under SQLite's authorizer, limited to the columns
  of the `chat_` views; accounts, settings, chat history and decrypted traffic are not readable from it.
- Data from the network and from program files is treated as untrusted in everything sent to an AI model.
- Automatic blocking never acts on unverified source addresses (SYN-only port scans are alerted, not blocked).

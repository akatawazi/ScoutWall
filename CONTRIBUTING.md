# Contributing

Thanks for helping. Issues and pull requests are welcome; for anything large, open an issue first so we can agree on
the approach.

## Getting started

- Install the [.NET 10 SDK](https://dotnet.microsoft.com/download).
- `dotnet build ScoutWall.slnx`
- Run the console: `dotnet run --project ScoutWall --framework net10.0-windows` (Linux: `--framework net10.0`).
  In development it uses its own database under `%LOCALAPPDATA%\ScoutWall-dev`.
- Run the sensor (as administrator / root for live capture), or with made-up traffic:
  `dotnet run --project ScoutWall --framework net10.0-windows -- sensor --Sensor:CaptureMode=Synthetic`

## Conventions

- Logic lives in the models (`ScoutWall.Data/Models`); controllers stay thin.
- Database access goes through `Repository<T>`; columns are snake_case.
- Names are spelled out (`dataContext`, not `ctx`); comments explain *why*, in plain sentences.
- Text in the console is written for a non-technical owner: short sentences, no jargon, say what to do next.
- Anything that comes from the network or from program files is untrusted, especially when it goes to an AI model.

## Database changes

The web console owns the schema and applies migrations at start. Add a migration with:

```sh
dotnet ef migrations add <Name> --project ScoutWall.Data --startup-project ScoutWall --framework net10.0-windows
```

If you add a table the assistant should be able to query, add a `chat_` view for it in a migration and describe it
in `ScoutWall.Data/Querying/ReadOnlyQuery.cs`. Never add views over accounts, settings or chat history.

## Releases

Pushing a tag such as `v0.2.0` builds the Windows and Linux single-file executables and publishes a GitHub release
with checksums and install scripts (`.github/workflows/release.yml`).

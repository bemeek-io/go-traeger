# Contributing to go-traeger

Thanks for your interest in contributing! This project is an unofficial SDK that relies on reverse-engineered APIs, so the most valuable contributions are around **API maintenance** and **new feature support** as Traeger evolves their platform.

## What We Need

- **API changes** — Traeger periodically updates their endpoints, authentication flow, command codes, or MQTT payload structure. If you notice something has broken or changed, a PR to fix it is incredibly helpful.
- **New commands** — If you discover new command codes or undocumented API endpoints, contributions to add typed methods for them are welcome.
- **Bug fixes** — Anything that improves reliability, error handling, or edge case coverage.

## Getting Started

1. **Fork** the repository and clone your fork:

   ```bash
   git clone https://github.com/your-username/go-traeger.git
   cd go-traeger
   ```

2. **Create a branch** for your change:

   ```bash
   git checkout -b my-feature
   ```

3. **Make your changes.** If you're adding a new command or status field, follow the existing patterns in `api.go` and `models.go`.

4. **Run the tests** to make sure everything passes:

   ```bash
   go test -v -race ./...
   ```

5. **Run the linters:**

   ```bash
   go vet ./...
   ```

6. If you have a Traeger grill available, **test against real hardware** to verify your changes work end-to-end. This is especially important for new commands or API changes.

7. **Send a pull request** with a clear description of what changed and why.

## Testing

All tests are unit tests that don't require a real grill or network access:

```bash
go test ./...
```

If you're adding new functionality, please include tests. Look at `client_test.go` for examples — we use a `fakeMessage` type to simulate MQTT messages without a real broker.

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Keep the public API surface small — unexported methods for internal logic, exported methods for things users need
- Use `context.Context` for any operation that hits the network
- Return errors rather than panicking
- Add JSON struct tags to any new model fields

## API Discovery Tips

If you're investigating API changes or new endpoints, a few things that help:

- Proxy the Traeger mobile app through a tool like mitmproxy or Charles to see what endpoints it calls
- The auth endpoint is `https://auth-api.iot.traegergrills.io/tokens`
- The API base is `https://mobile-iot-api.iot.traegergrills.io`
- MQTT status updates arrive on `prod/thing/update/{thingName}` — the full payload includes `status`, `features`, `settings`, `details`, `usage`, and `limits` sections

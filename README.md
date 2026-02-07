# go-traeger

[![Go Reference](https://pkg.go.dev/badge/github.com/bemeek-io/go-traeger.svg)](https://pkg.go.dev/github.com/bemeek-io/go-traeger)
[![Go Report Card](https://goreportcard.com/badge/github.com/bemeek-io/go-traeger)](https://goreportcard.com/report/github.com/bemeek-io/go-traeger)
[![Go](https://github.com/bemeek-io/go-traeger/actions/workflows/go.yml/badge.svg)](https://github.com/bemeek-io/go-traeger/actions)
[![codecov](https://codecov.io/gh/bemeek-io/go-traeger/branch/main/graph/badge.svg)](https://codecov.io/gh/bemeek-io/go-traeger)

A Go SDK for the Traeger grill IoT API. Connect to your Traeger WiFIRE-enabled grill, monitor temperatures in real time over MQTT, and send commands programmatically.

> **Disclaimer:** This project is not affiliated with, endorsed by, or sponsored by Traeger. All product names, trademarks, and registered trademarks are the property of their respective owners. This SDK was built by reverse-engineering the publicly accessible mobile app API for personal and educational use.

## Raw API Reference

If you're working in another language or want to interact with the Traeger API directly without using the Go SDK, see [docs/api.md](docs/api.md) for the full HTTP/MQTT API reference.

## Installation

```bash
go mod init github.com/my/repo
```

Then install go-traeger:

```bash
go get github.com/bemeek-io/go-traeger
```

## Quickstart

```go
package main

import (
    "context"
    "fmt"
    "log"

    traeger "github.com/bemeek-io/go-traeger"
)

func main() {
    client := traeger.NewClient("user@example.com", "password")

    ctx := context.Background()
    if err := client.Connect(ctx); err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    // List discovered grills
    for _, grill := range client.Grills() {
        fmt.Printf("Found: %s (%s)\n", grill.FriendlyName, grill.ThingName)
    }

    // Get a status update
    grill, _ := client.GrillByName("My Grill")
    status, err := client.RequestStatusUpdate(ctx, grill.ThingName)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Grill: %.0f°F (target: %.0f°F) — %s\n",
        status.GrillTemp, status.SetTemp, status.SystemStatus)
    fmt.Printf("Pellets: %.0f%%\n", status.PelletLevel)

    for _, probe := range status.Probes() {
        fmt.Printf("Probe %s: %.0f°F\n", probe.UUID, probe.Probe.CurrentTemp)
    }

    // Listen for real-time updates
    client.OnStatusAll(func(thingName string, status *traeger.GrillStatus) {
        fmt.Printf("[%s] %.0f°F\n", status.SystemStatus, status.GrillTemp)
    })
}
```

## Authentication

The SDK authenticates with the Traeger IoT API using your Traeger app credentials (email and password). A token is obtained automatically when you call `Connect()` and is refreshed transparently before it expires.

```go
// Basic authentication
client := traeger.NewClient("user@example.com", "password")
err := client.Connect(ctx)
```

Tokens are valid for 24 hours. The client refreshes them automatically when they are within a configurable buffer of expiry (default: 60 seconds). You can adjust this with `WithTokenRefreshBuffer`:

```go
client := traeger.NewClient("user@example.com", "password",
    traeger.WithTokenRefreshBuffer(5 * time.Minute),
)
```

## API Reference

### Client Lifecycle

| Method | Description |
|---|---|
| `NewClient(username, password, ...Option)` | Create a new client with functional options |
| `Connect(ctx) error` | Authenticate, discover grills, and start the MQTT connection |
| `Close() error` | Disconnect MQTT and clean up resources |

### Grill Discovery

| Method | Description |
|---|---|
| `Grills() []Grill` | Returns all discovered grills |
| `GrillByName(name) (*Grill, error)` | Look up a grill by its friendly name |

### Status

| Method | Description |
|---|---|
| `GetStatus(thingName) (*GrillStatus, bool)` | Returns the cached MQTT status for a grill |
| `RequestStatusUpdate(ctx, thingName) (*GrillStatus, error)` | Sends a status request and waits for the MQTT response |

### Commands

| Method | Description |
|---|---|
| `SetTemperature(ctx, thingName, temp)` | Set the grill target temperature |
| `SetProbeTemperature(ctx, thingName, temp)` | Set the probe target/alarm temperature |
| `SetTimer(ctx, thingName, duration)` | Set a cook timer |
| `ClearTimer(ctx, thingName)` | Clear the cook timer |
| `SetSuperSmoke(ctx, thingName, enabled)` | Enable or disable Super Smoke mode |
| `SetKeepWarm(ctx, thingName, enabled)` | Enable or disable Keep Warm mode |
| `Shutdown(ctx, thingName)` | Initiate the shutdown/cool-down cycle |
| `SendRawCommand(ctx, thingName, command)` | Send a raw command string |

### Real-Time Events

| Method | Description |
|---|---|
| `OnStatus(thingName, handler)` | Register a handler for updates from a specific grill |
| `OnStatusAll(handler)` | Register a handler for updates from all grills |

The handler signature is:

```go
type StatusHandler func(thingName string, status *GrillStatus)
```

### Options

| Option | Default | Description |
|---|---|---|
| `WithHTTPClient(client)` | 10s timeout | Custom `*http.Client` for API requests |
| `WithMQTTClientID(id)` | Random UUID | Custom MQTT client ID |
| `WithTokenRefreshBuffer(d)` | 60s | How early to refresh the auth token before expiry |
| `WithStatusUpdateTimeout(d)` | 10s | Timeout when waiting for MQTT status after a command |
| `WithLogger(logger)` | No-op | Pluggable logger (implement `Debug`, `Info`, `Error`) |

### System Status

`GrillStatus.SystemStatus` is a typed enum with a `String()` method:

| Value | Constant | String |
|---|---|---|
| 2 | `StatusSleeping` | `sleeping` |
| 3 | `StatusIdle` | `idle` |
| 4 | `StatusIgniting` | `igniting` |
| 5 | `StatusPreheating` | `preheating` |
| 6 | `StatusCooking` | `cooking` |
| 7 | `StatusCustomCook` | `custom_cook` |
| 8 | `StatusCoolDown` | `cool_down` |
| 9 | `StatusShutdown` | `shutdown` |
| 99 | `StatusOffline` | `offline` |

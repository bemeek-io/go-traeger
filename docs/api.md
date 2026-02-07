# Traeger IoT API Reference

This document describes the Traeger WiFIRE IoT API as reverse-engineered from the mobile app. It is intended for developers working in other languages or who want to interact with the API directly without using the Go SDK.

> **Disclaimer:** This is an unofficial, undocumented API. It may change at any time without notice. This project is not affiliated with Traeger.

## Authentication

**Endpoint:** `POST https://auth-api.iot.traegergrills.io/tokens`

**Request:**

```json
{
  "username": "your@email.com",
  "password": "your-password"
}
```

**Response:**

```json
{
  "accessToken": "eyJ...",
  "expiresIn": 86400,
  "idToken": "eyJ...",
  "refreshToken": "eyJ...",
  "tokenType": "Bearer"
}
```

Use the `idToken` value as the `Authorization` header for all subsequent API calls. Tokens expire after 24 hours (`expiresIn: 86400`).

## API Base URL

```
https://mobile-iot-api.iot.traegergrills.io
```

All endpoints below are relative to this base URL. Every request must include:

> **Note:** The `User-Agent` header is optional on many endpoints, but is sometimes required. For simplicity, we include it on all requests.

| Header | Value |
|---|---|
| `Authorization` | The `idToken` from authentication |
| `Content-Type` | `application/json` |
| `User-Agent` | `Traeger/11 CFNetwork/1209 Darwin/20.2.0` |

## Endpoints

### Get User Data & Grills

```
GET /users/self
```

Returns the authenticated user's profile and registered grills.

**Response:**

```json
{
  "userId": "b7736f20-...",
  "givenName": "xxx",
  "familyName": "xxx",
  "email": "xxx@example.com",
  "things": [
    {
      "thingName": "xxx",
      "friendlyName": "The Grillfather",
      "deviceTypeId": "2205",
      "status": "CONFIRMED"
    }
  ]
}
```

The `thingName` is the unique identifier used in all subsequent calls. A `thing` is a grill.

### Send Command

```
POST /things/{thingName}/commands
```

**Request:**

```json
{
  "command": "11,225"
}
```

**Response:** `200 OK` with `{}`

### Available Commands

| Command | Description | Example |
|---|---|---|
| `11,{temp}` | Set grill temperature | `"11,225"` |
| `12,{seconds}` | Set cook timer (zero-padded to 5 digits) | `"12,07200"` (2 hours) |
| `13` | Clear cook timer | `"13"` |
| `14,{temp}` | Set probe target/alarm temperature | `"14,165"` |
| `17` | Shutdown (initiates cool-down cycle) | `"17"` |
| `18` | Keep Warm ON | `"18"` |
| `19` | Keep Warm OFF | `"19"` |
| `20` | Super Smoke ON | `"20"` |
| `21` | Super Smoke OFF | `"21"` |
| `90` | Request status update (triggers MQTT publish) | `"90"` |

Temperatures use whatever units the grill is configured for (Fahrenheit or Celsius). Check the `units` field in the status response (`0` = Celsius, `1` = Fahrenheit).

### Get MQTT Credentials

```
POST /mqtt-connections
```

**Request:** `{}` (empty body)

**Response:**

```json
{
  "signedUrl": "wss://aqmix2am7g1w-ats.iot.us-west-2.amazonaws.com/mqtt?X-Amz-Algorithm=...",
  "expirationSeconds": 3600,
  "expiresAt": 1770430126
}
```

The `signedUrl` is a pre-signed AWS IoT WebSocket URL. Connect to it using any MQTT-over-WebSocket client with TLS enabled.

## MQTT Real-Time Updates

### Connection

1. Call `POST /mqtt-connections` to get a signed WebSocket URL
2. Connect using MQTT over WSS (port 443, TLS)
3. Subscribe to `prod/thing/update/{thingName}` for each grill (QoS 1)
4. Send command `90` via the REST API to trigger an immediate status publish

The signed URL expires after 1 hour. Reconnect with a new URL before it expires.

### Status Message Format

Messages on `prod/thing/update/{thingName}` are JSON with this structure:

```json
{
  "thingName": "xxx",
  "status": { ... },
  "features": { ... },
  "settings": { ... },
  "details": { ... },
  "usage": { ... },
  "limits": { ... }
}
```

### Status Object

The `status` object contains the primary grill state:

```json
{
  "grill": 225,
  "set": 250,
  "ambient": 72,
  "pellet_level": 70,
  "connected": true,
  "system_status": 6,
  "server_status": 1,
  "errors": 0,
  "probe": 145,
  "probe_set": 165,
  "probe_con": 1,
  "probe_alarm_fired": 0,
  "keepwarm": 0,
  "smoke": 1,
  "grill_mode": 0,
  "in_custom": 0,
  "cook_timer_start": 1770424781,
  "cook_timer_end": 1770432000,
  "cook_timer_complete": 0,
  "cook_id": "xxx",
  "sys_timer_start": 1770424781,
  "sys_timer_end": 1770426581,
  "sys_timer_complete": 0,
  "grease_level": 0,
  "grease_temperature": 0,
  "units": 1,
  "seasoned": 1,
  "uuid": "xxx",
  "time": 1770425196,
  "acc": [
    {
      "uuid": "probe0",
      "type": "probe",
      "channel": "p0",
      "con": 1,
      "probe": {
        "get_temp": 145,
        "set_temp": 165,
        "alarm_fired": 0
      }
    }
  ]
}
```

### System Status Codes

| Value | State | Description |
|---|---|---|
| 2 | Sleeping | Power switch on, screen off |
| 3 | Idle | Power switch on, screen on, ready |
| 4 | Igniting | Ignition sequence in progress |
| 5 | Preheating | Heating up to target temperature |
| 6 | Cooking | At temperature, cooking |
| 7 | Custom Cook | Running a custom cook program |
| 8 | Cool Down | Cooling down after shutdown |
| 9 | Shutdown | Shutdown complete, heading to sleep |
| 99 | Offline | Grill is not connected |

### Features Object

```json
{
  "super_smoke_enabled": 1,
  "pellet_sensor_connected": 1,
  "pellet_sensor_enabled": 1,
  "flame_sensor_enabled": 1,
  "lid_sensor_enabled": 1,
  "grill_light_enabled": 1,
  "cold_smoke_enabled": 0,
  "grease_sensor_enabled": 0
}
```

### Settings Object

```json
{
  "device_type_id": 2205,
  "fw_version": "01.06.04",
  "ui_fw_version": "01.04.00",
  "networking_fw_version": "1.4.2",
  "config_version": "2205.001",
  "ssid": "MyWiFi",
  "rssi": -50,
  "units": 1
}
```

### Details Object

```json
{
  "friendlyName": "The Grillfather",
  "thingName": "XXXX",
  "deviceType": "2205",
  "lastConnectedOn": 1770423605
}
```

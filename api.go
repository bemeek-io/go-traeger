package traeger

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	apiBaseURL = "https://mobile-iot-api.iot.traegergrills.io"
	userAgent  = "Traeger/11 CFNetwork/1209 Darwin/20.2.0"
)

// doAuthorizedRequest performs an HTTP request with the auth token, refreshing
// the token first if needed.
func (c *Client) doAuthorizedRequest(ctx context.Context, method, url string, body io.Reader) (*http.Response, error) {
	if err := c.refreshToken(ctx); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("traeger: create request: %w", err)
	}
	req.Header.Set("Authorization", c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Language", "en-us")
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defer resp.Body.Close()
		respBody, _ := io.ReadAll(resp.Body)
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Body:       string(respBody),
		}
	}

	return resp, nil
}

// getGrills fetches the user's grills from the Traeger API.
func (c *Client) getGrills(ctx context.Context) ([]Grill, error) {
	resp, err := c.doAuthorizedRequest(ctx, "GET", apiBaseURL+"/users/self", nil)
	if err != nil {
		return nil, fmt.Errorf("traeger: get grills: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("traeger: read grills response: %w", err)
	}

	var result userDataResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("traeger: unmarshal grills: %w", err)
	}

	return result.Things, nil
}

// sendCommand sends a raw command to a grill.
func (c *Client) sendCommand(ctx context.Context, thingName, command string) error {
	url := fmt.Sprintf("%s/things/%s/commands", apiBaseURL, thingName)
	data, err := json.Marshal(map[string]string{"command": command})
	if err != nil {
		return fmt.Errorf("traeger: marshal command: %w", err)
	}

	resp, err := c.doAuthorizedRequest(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("traeger: send command: %w", err)
	}
	resp.Body.Close()
	return nil
}

// getMQTTCredentials fetches a signed MQTT WebSocket URL from the Traeger API.
func (c *Client) getMQTTCredentials(ctx context.Context) (signedURL string, expiresAt time.Time, err error) {
	requestTime := time.Now()

	resp, err := c.doAuthorizedRequest(ctx, "POST", apiBaseURL+"/mqtt-connections", nil)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("traeger: get mqtt credentials: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("traeger: read mqtt credentials: %w", err)
	}

	var result mqttConnectionResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return "", time.Time{}, fmt.Errorf("traeger: unmarshal mqtt credentials: %w", err)
	}

	expiresAt = requestTime.Add(time.Duration(result.ExpirationSeconds) * time.Second)
	return result.SignedURL, expiresAt, nil
}

// SetTemperature sets the grill target temperature (in the grill's configured units).
func (c *Client) SetTemperature(ctx context.Context, thingName string, temp int) error {
	return c.sendCommand(ctx, thingName, fmt.Sprintf("11,%d", temp))
}

// SetTimer sets a cook timer. Duration is rounded to whole seconds.
func (c *Client) SetTimer(ctx context.Context, thingName string, d time.Duration) error {
	return c.sendCommand(ctx, thingName, fmt.Sprintf("12,%05d", int(d.Seconds())))
}

// ClearTimer resets/clears the cook timer.
func (c *Client) ClearTimer(ctx context.Context, thingName string) error {
	return c.sendCommand(ctx, thingName, "13")
}

// SetProbeTemperature sets the probe target/alarm temperature.
func (c *Client) SetProbeTemperature(ctx context.Context, thingName string, temp int) error {
	return c.sendCommand(ctx, thingName, fmt.Sprintf("14,%d", temp))
}

// Shutdown initiates the grill shutdown/cool-down cycle.
func (c *Client) Shutdown(ctx context.Context, thingName string) error {
	return c.sendCommand(ctx, thingName, "17")
}

// SetKeepWarm enables or disables Keep Warm mode.
func (c *Client) SetKeepWarm(ctx context.Context, thingName string, enabled bool) error {
	if enabled {
		return c.sendCommand(ctx, thingName, "18")
	}
	return c.sendCommand(ctx, thingName, "19")
}

// SetSuperSmoke enables or disables Super Smoke mode.
func (c *Client) SetSuperSmoke(ctx context.Context, thingName string, enabled bool) error {
	if enabled {
		return c.sendCommand(ctx, thingName, "20")
	}
	return c.sendCommand(ctx, thingName, "21")
}

// SendRawCommand sends a raw command string to a grill. Prefer the typed
// methods (SetTemperature, Shutdown, etc.) for common operations.
func (c *Client) SendRawCommand(ctx context.Context, thingName, command string) error {
	return c.sendCommand(ctx, thingName, command)
}

// RequestStatusUpdate sends a status request command (command "90") to a grill
// and waits for the MQTT status update to arrive. It respects the provided
// context for cancellation.
func (c *Client) RequestStatusUpdate(ctx context.Context, thingName string) (*GrillStatus, error) {
	// Clear cached status so we know when a fresh one arrives.
	c.mu.Lock()
	delete(c.status, thingName)
	c.mu.Unlock()

	if err := c.sendCommand(ctx, thingName, "90"); err != nil {
		return nil, err
	}

	// Wait for the MQTT update with a timeout derived from config or context.
	timeout := c.statusUpdateTimeout
	deadline, hasDeadline := ctx.Deadline()
	if hasDeadline {
		if remaining := time.Until(deadline); remaining < timeout {
			timeout = remaining
		}
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
			return nil, ErrTimeout
		case <-ticker.C:
			c.mu.RLock()
			s, ok := c.status[thingName]
			c.mu.RUnlock()
			if ok {
				return s, nil
			}
		}
	}
}

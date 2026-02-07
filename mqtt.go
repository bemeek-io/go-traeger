package traeger

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

const mqttTopicPrefix = "prod/thing/update/"

// connectMQTT obtains MQTT credentials and establishes the WebSocket connection.
func (c *Client) connectMQTT(ctx context.Context) error {
	signedURL, expiresAt, err := c.getMQTTCredentials(ctx)
	if err != nil {
		return err
	}
	c.mqttURL = signedURL
	c.mqttURLExpires = expiresAt

	parsed, err := url.Parse(signedURL)
	if err != nil {
		return fmt.Errorf("traeger: parse mqtt url: %w", err)
	}

	broker := fmt.Sprintf("wss://%s%s?%s", parsed.Host, parsed.Path, parsed.RawQuery)

	opts := mqtt.NewClientOptions()
	opts.AddBroker(broker)
	opts.SetClientID(c.mqttUUID)
	opts.SetTLSConfig(&tls.Config{InsecureSkipVerify: true}) //nolint:gosec // Traeger's MQTT broker requires this
	opts.SetOnConnectHandler(c.handleConnect)
	opts.SetAutoReconnect(true)

	c.mqttClient = c.newMQTTClient(opts)

	token := c.mqttClient.Connect()
	token.Wait()
	if err := token.Error(); err != nil {
		return fmt.Errorf("traeger: mqtt connect: %w", err)
	}

	return nil
}

// mqttKeepAlive runs in the background and reconnects the MQTT client before
// the signed WebSocket URL expires (typically every ~1 hour). It stops when
// the done channel is closed (via Close).
func (c *Client) mqttKeepAlive() {
	// Capture done channel once so Close() setting c.done = nil doesn't
	// cause us to select on a nil channel.
	c.mu.RLock()
	done := c.done
	c.mu.RUnlock()

	ticker := time.NewTicker(c.keepAliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			c.mu.RLock()
			remaining := time.Until(c.mqttURLExpires)
			buffer := c.tokenRefreshBuffer
			c.mu.RUnlock()

			if remaining > buffer {
				continue
			}
			c.logger.Info("mqtt url expiring, reconnecting", "remaining", remaining.String())
			if err := c.reconnectMQTT(); err != nil {
				c.logger.Error("mqtt reconnect failed", "error", err)
			}
		}
	}
}

// reconnectMQTT gets fresh MQTT credentials, disconnects the old client,
// and establishes a new connection. Subscriptions are restored automatically
// via the handleConnect callback.
func (c *Client) reconnectMQTT() error {
	ctx := context.Background()

	signedURL, expiresAt, err := c.getMQTTCredentials(ctx)
	if err != nil {
		return fmt.Errorf("get mqtt credentials: %w", err)
	}

	parsed, err := url.Parse(signedURL)
	if err != nil {
		return fmt.Errorf("parse mqtt url: %w", err)
	}

	broker := fmt.Sprintf("wss://%s%s?%s", parsed.Host, parsed.Path, parsed.RawQuery)

	// Disconnect the old client.
	c.mu.Lock()
	if c.mqttClient != nil && c.mqttClient.IsConnected() {
		c.mqttClient.Disconnect(250)
	}
	c.mqttURL = signedURL
	c.mqttURLExpires = expiresAt
	c.mu.Unlock()

	// Create and connect a new client with the fresh URL.
	opts := mqtt.NewClientOptions()
	opts.AddBroker(broker)
	opts.SetClientID(c.mqttUUID)
	opts.SetTLSConfig(&tls.Config{InsecureSkipVerify: true}) //nolint:gosec // Traeger's MQTT broker requires this
	opts.SetOnConnectHandler(c.handleConnect)
	opts.SetAutoReconnect(true)

	newClient := c.newMQTTClient(opts)
	token := newClient.Connect()
	token.Wait()
	if err := token.Error(); err != nil {
		return fmt.Errorf("mqtt connect: %w", err)
	}

	c.mu.Lock()
	c.mqttClient = newClient
	c.mu.Unlock()

	c.logger.Info("mqtt reconnected with fresh url", "expires_in", time.Until(expiresAt).String())
	return nil
}

// subscribeToGrills subscribes to MQTT status topics for all discovered grills.
func (c *Client) subscribeToGrills() error {
	if c.mqttClient == nil || !c.mqttClient.IsConnected() {
		return ErrNotConnected
	}

	c.mu.RLock()
	grills := c.grills
	c.mu.RUnlock()

	for _, grill := range grills {
		topic := mqttTopicPrefix + grill.ThingName
		c.logger.Debug("subscribing to grill", "thing_name", grill.ThingName, "topic", topic)
		token := c.mqttClient.Subscribe(topic, 1, c.handleMessage)
		token.Wait()
		if err := token.Error(); err != nil {
			return fmt.Errorf("traeger: subscribe to %s: %w", grill.ThingName, err)
		}
	}

	return nil
}

// handleMessage processes incoming MQTT messages, updates the status cache,
// and invokes registered handlers.
func (c *Client) handleMessage(_ mqtt.Client, msg mqtt.Message) {
	topic := msg.Topic()
	if !strings.HasPrefix(topic, mqttTopicPrefix) {
		return
	}
	thingName := topic[len(mqttTopicPrefix):]

	c.logger.Debug("mqtt message received", "thing_name", thingName, "payload", string(msg.Payload()))

	var payload grillUpdatePayload
	if err := json.Unmarshal(msg.Payload(), &payload); err != nil {
		c.logger.Error("failed to unmarshal mqtt payload", "error", err, "thing_name", thingName)
		return
	}

	c.logger.Debug("status payload", "thing_name", thingName, "raw_status", string(payload.Status))

	var status GrillStatus
	if err := json.Unmarshal(payload.Status, &status); err != nil {
		c.logger.Error("failed to unmarshal grill status", "error", err, "thing_name", thingName)
		return
	}

	c.mu.Lock()
	c.status[thingName] = &status
	// Copy handler slices under lock to invoke outside.
	handlers := make([]StatusHandler, 0, len(c.handlers[thingName])+len(c.globalHandlers))
	handlers = append(handlers, c.handlers[thingName]...)
	handlers = append(handlers, c.globalHandlers...)
	c.mu.Unlock()

	for _, h := range handlers {
		h(thingName, &status)
	}
}

// handleConnect is called when the MQTT client connects or reconnects.
// It re-subscribes to all grill topics.
func (c *Client) handleConnect(_ mqtt.Client) {
	c.logger.Info("mqtt connected, subscribing to grills")
	if err := c.subscribeToGrills(); err != nil {
		c.logger.Error("failed to subscribe on reconnect", "error", err)
	}
}

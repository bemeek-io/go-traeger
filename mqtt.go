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

	c.mqttClient = mqtt.NewClient(opts)

	token := c.mqttClient.Connect()
	token.Wait()
	if err := token.Error(); err != nil {
		return fmt.Errorf("traeger: mqtt connect: %w", err)
	}

	return nil
}

// refreshMQTTURL refreshes the signed MQTT URL if it is close to expiry.
func (c *Client) refreshMQTTURL(ctx context.Context) error {
	remaining := time.Until(c.mqttURLExpires)
	if remaining > c.tokenRefreshBuffer {
		return nil
	}

	c.logger.Debug("refreshing mqtt url")
	signedURL, expiresAt, err := c.getMQTTCredentials(ctx)
	if err != nil {
		return err
	}
	c.mqttURL = signedURL
	c.mqttURLExpires = expiresAt
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

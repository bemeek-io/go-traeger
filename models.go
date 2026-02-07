package traeger

import (
	"encoding/json"
	"fmt"
)

// Grill represents a Traeger grill device.
type Grill struct {
	ThingName    string `json:"thingName"`
	FriendlyName string `json:"friendlyName"`
}

// SystemStatus represents the operational state of a grill.
type SystemStatus int

const (
	StatusSleeping   SystemStatus = 2
	StatusIdle       SystemStatus = 3
	StatusIgniting   SystemStatus = 4
	StatusPreheating SystemStatus = 5
	StatusCooking    SystemStatus = 6
	StatusCustomCook SystemStatus = 7
	StatusCoolDown   SystemStatus = 8
	StatusShutdown   SystemStatus = 9
	StatusOffline    SystemStatus = 99
)

func (s SystemStatus) String() string {
	switch s {
	case StatusSleeping:
		return "sleeping"
	case StatusIdle:
		return "idle"
	case StatusIgniting:
		return "igniting"
	case StatusPreheating:
		return "preheating"
	case StatusCooking:
		return "cooking"
	case StatusCustomCook:
		return "custom_cook"
	case StatusCoolDown:
		return "cool_down"
	case StatusShutdown:
		return "shutdown"
	case StatusOffline:
		return "offline"
	default:
		return fmt.Sprintf("unknown(%d)", s)
	}
}

// GrillStatus represents the real-time status of a grill.
type GrillStatus struct {
	// Core temperature readings
	GrillTemp   float64 `json:"grill"`
	SetTemp     float64 `json:"set"`
	Ambient     float64 `json:"ambient"`
	PelletLevel float64 `json:"pellet_level"`

	// State
	Connected    bool         `json:"connected"`
	SystemStatus SystemStatus `json:"system_status"`
	ServerStatus int          `json:"server_status"`
	Errors       int          `json:"errors"`

	// Accessories (wireless probes, etc.)
	Accessories []Accessory `json:"acc"`

	// Built-in wired probe
	ProbeTemp       float64 `json:"probe"`
	ProbeSetTemp    float64 `json:"probe_set"`
	ProbeConnected  int     `json:"probe_con"`
	ProbeAlarmFired int     `json:"probe_alarm_fired"`

	// Modes
	KeepWarm  int `json:"keepwarm"`
	Smoke     int `json:"smoke"`
	GrillMode int `json:"grill_mode"`
	InCustom  int `json:"in_custom"`

	// Cook timer
	CookTimerStart    int64  `json:"cook_timer_start"`
	CookTimerEnd      int64  `json:"cook_timer_end"`
	CookTimerComplete int    `json:"cook_timer_complete"`
	CookID            string `json:"cook_id"`

	// System timer (preheat countdown, etc.)
	SysTimerStart    int64 `json:"sys_timer_start"`
	SysTimerEnd      int64 `json:"sys_timer_end"`
	SysTimerComplete int   `json:"sys_timer_complete"`

	// Sensor readings
	GreaseLevel       int `json:"grease_level"`
	GreaseTemperature int `json:"grease_temperature"`

	// Settings
	Units    int    `json:"units"` // 0 = Celsius, 1 = Fahrenheit
	Seasoned int    `json:"seasoned"`
	UUID     string `json:"uuid"`
	Time     int64  `json:"time"`
}

// Probes returns only connected probe accessories.
func (s *GrillStatus) Probes() []Accessory {
	var probes []Accessory
	for _, a := range s.Accessories {
		if a.Type == "probe" && a.Connected == 1 {
			probes = append(probes, a)
		}
	}
	return probes
}

// Accessory represents a grill accessory (wireless probe, etc.).
type Accessory struct {
	UUID      string     `json:"uuid"`
	Type      string     `json:"type"`
	Channel   string     `json:"channel"`
	Connected int        `json:"con"`
	Probe     *ProbeData `json:"probe,omitempty"`
}

// ProbeData represents temperature probe readings.
type ProbeData struct {
	CurrentTemp float64 `json:"get_temp"`
	TargetTemp  float64 `json:"set_temp"`
	AlarmFired  int     `json:"alarm_fired"`
}

// authRequest is the request body for the Traeger auth API.
type authRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// authResponse is the response from the Traeger auth API.
type authResponse struct {
	AccessToken  string  `json:"accessToken"`
	ExpiresIn    float64 `json:"expiresIn"`
	IdToken      string  `json:"idToken"`
	RefreshToken string  `json:"refreshToken"`
	TokenType    string  `json:"tokenType"`
}

// userDataResponse wraps the user data API response.
type userDataResponse struct {
	Things []Grill `json:"things"`
}

// mqttConnectionResponse wraps the MQTT connection API response.
type mqttConnectionResponse struct {
	SignedURL         string  `json:"signedUrl"`
	ExpirationSeconds float64 `json:"expirationSeconds"`
}

// grillUpdatePayload wraps the MQTT status update message.
type grillUpdatePayload struct {
	Status json.RawMessage `json:"status"`
}

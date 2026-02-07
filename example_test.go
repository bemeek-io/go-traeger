package traeger_test

import (
	"context"
	"fmt"
	"net/http"
	"time"

	traeger "github.com/bemeek-io/go-traeger"
)

func Example() {
	client := traeger.NewClient("user@example.com", "password",
		traeger.WithHTTPClient(&http.Client{Timeout: 30 * time.Second}),
	)

	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		fmt.Printf("connect error: %v\n", err)
		return
	}
	defer client.Close()

	for _, grill := range client.Grills() {
		fmt.Printf("Found: %s (%s)\n", grill.FriendlyName, grill.ThingName)
	}

	client.OnStatusAll(func(thingName string, status *traeger.GrillStatus) {
		fmt.Printf("[%s] %s: grill=%.0f°F set=%.0f°F pellets=%.0f%%\n",
			status.SystemStatus, thingName,
			status.GrillTemp, status.SetTemp, status.PelletLevel)
		for _, probe := range status.Probes() {
			fmt.Printf("  Probe %s: %.0f°F (target: %.0f°F)\n",
				probe.UUID, probe.Probe.CurrentTemp, probe.Probe.TargetTemp)
		}
	})
}

func Example_commands() {
	client := traeger.NewClient("user@example.com", "password")

	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		fmt.Printf("connect error: %v\n", err)
		return
	}
	defer client.Close()

	grill, err := client.GrillByName("Backyard Grill")
	if err != nil {
		fmt.Printf("grill not found: %v\n", err)
		return
	}

	// Set grill temperature to 225°F
	client.SetTemperature(ctx, grill.ThingName, 225)

	// Set probe target to 165°F
	client.SetProbeTemperature(ctx, grill.ThingName, 165)

	// Set a 2-hour cook timer
	client.SetTimer(ctx, grill.ThingName, 2*time.Hour)

	// Enable Super Smoke mode
	client.SetSuperSmoke(ctx, grill.ThingName, true)

	// When done, shut down the grill
	client.Shutdown(ctx, grill.ThingName)
}

func Example_statusUpdate() {
	client := traeger.NewClient("user@example.com", "password")

	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		fmt.Printf("connect error: %v\n", err)
		return
	}
	defer client.Close()

	grills := client.Grills()
	if len(grills) == 0 {
		return
	}

	status, err := client.RequestStatusUpdate(ctx, grills[0].ThingName)
	if err != nil {
		fmt.Printf("status error: %v\n", err)
		return
	}

	fmt.Printf("Grill temp: %.0f°F (target: %.0f°F)\n", status.GrillTemp, status.SetTemp)
	fmt.Printf("Status: %s\n", status.SystemStatus)
	fmt.Printf("Pellets: %.0f%%\n", status.PelletLevel)
	fmt.Printf("Keep Warm: %v, Super Smoke: %v\n", status.KeepWarm == 1, status.Smoke == 1)
}

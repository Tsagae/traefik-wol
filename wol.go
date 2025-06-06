package traefik_wol

import (
	"context"
	"fmt"
	"github.com/MarkusJx/traefik-wol/wol"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

type HttpMethod int

const (
	GET HttpMethod = iota
	POST
)

type StartActionType int

const (
	HTTP StartActionType = iota
	MAGICPACKET
)

// Config the plugin configuration.
type Config struct {
	MacAddress         string `json:"macAddress,omitempty"`
	IpAddress          string `json:"ipAddress,omitempty"`
	StartUrl           string `json:"startUrl,omitempty"`
	StartMethod        string `json:"startMethod,omitempty"`
	StopUrl            string `json:"stopUrl,omitempty"`
	StopMethod         string `json:"stopMethod,omitempty"`
	StopTimeout        int    `json:"stopTimeout,omitempty"`
	HealthCheck        string `json:"healthCheck,omitempty"`
	BroadcastInterface string `json:"broadcastInterface,omitempty"`
	RequestTimeout     int    `json:"requestTimeout,omitempty"`
	NumRetries         int    `json:"numRetries,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		MacAddress:         "",
		IpAddress:          "",
		HealthCheck:        "",
		StartUrl:           "",
		StartMethod:        "GET",
		StopUrl:            "",
		StopMethod:         "GET",
		BroadcastInterface: "",
		StopTimeout:        5,
		RequestTimeout:     5,
		NumRetries:         10,
	}
}

// Wol a Demo plugin.
type Wol struct {
	next              http.Handler
	stopTimeout       time.Duration
	numRetries        int
	sleepTimer        *time.Timer
	timerMutex        *sync.Mutex
	wakeUpAction      func() error
	healthCheckAction func() (bool, error)
}

// New created a new Demo plugin.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.HealthCheck) == 0 {
		return nil, fmt.Errorf("healthCheck cannot be empty")
	}

	if (len(config.MacAddress) > 0 && len(config.IpAddress) == 0) || (len(config.MacAddress) == 0 && len(config.IpAddress) > 0) {
		return nil, fmt.Errorf("if mac or ip is set, the other must be set too")
	}

	if len(config.MacAddress) == 0 && len(config.IpAddress) == 0 && len(config.StartUrl) == 0 {
		return nil, fmt.Errorf("either mac and ip or startUrl must be set")
	}

	if len(config.StartUrl) > 0 && len(config.MacAddress) > 0 {
		return nil, fmt.Errorf("cannot use mac and startUrl at the same time")
	}

	if config.StopTimeout < 1 {
		return nil, fmt.Errorf("stopTimeout must be at least 1")
	}

	if len(config.StopMethod) > 0 && config.StopMethod != "GET" && config.StopMethod != "POST" {
		return nil, fmt.Errorf("stopMethod must be either GET or POST")
	}

	if len(config.StartMethod) > 0 && config.StartMethod != "GET" && config.StartMethod != "POST" {
		return nil, fmt.Errorf("startMethod must be either GET or POST")
	}

	if config.RequestTimeout < 1 {
		return nil, fmt.Errorf("requestTimeout must be at least 1")
	}

	if config.NumRetries < 1 {
		return nil, fmt.Errorf("numRetries must be at least 1")
	}

	client := &http.Client{
		Timeout: time.Duration(config.RequestTimeout) * time.Second,
	}

	var startActionType StartActionType
	var startHttpMethod HttpMethod
	if len(config.StartUrl) > 0 {
		startActionType = HTTP
		switch config.StartMethod {
		case "GET":
			startHttpMethod = GET
		case "POST":
			startHttpMethod = POST
		default:
			return nil, fmt.Errorf("startMethod must be either GET or POST")
		}
	} else {
		startActionType = MAGICPACKET
	}

	var w = Wol{
		next:              next,
		stopTimeout:       time.Duration(config.StopTimeout) * time.Minute,
		sleepTimer:        nil,
		numRetries:        config.NumRetries,
		timerMutex:        &sync.Mutex{},
		healthCheckAction: nil,
		wakeUpAction:      nil,
	}

	// Health Check Action
	w.healthCheckAction = func() (bool, error) {
		log.Println("Checking if server is up")
		_, err := client.Get(config.HealthCheck)
		if err != nil {
			log.Printf("Server is down: %s", err)
			return false, nil
		}

		log.Println("Server is up")
		return true, nil
	}

	// Stop Action
	if len(config.StopUrl) > 0 {
		var stopHttpMethod HttpMethod
		switch config.StopMethod {
		case "GET":
			stopHttpMethod = GET
		case "POST":
			stopHttpMethod = POST
		default:
			return nil, fmt.Errorf("stopMethod must be either GET or POST")
		}

		log.Println("Starting sleep timer")
		w.sleepTimer = time.AfterFunc(w.stopTimeout, func() {
			log.Printf("Attempting to stop server at %s\n", config.StopUrl)

			var err error
			isAlive, err := w.healthCheckAction()
			if err != nil {
				log.Printf("Error while checking server status: %s\n", err)
			}
			if !isAlive {
				log.Println("Server is already stopped")
				return
			}

			switch stopHttpMethod {
			case GET:
				_, err = client.Get(config.StopUrl)
			case POST:
				_, err = client.Post(config.StopUrl, "application/json", nil)
			}

			if err != nil {
				log.Printf("Error while stopping server: %s\n", err)
			}
		})
	}

	// Start Action
	var startAction func() error
	switch startActionType {
	case HTTP:
		startAction = func() error {
			log.Printf("Attempting to start server at %s %s\n", config.StartMethod, config.StartUrl)
			var err error
			switch startHttpMethod {
			case GET:
				_, err = http.Get(config.StartUrl)
			case POST:
				_, err = http.Post(config.StartUrl, "text/plain", nil)
			default:
				err = fmt.Errorf("unknown start method: %s", config.StartMethod)
			}
			return err
		}
	case MAGICPACKET:
		startAction = func() error {
			var localAddr *net.UDPAddr
			var err error
			if len(config.BroadcastInterface) > 0 {
				localAddr, err = ipFromInterface(config.BroadcastInterface)
				if err != nil {
					return err
				}
			}

			bcastAddr := fmt.Sprintf("%s:%s", "255.255.255.255", "9")
			udpAddr, err := net.ResolveUDPAddr("udp", bcastAddr)
			if err != nil {
				return err
			}

			mp, err := wol.New(config.MacAddress)
			if err != nil {
				return err
			}

			bs, err := mp.Marshal()
			if err != nil {
				return err
			}

			conn, err := net.DialUDP("udp", localAddr, udpAddr)
			if err != nil {
				return err
			}
			defer func(conn *net.UDPConn) {
				err := conn.Close()
				if err != nil {
					log.Printf("Error closing UDP connection: %s\n", err)
				}
			}(conn)

			log.Printf("Attempting to send a magic packet to MAC %s\n", config.MacAddress)
			log.Printf("... Broadcasting to: %s\n", bcastAddr)
			n, err := conn.Write(bs)
			if err == nil && n != 102 {
				err = fmt.Errorf("magic packet sent was %d bytes (expected 102 bytes sent)", n)
			}
			if err != nil {
				return err
			}
			return nil

		}
	}
	w.wakeUpAction = startAction
	return &w, nil
}

func (a *Wol) resetTimer() {
	if a.sleepTimer != nil {
		a.timerMutex.Lock()
		log.Println("Resetting sleep timer")
		a.sleepTimer.Reset(a.stopTimeout)
		a.timerMutex.Unlock()
	}
}

func ipFromInterface(iface string) (*net.UDPAddr, error) {
	ief, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}

	addrs, err := ief.Addrs()
	if err == nil && len(addrs) <= 0 {
		err = fmt.Errorf("no address associated with interface %s", iface)
	}
	if err != nil {
		return nil, err
	}

	// Validate that one of the addrs is a valid network IP address.
	for _, addr := range addrs {
		switch ip := addr.(type) {
		case *net.IPNet:
			if !ip.IP.IsLoopback() && ip.IP.To4() != nil {
				return &net.UDPAddr{
					IP: ip.IP,
				}, nil
			}
		}
	}
	return nil, fmt.Errorf("no address associated with interface %s", iface)
}

func (a *Wol) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	isAlive, err := a.healthCheckAction()
	if err != nil {
		log.Printf("Error while checking server status: %s\n", err)
	}
	if !isAlive {
		log.Println("Server is down, waking up")
		err := a.wakeUpAction()
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		log.Println("Waiting for server to come up")
		for i := 0; i < a.numRetries; i++ {
			isAlive, err := a.healthCheckAction()
			if err != nil {
				log.Printf("Error while checking server status: %s\n", err)
			}
			if isAlive {
				log.Println("Server is up")
				break
			}

			time.Sleep(5 * time.Second)
		}

		isAlive, err := a.healthCheckAction()
		if err != nil {
			log.Printf("Error while checking server status: %s\n", err)
		}
		if !isAlive {
			http.Error(rw, "Failed to start server", http.StatusInternalServerError)
			return
		}
	}

	a.next.ServeHTTP(rw, req)
}

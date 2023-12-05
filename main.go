package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"os/exec"
	"syscall"
	"time"
	"sync"
)

var (
	maxConnections      = 5
	blockedIPs          = make(map[string]*BlockedIP)
	connectionThreshold = 20 * time.Second
	minConnectionTime   = 3 * time.Second
	cleanupInterval     = 1 * time.Minute
	frequentConnLimit   = 3
	frequentConnWindow  = 5 * time.Second
	spamThreshold       = 10
	spamBlockDuration   = 1 * time.Minute
)

type BlockedIP struct {
	LastBlockTime time.Time
	BlockDuration time.Duration
	Connections   int
	IsBlocked     bool
}

type ConnRecord struct {
	IP           string
	ConnectTime  time.Time
	DisconnectTime time.Time
}

var (
	connectionRecords []ConnRecord
	connectionMutex   sync.Mutex
	blockedMutex      sync.Mutex
)

func main() {
	listener, err := net.Listen("tcp", "0.0.0.0:8080")
	if err != nil {
		log.Fatalf("Erreur lors de la création du socket TCP : %s", err.Error())
	}

	log.Printf("Serveur en écoute sur 0.0.0.0:8080")

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)

	go cleanBlockedIPs()

	go func(listener net.Listener) {
		defer listener.Close()

		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("Erreur lors de l'acceptation de la connexion : %s", err.Error())
				continue
			}

			go handleConnection(conn)
		}
	}(listener)

	<-signals

	log.Println("Arrêt du serveur...")
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	connectionMutex.Lock()
	connectTime := time.Now()
	connectionMutex.Unlock()

	log.Printf("Connexion de %s traitée", conn.RemoteAddr())

	time.Sleep(minConnectionTime)

	disconnectTime := time.Now()

	connectionMutex.Lock()
	record := ConnRecord{
		IP:           conn.RemoteAddr().(*net.TCPAddr).IP.String(),
		ConnectTime:  connectTime,
		DisconnectTime: disconnectTime,
	}
	connectionRecords = append(connectionRecords, record)
	connectionMutex.Unlock()

	ip := record.IP

	if isBlocked(ip) {
		log.Printf("Connexion de %s refusée (adresse IP bloquée)", conn.RemoteAddr())
		return
	}

	if !isConnectionAllowed(ip) {
		log.Printf("Connexion de %s refusée (possible DDoS)", conn.RemoteAddr())
		blockIP(ip)
		return
	}
}

func isBlocked(ip string) bool {
	blockedMutex.Lock()
	defer blockedMutex.Unlock()

	blockedIP, exists := blockedIPs[ip]
	if exists && blockedIP.IsBlocked {
		if blockedIP.LastBlockTime.Add(blockedIP.BlockDuration).After(time.Now()) {
			return true
		}
		blockedIP.IsBlocked = false
	}

	return false
}

func isConnectionAllowed(ip string) bool {
	blockedMutex.Lock()
	defer blockedMutex.Unlock()

	if blockedIP, exists := blockedIPs[ip]; exists {
		if blockedIP.LastBlockTime.Add(blockedIP.BlockDuration).After(time.Now()) {
			return false
		}

		if blockedIP.Connections >= maxConnections {
			return false
		}

		blockedIP.Connections++
	} else {
		blockedIPs[ip] = &BlockedIP{
			LastBlockTime: time.Time{},
			BlockDuration: 0,
			Connections:   1,
		}
	}

	if connectionCount(ip) > maxConnections {
		return false
	}

	if tooFrequentConnections(ip) {
		return false
	}

	if isSpamming(ip) {
		blockIP(ip)
		return false
	}

	updateLastConnectionTime(ip)

	return true
}

func connectionCount(ip string) int {
	count := 0

	connectionMutex.Lock()
	defer connectionMutex.Unlock()

	for _, record := range connectionRecords {
		if record.IP == ip {
			count++
		}
	}
	return count
}

func tooFrequentConnections(ip string) bool {
	currentTime := time.Now()
	startTime := currentTime.Add(-frequentConnWindow)

	connectionMutex.Lock()
	defer connectionMutex.Unlock()

	count := 0
	for _, record := range connectionRecords {
		if record.IP == ip && record.DisconnectTime.After(startTime) {
			count++
		}
	}

	return count > frequentConnLimit
}

func isSpamming(ip string) bool {
	connectionMutex.Lock()
	defer connectionMutex.Unlock()

	count := 0
	for _, record := range connectionRecords {
		if record.IP == ip {
			count++
		}
	}

	return count > spamThreshold
}

func blockIP(ip string) {
	blockedMutex.Lock()
	defer blockedMutex.Unlock()

	if blockedIP, exists := blockedIPs[ip]; exists {
		blockedIP.IsBlocked = true
		blockedIP.LastBlockTime = time.Now()
		blockedIP.BlockDuration = spamBlockDuration

		cmd := exec.Command("iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
		err := cmd.Run()
		if err != nil {
			log.Printf("Erreur lors du blocage de l'adresse IP %s : %s", ip, err.Error())
		}
	}
}

func updateLastConnectionTime(ip string) {
	blockedMutex.Lock()
	defer blockedMutex.Unlock()

	lastConnTime := time.Now().Add(connectionThreshold)
	blockedIPs[ip].LastBlockTime = lastConnTime
}

func cleanBlockedIPs() {
	for {
		time.Sleep(cleanupInterval)

		blockedMutex.Lock()
		currentTime := time.Now()
		for ip, blockedIP := range blockedIPs {
			if blockedIP.IsBlocked && blockedIP.LastBlockTime.Add(blockedIP.BlockDuration).Before(currentTime) {
				blockedIP.IsBlocked = false

				cmd := exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
				err := cmd.Run()
				if err != nil {
					log.Printf("Erreur lors du déblocage de l'adresse IP %s : %s", ip, err.Error())
				}
			}
		}
		blockedMutex.Unlock()
	}
}

func netstat() []net.Conn {
	return []net.Conn{}
}

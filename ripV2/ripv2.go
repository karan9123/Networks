package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"golang.org/x/net/ipv4"
	"math/rand"
	"net"
	"regexp"
	"strconv"
	"time"
)

const (
	ripPort        = 520
	updateInterval = 2 * time.Second  // This is custom for testing
	expireTime     = 12 * time.Second // This is custom for testing
	garbageTime    = 16 * time.Second // This is custom for testing
	groupIp        = "224.0.0.9"
)

type routeEntry struct {
	network *net.IPNet
	nextHop net.IP
	metric  uint32
	updated time.Time
	isValid bool
}

type ripTable []*routeEntry

func (rt *ripTable) updateRoute(network *net.IPNet, nextHop net.IP, metric uint32, myAddr string) {
	now := time.Now()
	_, myNetwork, _ := net.ParseCIDR(myAddr + "/24")

	for _, entry := range *rt {
		if entry.network.String() == network.String() {
			if nextHop.Equal(entry.nextHop) || metric+1 < entry.metric {
				entry.metric = metric + 1
				entry.nextHop = nextHop
				entry.updated = now
				entry.isValid = true
			}
			return
		}
		//fmt.Println(entry.network, network, myNetwork)
		if entry.network == myNetwork {
			return
		}
	}

	if network.String() == myNetwork.String() {
		//fmt.Println("returned here")
		return
	}

	*rt = append(*rt, &routeEntry{
		network: network,
		nextHop: nextHop,
		metric:  metric + 1,
		updated: now,
		isValid: true,
	})
}

func (rt *ripTable) expiredRoutes() {
	now := time.Now()
	for _, entry := range *rt {
		if entry.isValid && now.Sub(entry.updated) > expireTime {
			entry.isValid = false
			entry.metric = 16
			fmt.Println("Expiring entry:", entry.network)
		}
	}
}

func (rt *ripTable) garbageCollect() {
	now := time.Now()
	newTable := ripTable{}
	for _, entry := range *rt {
		if !entry.isValid && now.Sub(entry.updated) >= garbageTime {
			fmt.Println("Dropping entry:", entry.network)
			continue
		}
		newTable = append(newTable, entry)
	}
	*rt = newTable
}

func createRIPv2Packet(rt ripTable, srcInterface net.IP) []byte {
	packet := make([]byte, 4)
	packet[0] = 2                             // RIPv2 version
	packet[1] = 2                             // Response
	binary.BigEndian.PutUint16(packet[2:], 0) // Zero (must be set to 0)

	for _, entry := range rt {
		if !entry.isValid {
			continue
		}

		// Skip routes learned from the same interface (Split Horizon)
		if srcInterface.Equal(entry.nextHop) {
			continue
		}

		// Poison Reverse: If the route was learned from the same interface,
		// set the metric to 16 (infinity) to indicate that the route is no longer valid.
		metric := entry.metric
		if srcInterface.Equal(entry.nextHop) {
			metric = 16
		}

		offset := len(packet)
		packet = append(packet, make([]byte, 20)...)

		af := uint16(2) // Address Family: IP (2)
		binary.BigEndian.PutUint16(packet[offset:], af)
		copy(packet[offset+4:], entry.network.IP)
		copy(packet[offset+8:], entry.network.Mask)
		copy(packet[offset+12:], entry.nextHop)
		binary.BigEndian.PutUint32(packet[offset+16:], metric)
	}
	return packet
}

func parseRIPv2Packet(packet []byte, sender net.IP) ripTable {
	if len(packet) < 4 || packet[0] != 2 || packet[1] != 2 {
		return nil
	}
	entries := (len(packet) - 4) / 20
	rt := make(ripTable, 0, entries)

	for i := 0; i < entries; i++ {
		offset := 4 + i*20
		af := binary.BigEndian.Uint16(packet[offset:])
		if af != 2 {
			continue
		}
		ip := net.IP(packet[offset+4 : offset+8])
		mask := net.IPMask(packet[offset+8 : offset+12])
		network := &net.IPNet{IP: ip.Mask(mask), Mask: mask}
		_ = net.IP(packet[offset+12 : offset+16])
		metric := binary.BigEndian.Uint32(packet[offset+16:])
		if metric < 1 || metric > 16 {
			continue
		}
		rt = append(rt, &routeEntry{
			network: network,
			nextHop: sender,
			metric:  metric,
			updated: time.Now(),
			isValid: true,
		})
	}

	return rt
}

func generateRipTable(name string) ripTable {
	ret := ripTable{}

	_, ipv4Net, _ := net.ParseCIDR("129.21.30.37/24")
	ipv4NextHop := net.ParseIP("129.21.30.37")

	queeg := routeEntry{
		network: ipv4Net,
		nextHop: ipv4NextHop,
		metric:  1,
		updated: time.Now(),
		isValid: true,
	}

	_, ipv4Net, _ = net.ParseCIDR("129.21.34.80/24")
	ipv4NextHop = net.ParseIP("129.21.34.80")

	comet := routeEntry{
		network: ipv4Net,
		nextHop: ipv4NextHop,
		metric:  1,
		updated: time.Now(),
		isValid: true,
	}

	_, ipv4Net, _ = net.ParseCIDR("129.21.37.49/24")
	ipv4NextHop = net.ParseIP("129.21.37.49")

	rhea := routeEntry{
		network: ipv4Net,
		nextHop: ipv4NextHop,
		metric:  1,
		updated: time.Now(),
		isValid: true,
	}

	_, ipv4Net, _ = net.ParseCIDR("129.21.22.196/24")
	ipv4NextHop = net.ParseIP("129.21.22.196")

	glados := routeEntry{
		network: ipv4Net,
		nextHop: ipv4NextHop,
		metric:  1,
		updated: time.Now(),
		isValid: true,
	}

	switch name {
	case "queeg":
		ret = append(ret, &comet)
		ret = append(ret, &glados)
	case "comet":
		ret = append(ret, &queeg)
		ret = append(ret, &rhea)
	case "rhea":
		ret = append(ret, &comet)
		ret = append(ret, &glados)
	case "glados":
		ret = append(ret, &rhea)
		ret = append(ret, &queeg)
	default:
		fmt.Println("Configured routers available(queeg, comet, rhea, glados)")
	}

	return ret
}

func getArg() (string, int, string) {
	var name string
	var lossProb int
	var interfaceName string

	// Define command-line flags
	flag.StringVar(&name, "n", "", "name to set")
	flag.IntVar(&lossProb, "lp", 0, "loss probability to set(default: 0)")
	flag.StringVar(&interfaceName, "if", "eth0", "device interface(default: eth0)")

	// Parse command-line arguments
	flag.Parse()

	// Verify the arguments
	if name == "" {
		fmt.Println("Error: name is required (-n)")
		return "", 0, " "
	}

	if lossProb < 0 || lossProb > 100 {
		fmt.Println("Error: loss probability must be between 0 and 100 (-lp)")
		return "", 0, " "
	}

	// Output the arguments
	fmt.Println("Name:", name)
	fmt.Println("Loss Probability:", lossProb)

	return name, lossProb, interfaceName
}
func main() {

	routerName, lossPercent, networkInterfaceName := getArg()

	// Initialize the routing table and add connected networks
	rTable := generateRipTable(routerName)

	networkInterface, err := net.InterfaceByName(networkInterfaceName)
	if err != nil {
		fmt.Printf("Error: %v", err)
		return
	}

	myAddr, _ := networkInterface.Addrs()

	// Set up a multicast socket for sending and receiving RIPv2 updates
	conn, err := net.ListenPacket("udp4", ":"+strconv.Itoa(ripPort))
	if err != nil {
		fmt.Println("Error while listening on the port 520:", err)
		return
	}
	defer func(conn net.PacketConn) {
		err := conn.Close()
		if err != nil {

		}
	}(conn)

	// Join the RIPv2 multicast group
	group := net.ParseIP(groupIp)

	p := ipv4.NewPacketConn(conn)
	err = p.JoinGroup(networkInterface, &net.UDPAddr{IP: group})
	if err != nil {
		fmt.Println("err:", err)
		return
	}

	//Periodic updates
	go func() {
		for {
			rTable.expiredRoutes()
			rTable.garbageCollect()

			if len(rTable) == 0 {
				bytese := make([]byte, 100)
				_, err = conn.WriteTo(bytese, &net.UDPAddr{IP: group, Port: ripPort})

				if err != nil {
					fmt.Println("Error while writing to group", err)
				}
				continue
			}
			for _, entry := range rTable {
				if !entry.isValid {
					fmt.Println("Invalid entry:", entry.network)
					continue
				}

				packet := createRIPv2Packet(rTable, entry.nextHop)
				// Generate a random integer between 0 and 99
				randomInt := rand.Intn(100)
				if !(0 <= randomInt && randomInt <= lossPercent) {
					_, err = conn.WriteTo(packet, &net.UDPAddr{IP: group, Port: ripPort})
				}
				if err != nil {
					fmt.Println("Error while writing to group", err)
					return
				}

			}
			time.Sleep(updateInterval)
		}
	}()

	buf := make([]byte, 2*1024)
	for true {
		n, addr, err := conn.ReadFrom(buf)

		var recvAddr string
		var myAddress string

		re := regexp.MustCompile(`^(.*?):`)
		match := re.FindStringSubmatch(addr.String())
		if match != nil {
			recvAddr = match[1]
		}
		re = regexp.MustCompile(`^(.*?)/`)
		match = re.FindStringSubmatch(myAddr[0].String())
		if match != nil {
			myAddress = match[1]
		}

		inTable := entryInTable(recvAddr, rTable)

		if recvAddr != myAddress {
			fmt.Println("before", inTable, len(rTable))
			if len(rTable) == 0 {
				fmt.Println("After")
				_, senderNetwork, _ := net.ParseCIDR(recvAddr + "/24")
				senderIP := net.ParseIP(recvAddr)

				neighbor := routeEntry{
					network: senderNetwork,
					nextHop: senderIP,
					metric:  1,
					updated: time.Now(),
					isValid: true,
				}

				fmt.Println("<<<--", neighbor.network)
				rTable = append(rTable, &neighbor)
			}

			sender := addr.(*net.UDPAddr).IP
			fmt.Println("Update received from:", sender)
			if err != nil {
				fmt.Println("Error:", err)
				continue
			}

			// Process incoming RIPv2 updates
			updates := parseRIPv2Packet(buf[:n], sender)
			for _, update := range updates {
				_, myNetwork, _ := net.ParseCIDR(myAddress + "/24")
				if update.network != myNetwork {
					rTable.updateRoute(update.network, update.nextHop, update.metric, myAddress)
				}

			}

			printRouteTable(rTable)
		}
	}
}

func entryInTable(addr string, rt ripTable) bool {

	_, senderNetwork, _ := net.ParseCIDR(addr + "/24")
	for _, entry := range rt {
		if entry.network == senderNetwork {
			fmt.Println("table", entry.network, senderNetwork)
			return true
		}
	}
	return false
}
func printRouteTable(entries ripTable) {
	fmt.Printf("| %-18s | %-15s | %-7s | %-7s |\n", "Network", "Next Hop", "Metric", "Valid")
	fmt.Println("|--------------------|-----------------|---------|---------|")
	for _, entry := range entries {
		fmt.Printf("| %-18s | %-15s | %-6d  | %-7t |\n", entry.network.String(), entry.nextHop.String(), entry.metric, entry.isValid)
	}
}

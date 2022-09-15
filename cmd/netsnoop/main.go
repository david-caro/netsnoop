package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os/user"
	"strconv"
	"strings"

	"github.com/david-caro/netsnoop/internal/netstat"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"gopkg.in/yaml.v3"
)

var iface = flag.String("iface", "wlp0s20f3", "Select interface where to capture")
var promisc = flag.Bool("promisc", false, "Enable promiscuous mode")
var configPath = flag.String("configPath", "./netsnoop.yaml", "Path to the configuration yaml file")

type Service struct {
	IPs []string `yaml:"ips"`
}

type Config struct {
	InterestingServices map[string]Service `yaml:"interesting_services"`
}

func readConfig(configPath string) (Config, error) {
	config := Config{}
	// this is deprecated but we have golang go1.11.6 in prod hosts, replace with os.ReadFile once we get on >1.16
	rawConfig, err := ioutil.ReadFile(configPath)
	if err != nil {
		fmt.Print(err)
		return config, err
	}

	err = yaml.Unmarshal(rawConfig, &config)
	if err != nil {
		fmt.Print(err)
		return config, err
	}

	return config, nil
}

func getIPToService(config Config) map[string]string {
	ipToService := make(map[string]string)
	for serviceName, service := range config.InterestingServices {
		for _, ip := range service.IPs {
			ipToService[ip] = serviceName
		}
	}
	return ipToService
}

func configToBPFFilter(config Config) string {
	bpfFilter := "((tcp and tcp[tcpflags] & tcp-syn != 0) or udp) and ("
	firstFilter := true
	for _, service := range config.InterestingServices {
		for _, ip := range service.IPs {
			if firstFilter {
				bpfFilter += " host " + ip
				firstFilter = false
			} else {
				bpfFilter += " or host " + ip
			}
		}
	}
	bpfFilter += ")"
	return bpfFilter
}

func main() {
	log.Println("start")
	defer log.Println("end")

	flag.Parse()

	config, err := readConfig(*configPath)
	if err != nil {
		fmt.Print(err)
		return
	}

	bpfFilter := configToBPFFilter(config)
	ipToService := getIPToService(config)

	// Opening Device
	// for now capturing size 0, not interested in the contents
	handle, err := pcap.OpenLive(*iface, int32(0), *promisc, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	defer handle.Close()

	err = handle.SetBPFFilter(bpfFilter)
	if err != nil {
		log.Fatalf("error applying BPF Filter %s - %v", bpfFilter, err)
	}
	fmt.Printf("Applying BPF filter: %s\n", bpfFilter)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		//fmt.Printf("Got packet: %s\n", packet)
		var foundService string
		var ipIsIn bool
		if ip4layer := packet.Layer(layers.LayerTypeIPv4); ip4layer != nil {
			layerData, _ := ip4layer.(*layers.IPv4)
			//fmt.Printf("Got dstIP: %s\n", layerData.DstIP.String())
			//fmt.Printf("Got srcIP: %s\n", layerData.SrcIP.String())
			foundService, ipIsIn = ipToService[layerData.DstIP.String()]
			if ipIsIn {
				fmt.Printf("Detected contact to service '%s'\n", foundService)
				user, err := getUser(packet, true)
				if err != nil {
					fmt.Printf("    unable to get process for packet: %s\n", err)
				} else if user == "0" {
					fmt.Printf("    too slow to get process info for packet\n")
				} else {
					fmt.Printf("    from user %s\n", user)
				}
				continue
			}
			foundService, ipIsIn = ipToService[layerData.SrcIP.String()]
			if ipIsIn {
				fmt.Printf("Detected contact from service '%s'\n", foundService)
				user, err := getUser(packet, false)
				if err != nil {
					fmt.Printf("    unable to get process info for packet: %s\n", err)
				} else if user == "0" {
					fmt.Printf("    too slow to get process for packet\n")
				} else {
					fmt.Printf("    from user %s\n", user)
				}
				continue
			}
			fmt.Printf("Detected unknown ip %s\n", packet.NetworkLayer().NetworkFlow().Dst().String())
		}
	}
}

func portToInt(port string) (int, error) {
	maybePort := strings.Split(port, "(")[0]
	return strconv.Atoi(maybePort)
}

func getUser(packet gopacket.Packet, localIsSrc bool) (string, error) {
	var port int
	var err error
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		layerData, _ := tcpLayer.(*layers.TCP)
		if localIsSrc {
			port, err = portToInt(layerData.SrcPort.String())
		} else {
			port, err = portToInt(layerData.DstPort.String())
		}

	} else if tcpLayer := packet.Layer(layers.LayerTypeUDP); tcpLayer != nil {
		layerData, _ := tcpLayer.(*layers.UDP)
		if localIsSrc {
			port, err = portToInt(layerData.SrcPort.String())
		} else {
			port, err = portToInt(layerData.DstPort.String())
		}
	}
	if err != nil {
		return "", err
	}

	connection, err := netstat.TCP.ConnectionFromLocalPort(port)
	if err != nil {
		return "", err
	}

	user, err := user.LookupId(connection.UserID)
	return user.Name, err
}

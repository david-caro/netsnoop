package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os/user"
	"strconv"
	"strings"

	"github.com/david-caro/netsnoop/internal/netstat"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

var iface = flag.String("iface", "wlp0s20f3", "Select interface where to capture")
var configPath = flag.String("configPath", "./netsnoop.yaml", "Path to the configuration yaml file")
var verbose = flag.Bool("verbose", false, "Enable verbose logging")

type Service struct {
	IPs []string `yaml:"ips"`
}

type Config struct {
	InterestingServices         map[string]Service `yaml:"interesting_services"`
	InterestingProcessNameMatch string             `yaml:"interesting_process_name_match"`
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
	flag.Parse()

	log.Info(fmt.Sprintf("Starting up, verbose=%v, configPath='%s'", *verbose, *configPath))
	if *verbose {
		log.SetLevel(log.DebugLevel)
	}

	config, err := readConfig(*configPath)
	if err != nil {
		fmt.Print(err)
		return
	}

	bpfFilter := configToBPFFilter(config)
	ipToService := getIPToService(config)

	// Opening Device
	// for now capturing size 0, not interested in the contents
	// not interested in promiscuous listening
	handle, err := pcap.OpenLive(*iface, int32(0), false, pcap.BlockForever)
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
			log.Debug("Got packet ", packet)
			//fmt.Printf("Got dstIP: %s\n", layerData.DstIP.String())
			//fmt.Printf("Got srcIP: %s\n", layerData.SrcIP.String())
			foundService, ipIsIn = ipToService[layerData.DstIP.String()]
			if ipIsIn {
				log.Info("Detected contact to service ", foundService)
				user, err := getUser(packet, true)
				if err != nil {
					log.Warn("    unable to get process for packet: ", err)
				} else if user == "0" {
					log.Warn("    too slow to get process info for packet")
				} else {
					log.Info("    from user ", user)
				}
				continue
			}
			foundService, ipIsIn = ipToService[layerData.SrcIP.String()]
			if ipIsIn {
				log.Info("Detected contact from service ", foundService)
				user, err := getUser(packet, false)
				if err != nil {
					log.Warn("    unable to get process info for packet: ", err)
				} else if user == "0" {
					log.Warn("    too slow to get process for packet")
				} else {
					log.Info("    from user ", user)
				}
				continue
			}
			log.Warn("Detected unknown ip ", packet.NetworkLayer().NetworkFlow().Dst().String())
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
	var protocol *netstat.Protocol
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		layerData, _ := tcpLayer.(*layers.TCP)
		protocol = netstat.TCP
		if localIsSrc {
			port, err = portToInt(layerData.SrcPort.String())
		} else {
			port, err = portToInt(layerData.DstPort.String())
		}

	} else if tcpLayer := packet.Layer(layers.LayerTypeUDP); tcpLayer != nil {
		layerData, _ := tcpLayer.(*layers.UDP)
		protocol = netstat.UDP
		if localIsSrc {
			port, err = portToInt(layerData.SrcPort.String())
		} else {
			port, err = portToInt(layerData.DstPort.String())
		}
	}
	if err != nil {
		return "", err
	}

	connection, err := netstat.FindConnectionFromLocalPortPerProcess(port, protocol)
	if err != nil {
		return "", err
	}

	user, err := user.LookupId(strconv.Itoa(connection.UserID))
	return user.Name, err
}

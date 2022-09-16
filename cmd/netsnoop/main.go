package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os/user"
	"strconv"

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
		log.Error(err)
		return config, err
	}

	err = yaml.Unmarshal(rawConfig, &config)
	if err != nil {
		log.Error(err)
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
				bpfFilter += "dst host " + ip
				firstFilter = false
			} else {
				bpfFilter += " or dst host " + ip
			}
		}
	}
	bpfFilter += ")"
	return bpfFilter
}

func main() {
	flag.Parse()

	log.SetFormatter(&log.JSONFormatter{})
	log.Info(fmt.Sprintf("Starting up, verbose=%v, configPath='%s'", *verbose, *configPath))
	if *verbose {
		log.SetLevel(log.DebugLevel)
	}

	config, err := readConfig(*configPath)
	if err != nil {
		log.Error(err)
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
		log.Fatalf("error applying BPF Filter ", bpfFilter, "  error:", err)
	}
	log.Info("Applying BPF filter: ", bpfFilter)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// we use the network traffic only to trigger a full scan, as what we are looking for is containers we can't really match per port
	for packet := range packetSource.Packets() {
		var foundService string
		var foundDstIP, foundSrcIP bool
		if ip4layer := packet.Layer(layers.LayerTypeIPv4); ip4layer != nil {
			layerData, _ := ip4layer.(*layers.IPv4)
			log.Debug("Got packet ", packet)
			foundService, foundDstIP = ipToService[layerData.DstIP.String()]
			if !foundDstIP {
				foundService, foundSrcIP = ipToService[layerData.SrcIP.String()]
			}
			if foundDstIP || foundSrcIP {
				log.Debug("Detected contact with service ", foundService)
				log.Debug("Triggering a full re-scan")
				userToService, err := getUserAndInterestingServices(packet, true, &ipToService)
				if err != nil {
					log.Warn("    unable to get process for packet: ", err)
				}
				for userID, services := range userToService {
					user, err := user.LookupId(strconv.Itoa(userID))
					if err != nil {
						log.Warn("Unable to resolve user id ", userID, ", ignoring...")
						continue
					}
					log.Info("  User:", user.Name, " services:", services)
				}
				continue
			}
			log.Warn("Detected unknown ip ", packet.NetworkLayer().NetworkFlow().Dst().String())
		}
	}
}

func getUserAndInterestingServices(packet gopacket.Packet, localIsSrc bool, ipToService *map[string]string) (map[int]map[string]netstat.Void, error) {
	var err error
	var protocol *netstat.Protocol
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		protocol = netstat.TCP

	} else if tcpLayer := packet.Layer(layers.LayerTypeUDP); tcpLayer != nil {
		protocol = netstat.UDP
	}
	if err != nil {
		return nil, err
	}

	userToService, err := netstat.FindUsersUsingInterestingServices(ipToService, protocol)
	if err != nil {
		return nil, err
	}

	return userToService, err
}

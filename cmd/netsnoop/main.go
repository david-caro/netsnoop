package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	configMod "github.com/david-caro/netsnoop/internal/config"
	"github.com/david-caro/netsnoop/internal/utils"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	log "github.com/sirupsen/logrus"
)

var iface = flag.String("iface", "wlp0s20f3", "Select interface where to capture")
var configPath = flag.String("configPath", "./netsnoop.yaml", "Path to the configuration yaml file")
var verbose = flag.Bool("verbose", false, "Enable verbose logging")
var promPath = flag.String("promPath", "./netsnoop.prom", "File to output prometheus stats")
var refreshSecs = flag.Uint("refreshSecs", 60, "How often to show the stats and write down the prom file")

func writePromFile(path *string, counter *map[string]map[string]int) error {
	promData := "# HELP toolforge_internal_dependencies Number of times a tool has known to start a connection to the given known dependency\n"
	promData += "# TYPE toolforge_internal_dependencies counter\n"
	for toolName, sites := range *counter {
		for site, count := range sites {
			promData += fmt.Sprintf("toolforge_internal_dependencies{tool=\"%s\", dependency=\"%s\"} %d\n", toolName, site, count)
		}
	}
	// needed as we use golang 1.11.6 and os.WriteFile is not supported yet
	err := ioutil.WriteFile(*path, []byte(promData), 0644)
	log.Debug("Wrote prometheus file ", path)
	return err
}

func interestingSiteInPacket(packet gopacket.Packet, httpServices []string) (string, bool) {
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		log.Debug("Application layer/Payload found.")
		payload := string(applicationLayer.Payload())
		return interestingSiteInString(payload, httpServices)
	}
	return "", false
}

func interestingSiteInString(stringToCheck string, interestingSites []string) (string, bool) {
	for _, interestingSite := range interestingSites {
		if strings.Contains(stringToCheck, interestingSite) {
			log.Debug("Found ", interestingSite, " in data:", stringToCheck)
			return interestingSite, true
		} else {
			log.Debug("Nothing interesting found in:", stringToCheck)
		}
	}
	return "", false
}

func main() {
	flag.Parse()

	log.SetFormatter(&log.JSONFormatter{})
	log.Info(fmt.Sprintf("Starting up, verbose=%v, configPath='%s'", *verbose, *configPath))
	if *verbose {
		log.SetLevel(log.DebugLevel)
	}

	config, err := configMod.ReadConfig(*configPath)
	if err != nil {
		log.Error(err)
		return
	}
	log.Debug("Got config: ", config)

	// Opening Device
	// for now capturing size 1024, only interested in the http headers if any
	// not interested in promiscuous listening either, only packets from this host
	handle, err := pcap.OpenLive(*iface, int32(1024), false, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	defer handle.Close()

	ticker := time.NewTicker(5 * time.Second)
	quit := make(chan struct{})
	counters := make(chan map[string]map[string]int)
	go func() {
		for {
			log.Debug("Waiting for ticker....")
			select {
			case <-ticker.C:
				log.Debug("Waiting for counts....")
				counts := <-counters
				log.Info("Got counts ", counts)
				writePromFile(promPath, &counts)
			case <-quit:
				ticker.Stop()
				return
			}
		}
	}()

	defer ticker.Stop()

	bpfFilter := configMod.ConfigToBPFFilter(config)
	err = handle.SetBPFFilter(bpfFilter)
	if err != nil {
		log.Fatalf("error applying BPF Filter ", bpfFilter, "  error:", err)
	}
	log.Info("Applying BPF filter: ", bpfFilter)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	usersToServicesCount := make(map[string]map[string]int)

	ipToService := configMod.GetIPToService(config)
	httpServices := make([]string, 0, len(config.InterestingHTTPServices))
	for key := range config.InterestingHTTPServices {
		httpServices = append(httpServices, key)
	}

	last_stat_time := time.Now()
	// we use the network traffic only to trigger a full scan, as what we are looking for is containers we can't really match per port
	packetChannel := packetSource.Packets()
	for {
		select {
		case packet := <-packetChannel:
			var foundIPService string
			var foundDstIP, foundSrcIP bool
			if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
				layerData, _ := ip4Layer.(*layers.IPv4)
				log.Debug("Got packet ", packet)

				tcpLayer := packet.Layer(layers.LayerTypeTCP)
				if tcpLayer == nil {
					log.Debug("Skipping packet, not tcp")
					continue
				}
				tcpLayerData, _ := tcpLayer.(*layers.TCP)

				foundHttpService, wasFound := interestingSiteInPacket(packet, httpServices)
				if wasFound {
					log.Info("Detected HTTP based site '", foundHttpService, "'")
				} else {
					log.Debug("Detected IP based site")
				}

				log.Debug("Extracting interesting IPs/port")
				interestingIP := layerData.DstIP.String()
				var localPort int
				foundIPService, foundDstIP = ipToService[interestingIP]
				// the local port is the opposite (src<->dst) than the interesting ip
				localPort = int(tcpLayerData.SrcPort)
				if !foundDstIP {
					interestingIP = layerData.SrcIP.String()
					foundIPService, foundSrcIP = ipToService[interestingIP]
					localPort = int(tcpLayerData.DstPort)
				}
				if !foundDstIP && !foundSrcIP {
					log.Debug("Skipping packet, no interesting ips found in it.")
					continue
				}

				var foundService string
				if wasFound {
					foundService = foundHttpService
				} else {
					foundService = foundIPService
				}

				log.Debug("Found interesting ip ", interestingIP, ", connected to local port ", localPort)

				err := utils.GetUsersAndInterestingServicesNatted(
					packet,
					interestingIP,
					localPort,
					foundService,
					config.InterestingUsersPrefix,
					&usersToServicesCount,
				)
				if err != nil {
					log.Warn("    unable to get process for packet: ", err)
					otherUserServices, ok := usersToServicesCount[utils.OtherUser]
					if !ok {
						otherUserServices = make(map[string]int)
					}
					serviceCount, ok := otherUserServices[foundIPService]
					if ok {
						otherUserServices[foundIPService] = serviceCount + 1
					} else {
						otherUserServices[foundIPService] = 1
					}
					usersToServicesCount[utils.OtherUser] = otherUserServices
				}
				for userName, services := range usersToServicesCount {
					log.Debug("  User:", userName, " services:", services)
				}
				continue
				//log.Warn("Detected unknown ip ", packet.NetworkLayer().NetworkFlow().Dst().String())
			}
		default:
			if time.Since(last_stat_time) > time.Duration(*refreshSecs)*time.Second {
				log.Debug("Sending counts...")
				counters <- usersToServicesCount
			}
		}
	}
}

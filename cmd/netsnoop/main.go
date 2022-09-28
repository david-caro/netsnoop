package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"regexp"
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

func findSiteInPacket(packet gopacket.Packet, httpServicesRegexes []*regexp.Regexp) (string, bool) {
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		log.Debug("Application layer/Payload found.")
		payload := string(applicationLayer.Payload())
		return findSiteInString(payload, httpServicesRegexes)
	}
	return "", false
}

func findSiteInString(stringToCheck string, siteRegexes []*regexp.Regexp) (string, bool) {
	for _, siteRegex := range siteRegexes {
		match := siteRegex.FindString(stringToCheck)
		if match != "" {
			log.Debug("Found ", match, " in data:", stringToCheck)
			return match, true
		} else {
			log.Debug("Nothing interesting found in:", stringToCheck, " with regex:", siteRegex)
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
	// for now capturing size 512, only interested in the http headers if any
	// not interested in promiscuous listening either, only packets from this host
	handle, err := pcap.OpenLive(*iface, int32(512), false, pcap.BlockForever)
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

	httpServicesRegexes := make([]*regexp.Regexp, 0, len(config.HttpServiceRegexes))
	for _, serviceRegex := range config.HttpServiceRegexes {
		regex, err := regexp.Compile(serviceRegex)
		if err != nil {
			log.Error("Unable to parse service regex: ", serviceRegex, " error:", err)
			continue
		}
		httpServicesRegexes = append(httpServicesRegexes, regex)
	}

	last_stat_time := time.Now()
	// we use the network traffic only to trigger a full scan, as what we are looking for is containers we can't really match per port
	packetChannel := packetSource.Packets()
	for {
		select {
		case packet := <-packetChannel:
			if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
				layerData, _ := ip4Layer.(*layers.IPv4)
				log.Debug("Got packet ", packet)

				tcpLayer := packet.Layer(layers.LayerTypeTCP)
				if tcpLayer == nil {
					log.Debug("Skipping packet, not tcp")
					continue
				}
				tcpLayerData, _ := tcpLayer.(*layers.TCP)

				foundService, wasFound := findSiteInPacket(packet, httpServicesRegexes)
				if wasFound {
					log.Debug("Detected HTTP based site '", foundService, "'")
				} else {
					log.Debug("No site found, skipping packet")
					continue
				}

				log.Debug("Extracting interesting IPs/port")
				interestingIP := layerData.DstIP.String()
				// the local port is the opposite (src<->dst) than the interesting ip
				localPort := int(tcpLayerData.SrcPort)
				log.Debug("Found interesting ip ", interestingIP, ", connected to local port ", localPort, " for service ", foundService)

				err := utils.FindUsersForLocalPort(
					packet,
					interestingIP,
					localPort,
					foundService,
					config.InterestingUsersPrefix,
					&usersToServicesCount,
				)
				if err != nil {
					log.Warn("    unable to get process for packet: ", err)
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

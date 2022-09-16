package main

import (
	"flag"
	"fmt"
	"io/ioutil"
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
var writePromSecs = flag.Uint("writePromSecs", 60, "How often to write down the prometheus statistics")

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

	bpfFilter := configMod.ConfigToBPFFilter(config)
	ipToService := configMod.GetIPToService(config)

	// Opening Device
	// for now capturing size 0, not interested in the contents
	// not interested in promiscuous listening either, only packets from this host
	handle, err := pcap.OpenLive(*iface, int32(0), false, pcap.BlockForever)
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

	err = handle.SetBPFFilter(bpfFilter)
	if err != nil {
		log.Fatalf("error applying BPF Filter ", bpfFilter, "  error:", err)
	}
	log.Info("Applying BPF filter: ", bpfFilter)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	usersToServicesCount := make(map[string]map[string]int)

	last_stat_time := time.Now()
	// we use the network traffic only to trigger a full scan, as what we are looking for is containers we can't really match per port
	packetChannel := packetSource.Packets()
	for {
		select {
		case packet := <-packetChannel:
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
					err := utils.GetUsersAndInterestingServices(packet, true, &ipToService, config.InterestingUsersPrefix, &usersToServicesCount)
					if err != nil {
						log.Warn("    unable to get process for packet: ", err)
					}
					for userName, services := range usersToServicesCount {
						log.Debug("  User:", userName, " services:", services)
					}
					continue
				}
				log.Warn("Detected unknown ip ", packet.NetworkLayer().NetworkFlow().Dst().String())
			}
		default:
			if time.Since(last_stat_time) > time.Duration(*writePromSecs)*time.Second {
				log.Debug("Sending counts...")
				counters <- usersToServicesCount
			}
		}
	}
}

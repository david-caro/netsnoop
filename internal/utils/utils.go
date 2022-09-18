package utils

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	log "github.com/sirupsen/logrus"
)

type Void struct{}

var member Void
var OtherUser = "other"

// ProcRoot should point to the root of the proc file system
var ProcRoot = "/proc"

var (
	// TCP contains the standard location to read open TCP IPv4 connections.
	TCP = "net/tcp"
	// TCP6 contains the standard location to read open TCP IPv6 connections.
	TCP6 = "net/tcp6"
	// UDP contains the standard location to read open UDP IPv4 connections.
	UDP = "net/udp"
	// UDP6 contains the standard location to read open UDP IPv6 connections.
	UDP6 = "net/udp6"
)

type Process struct {
	Protocol string
	Pid      int
}

// reads the specific network namespace process file
func (p *Process) getNetNamespace() (string, error) {
	path := filepath.Join(ProcRoot, strconv.Itoa(p.Pid), "ns/net")
	log.Debug("        reading proc namespace net file ", path)
	dest, err := os.Readlink(path)
	return dest[len("net:[")-1 : len(dest)-1], err
}

// reads the specific process file
func (p *Process) readProcNetFile() ([][]string, error) {
	var lines [][]string
	var err error

	path := filepath.Join(ProcRoot, strconv.Itoa(p.Pid), p.Protocol)
	log.Debug("        reading proc net file ", path)
	lines, err = readProcNetFile(path)
	return lines, err
}

func (p *Process) getInterestingServices(ipToService *map[string]string) (*map[string]Void, error) {
	lines, err := p.readProcNetFile()
	if err != nil {
		return nil, err
	}
	interestingServices := findInterestingIPs(lines, ipToService, p.Protocol, p.Pid)
	return interestingServices, nil
}

func findInterestingIPs(lines [][]string, ipToService *map[string]string, protocol string, pid int) *map[string]Void {
	interestingServices := make(map[string]Void)
	for _, line := range lines {
		remoteIPPort := strings.Split(line[2], ":")
		remoteIP := parseIP(remoteIPPort[0])

		interestingService, ok := (*ipToService)[remoteIP.String()]
		if !ok {
			continue
		}
		log.Debug("    found interesting ip ", remoteIP.String(), " part of service ", interestingService)

		interestingServices[interestingService] = member
	}
	return &interestingServices
}

func getUserFromFile(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		log.Error(err)
		return OtherUser
	}

	stat := info.Sys().(*syscall.Stat_t)
	userName, err := user.LookupId(strconv.Itoa(int(stat.Uid)))
	if err != nil {
		log.Error(err)
		return OtherUser
	}
	return userName.Name
}

func findUsersUsingInterestingServices(ipToService *map[string]string, usersPrefix string, protocol string, usersToServices *map[string]map[string]int) error {
	knownNamespaces := make(map[string]bool, 25)
	globStr := fmt.Sprintf("%s/*/%s", ProcRoot, protocol)

	log.Debug("Searching for proc dirs matching ", globStr)
	procDirs, err := filepath.Glob(globStr)
	if err != nil {
		return err
	}
	log.Debug(
		fmt.Sprintf(
			"Checking for any process is connecting to any interesting IPs under %d proc dirs",
			len(procDirs),
		),
	)
	for _, netFile := range procDirs {
		log.Debug("   looking into process network dir", netFile)
		dirChunks := strings.Split(netFile, "/")
		procDirName := dirChunks[len(dirChunks)-3]
		if procDirName == "self" || procDirName == "thread-self" {
			continue
		}
		pid, err := strconv.Atoi(procDirName)
		if err != nil {
			return err
		}

		process := Process{
			Pid:      pid,
			Protocol: protocol,
		}
		netNamespace, _ := process.getNetNamespace()
		if err != nil {
			log.Debug("skipping process ", process, " due to error reading it's net namespace: ", err)
			continue
		}

		// this skips any other process from a net ns that we have already checked
		if ok := knownNamespaces[netNamespace]; ok {
			continue
		}
		knownNamespaces[netNamespace] = true
		interestingServices, err := process.getInterestingServices(ipToService)
		if err != nil {
			log.Debug("Unable to read process network file ", netFile, " error:", err)
			continue
		}
		if len(*interestingServices) != 0 {
			userName := getUserFromFile(filepath.Join(ProcRoot, procDirName))
			if !strings.HasPrefix(userName, usersPrefix) {
				log.Debug("        skipping non interesting user ", userName)
				continue
			}
			log.Debug("        found services (", interestingServices, ") for user ", userName)
			userServices, ok := (*usersToServices)[userName]
			if !ok {
				userServices = make(map[string]int)
			}
			for service := range *interestingServices {
				if curCount, ok := userServices[service]; ok {
					userServices[service] = curCount + 1
				} else {
					userServices[service] = 1
				}
			}
			(*usersToServices)[userName] = userServices
		} else {
			log.Debug("        got nothing xd! from dir ", netFile)
		}
	}
	if len(*usersToServices) == 0 {
		log.Debug("Found no process using any interesting services!", ipToService)
		return fmt.Errorf("unable to find any processes using interesting ips %v", ipToService)
	}
	return nil
}

func readProcNetFile(procFilePath string) ([][]string, error) {
	var lines [][]string

	f, err := os.Open(procFilePath)
	if err != nil {
		// this might happen when the process finished before we were able to read the file
		return nil, fmt.Errorf("can't open proc file: %s", err)
	}
	defer f.Close()

	r := bufio.NewReader(f)
	for {
		line, err := r.ReadBytes('\n')
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		lines = append(lines, lineParts(string(bytes.Trim(line, "\t\n "))))
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("can't read proc file: %s has no content", procFilePath)
	}
	// Remove header line
	return lines[1:], nil
}

// The values in a line are separated by one or more space.
// Split by space and remove all resulting empty strings.
// strings.Split("01   AB", " ") results in ["01", "", "", "AB"]
func lineParts(line string) []string {
	parts := strings.Split(line, " ")
	filtered := parts[:0]
	for _, part := range parts {
		if part != "" {
			filtered = append(filtered, part)
		}
	}
	return filtered
}

func parseIP(ip string) net.IP {
	return net.IP(parseIPSegments(ip))
}

// The IP address is encoded hexadecimal and in reverse order.
// Take two characters and parse then from back to front.
// 01 00 00 7F -> 127 0 0 1
func parseIPSegments(ip string) []uint8 {
	segments := make([]uint8, 0, len(ip)/2)
	for i := len(ip); i > 0; i -= 2 {
		seg, _ := strconv.ParseUint(ip[i-2:i], 16, 8)
		segments = append(segments, uint8(seg))
	}
	return segments
}

func GetUsersAndInterestingServices(packet gopacket.Packet, localIsSrc bool, ipToService *map[string]string, usersPrefix string, usersToServices *map[string]map[string]int) error {
	var err error
	var protocol string
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		protocol = TCP

	} else if tcpLayer := packet.Layer(layers.LayerTypeUDP); tcpLayer != nil {
		protocol = UDP
	}
	if err != nil {
		return err
	}

	err = findUsersUsingInterestingServices(ipToService, usersPrefix, protocol, usersToServices)
	if err != nil {
		return err
	}

	return err
}

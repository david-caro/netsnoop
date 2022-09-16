package netstat

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

	log "github.com/sirupsen/logrus"
)

type Void struct{}

var member Void

type Protocol struct {
	// RelPath is the proc file path relative to the process directory
	RelPath string
}

type Process struct {
	Protocol *Protocol
	Pid      int
}

// ProcRoot should point to the root of the proc file system
var ProcRoot = "/proc"

var (
	// TCP contains the standard location to read open TCP IPv4 connections.
	TCP = &Protocol{"net/tcp"}
	// TCP6 contains the standard location to read open TCP IPv6 connections.
	TCP6 = &Protocol{"net/tcp6"}
	// UDP contains the standard location to read open UDP IPv4 connections.
	UDP = &Protocol{"net/udp"}
	// UDP6 contains the standard location to read open UDP IPv6 connections.
	UDP6 = &Protocol{"net/udp6"}
)

func (p *Process) getInterestingServices(ipToService *map[string]string, userServices *map[string]Void) error {
	lines, err := p.readProcNetFile()
	if err != nil {
		return err
	}
	p.findInterestingIPs(lines, ipToService, userServices)
	return nil
}

func findInterestingIPs(lines [][]string, ipToService *map[string]string, protocol *Protocol, pid int, userServices *map[string]Void) {
	for _, line := range lines {
		remoteIPPort := strings.Split(line[2], ":")
		remoteIP := parseIP(remoteIPPort[0])

		interestingService, ok := (*ipToService)[remoteIP.String()]
		if !ok {
			continue
		}
		log.Debug("    found interesting ip ", remoteIP.String(), " part of service ", interestingService)

		(*userServices)[interestingService] = member
	}
}

func (p *Process) findInterestingIPs(lines [][]string, ipToService *map[string]string, userServices *map[string]Void) {
	findInterestingIPs(lines, ipToService, p.Protocol, p.Pid, userServices)
}

func getUserFromFile(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		log.Error(err)
		return "unknown"
	}

	stat := info.Sys().(*syscall.Stat_t)
	userName, err := user.LookupId(strconv.Itoa(int(stat.Uid)))
	if err != nil {
		log.Error(err)
		return "unknown"
	}
	return userName.Name
}

func FindUsersUsingInterestingServices(ipToService *map[string]string, usersPrefix string, protocol *Protocol) (map[string]map[string]Void, error) {
	globStr := fmt.Sprintf("%s/*/%s", ProcRoot, protocol.RelPath)
	usersUsingInterestingServices := make(map[string]map[string]Void)
	log.Debug("Searching for proc dirs matching ", globStr)
	procDirs, err := filepath.Glob(globStr)
	if err != nil {
		return nil, err
	}
	log.Debug(fmt.Sprintf("Checking for any process is connecting to any interesting IPs under %d proc dirs", len(procDirs)))
	for _, netFile := range procDirs {
		log.Debug("   looking into process dir", netFile)
		dirChunks := strings.Split(netFile, "/")
		procDirName := dirChunks[len(dirChunks)-3]
		if procDirName == "self" || procDirName == "thread-self" {
			continue
		}
		pid, err := strconv.Atoi(procDirName)
		if err != nil {
			return nil, err
		}

		process := Process{
			Pid:      pid,
			Protocol: protocol,
		}
		interestingServices := make(map[string]Void)
		process.getInterestingServices(ipToService, &interestingServices)
		if len(interestingServices) != 0 {
			userName := getUserFromFile(filepath.Join(ProcRoot, procDirName))
			if !strings.HasPrefix(userName, usersPrefix) {
				log.Debug("        skipping non interesting user ", userName)
				continue
			}
			log.Debug("        found services (", interestingServices, ") for user ", userName)
			userServices, ok := usersUsingInterestingServices[userName]
			if !ok {
				userServices = make(map[string]Void)
			}
			for service := range interestingServices {
				userServices[service] = member
			}
			usersUsingInterestingServices[userName] = userServices
		} else {
			log.Debug("        got nothing xd! from dir ", netFile)
		}
	}
	if len(usersUsingInterestingServices) == 0 {
		log.Debug("Found no process using any interesting services!", ipToService)
		return nil, fmt.Errorf("unable to find any processes using interesting ips %v", ipToService)
	}
	return usersUsingInterestingServices, nil
}

func readProcNetFile(procFilePath string) ([][]string, error) {
	var lines [][]string

	f, err := os.Open(procFilePath)
	if err != nil {
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

// reads the specific process file
func (p *Process) readProcNetFile() ([][]string, error) {
	var lines [][]string
	var err error

	path := filepath.Join(ProcRoot, strconv.Itoa(p.Pid), p.Protocol.RelPath)
	log.Debug("        reading proc net file ", path)
	lines, err = readProcNetFile(path)
	return lines, err
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

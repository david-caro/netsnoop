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

type ServiceCounts map[string]int

type UserCounts map[string]*ServiceCounts

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

type ProcessDir struct {
	Protocol string
	Pid      int
}

// reads the specific process file
func (p *ProcessDir) readProcNetFile() ([][]string, error) {
	var lines [][]string
	var err error

	path := filepath.Join(ProcRoot, strconv.Itoa(p.Pid), p.Protocol)
	log.Debug("        reading proc net file ", path)
	lines, err = readProcNetFile(path)
	return lines, err
}

func (p *ProcessDir) getInterestingServices(ipToService *map[string]string, userPrefix string) (*UserCounts, error) {
	lines, err := p.readProcNetFile()
	if err != nil {
		return nil, err
	}

	userCounts := make(UserCounts)
	interestingServices := findInterestingIPs(lines, ipToService, p.Protocol, p.Pid)
	if len(*interestingServices) == 0 {
		log.Debug("    no services found")
		return &userCounts, nil
	}
	log.Debug("    got interesting services: ", interestingServices)
	interestingUsers, err := findInterestingUsers(lines, userPrefix, p.Protocol, p.Pid)
	log.Debug("    got interesting users: ", interestingUsers, " len:", len(interestingUsers))
	if err != nil {
		return nil, err
	}
	for _, user := range interestingUsers {
		userCounts[user] = interestingServices
	}
	log.Debug("    got usercounts: ", userCounts)
	return &userCounts, nil
}

// for some reason, when using containers we have to pull users from two places, from the /proc/<pid>/net/* files and
// the ownership of the /proc/<pid>
func findInterestingUsers(lines [][]string, userPrefix string, protocol string, pid int) ([]string, error) {
	interestingUsers := make(map[string]bool)
	for _, line := range lines {
		if len(line) < 8 {
			return nil, fmt.Errorf("wrong net proc file format, it does not have 8")
		}
		userID := line[8]

		_, ok := interestingUsers[userID]
		if ok {
			log.Debug("               skipping known user id ", userID)
			continue
		}
		log.Debug("    found interesting user ", userID)

		interestingUsers[userID] = true
	}

	procFilePath := filepath.Join(ProcRoot, strconv.Itoa(pid))
	fileInfo, err := os.Stat(procFilePath)
	if err != nil {
		log.Debug("     unable to find owner of ", procFilePath)
	} else {
		log.Debug("     getting owner of ", procFilePath)
		fileSys := fileInfo.Sys()
		userID := strconv.Itoa(int(fileSys.(*syscall.Stat_t).Uid))
		log.Debug("         got ", userID)
		_, ok := interestingUsers[userID]
		if ok {
			log.Debug("               skipping known user id ", userID)
		} else {
			log.Debug("    found interesting user ", userID)
			interestingUsers[userID] = true
		}
	}

	var foundUsers []string
	for userID := range interestingUsers {
		user, err := user.LookupId(userID)
		if err != nil {
			log.Warn("Unable to resolve user with id ", userID, ", err:", err)
			continue
		}
		if strings.HasPrefix(user.Username, userPrefix) {
			foundUsers = append(foundUsers, user.Username)
		}
	}
	return foundUsers, nil
}

func findInterestingIPs(lines [][]string, ipToService *map[string]string, protocol string, pid int) *ServiceCounts {
	interestingServices := make(ServiceCounts)
	for _, line := range lines {
		remoteIPPort := strings.Split(line[2], ":")
		remoteIP := parseIP(remoteIPPort[0])

		interestingService, ok := (*ipToService)[remoteIP.String()]
		if !ok {
			continue
		}
		log.Debug("        found interesting ip ", remoteIP.String(), " part of service ", interestingService)

		interestingServices[interestingService] = 1
	}
	return &interestingServices
}

// this finds every user that is connecting to any interesting service, filtering by the usersPrefix
// to do so, it scans the whole /proc/*/net/* for any network namespace in which there's a connection to any
// interesting service ip, and extracts the users that the file declares, and also from the processes in that namespace.
// The premise here is that in toolforge, for any namespaces there's one and only one tool user in it, so any user
// match in a namespace means that it belongs to that tool's user (that would not be true for shared namespaces).
func findUsersUsingInterestingServices(ipToService *map[string]string, usersPrefix string, protocol string, usersCounts *map[string]map[string]int) error {
	procNetGlob := fmt.Sprintf("%s/*/%s", ProcRoot, protocol)

	log.Debug("Searching for proc dirs matching ", procNetGlob)
	procDirs, err := filepath.Glob(procNetGlob)
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
			log.Debug("    skipping, got procDirName=", procDirName)
			continue
		}
		pid, err := strconv.Atoi(procDirName)
		if err != nil {
			log.Debug("    got error when extracting the pid:", err)
			return err
		}

		processDir := ProcessDir{
			Pid:      pid,
			Protocol: protocol,
		}

		newUsersCounts, err := processDir.getInterestingServices(ipToService, usersPrefix)
		if err != nil {
			log.Debug("    unable to read process network file ", netFile, " error:", err)
			continue
		}
		if len(*newUsersCounts) != 0 {
			log.Debug("        found services (", newUsersCounts, ")")
			for userName, newUserCounts := range *newUsersCounts {
				curUserCounts, ok := (*usersCounts)[userName]
				if !ok {
					(*usersCounts)[userName] = *newUserCounts
					continue
				}
				for service, toAdd := range *newUserCounts {
					if curCount, ok := curUserCounts[service]; ok {
						curUserCounts[service] = curCount + toAdd
					} else {
						curUserCounts[service] = toAdd
					}
				}
			}
		} else {
			log.Debug("        got nothing xd! from dir ", netFile)
		}
	}
	if len(*usersCounts) == 0 {
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

func GetUsersAndInterestingServices(packet gopacket.Packet, localIsSrc bool, ipToService *map[string]string, usersPrefix string, usersCounts *map[string]map[string]int) error {
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

	err = findUsersUsingInterestingServices(ipToService, usersPrefix, protocol, usersCounts)
	if err != nil {
		return err
	}

	return err
}

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
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	log "github.com/sirupsen/logrus"
)

type Void struct{}

type ServiceCounts map[string]int

type UserCounts map[string]*ServiceCounts

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
	lines, err = readProcFile(path)
	return lines, err
}

// Poor man's function to get the user owning a process, uses the permissions of the /proc dirs
func (p *ProcessDir) getUser(userPrefix string) ([]string, error) {
	interestingUsers := make(map[string]bool)
	procFilePath := filepath.Join(ProcRoot, strconv.Itoa(p.Pid))
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
	for user := range interestingUsers {
		foundUsers = append(foundUsers, user)
	}
	return foundUsers, nil
}

func (p *ProcessDir) getUsersUsingIp(ip string, userPrefix string) ([]string, error) {
	lines, err := p.readProcNetFile()
	if err != nil {
		log.Debug("Got error reading procnetfile", err)
		return nil, err
	}

	usersSet := make(map[string]bool)

	for _, line := range lines {
		if len(line) < 8 {
			return nil, fmt.Errorf("wrong net proc file format, it does not have 8")
		}
		localIPPort := strings.Split(line[1], ":")
		localIP := parseIP(localIPPort[0])
		if localIP.String() != ip {
			continue
		}
		log.Debug("Got matching ip (", localIP.String(), "==", ip)
		procUsers, err := p.getUser(userPrefix)
		if err != nil {
			log.Debug("Unable to retrieve users for process ", p, " got error:", err)
			return nil, err
		}
		for _, userID := range procUsers {
			usersSet[userID] = true
		}
	}

	users := make([]string, 0)
	for userID := range usersSet {
		user, err := user.LookupId(userID)
		if err != nil {
			log.Warn("Unable to resolve user with id ", userID, ", err:", err)
			continue
		}
		if strings.HasPrefix(user.Username, userPrefix) {
			users = append(users, user.Username)
		} else {
			log.Debug("skipping user ", user.Username, " as does not match prefix '", userPrefix, "'")
		}
	}
	return users, nil
}

func readProcFile(procFilePath string) ([][]string, error) {
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

type UserCacheEntry struct {
	ExpiresAt int64
	Users     []string
}

func (u *UserCacheEntry) IsExpired() bool {
	if u.ExpiresAt == 0 {
		return false
	}
	return u.ExpiresAt < time.Now().Unix()
}

var userCache = make(map[string]*UserCacheEntry)

func GetUserFromCache(cacheKey string) ([]string, bool) {
	if entry, ok := userCache[cacheKey]; ok {
		if entry.IsExpired() {
			delete(userCache, cacheKey)
			return nil, false
		}
		// refresh the expiration time
		userCache[cacheKey] = &UserCacheEntry{
			// TODO: configure the cache expiration time
			ExpiresAt: time.Now().Add(1 * time.Minute).Unix(),
			Users:     entry.Users,
		}
		return entry.Users, true
	}
	return nil, false
}

// scans the whole /proc for any process that has the given ip in it's network namespace, and returns the interesting
// users in that namespace matching the given prefix
func getUsersForIP(ip string, usersPrefix string, protocol string) ([]string, error) {
	// using a cache as it's quite expensive to scan the whole /proc for every user
	// and relatively save to think that the same ip/port will be used by the same process for a while
	cacheKey := fmt.Sprintf("%s-%s", ip, protocol)
	if cachedUsers, ok := GetUserFromCache(cacheKey); ok {
		log.Debug("Found user in cache for ip ", ip, " users=", cachedUsers)
		return cachedUsers, nil
	}

	procNetGlob := fmt.Sprintf("%s/*/%s", ProcRoot, protocol)

	log.Debug("Searching for proc dirs matching ", procNetGlob)
	procDirs, err := filepath.Glob(procNetGlob)
	if err != nil {
		return nil, err
	}

	usersSet := make(map[string]bool)
	log.Debug("Checking for any process connecting from ip ", ip)
	for _, netFile := range procDirs {
		log.Debug("   looking into process network dir", netFile, " for ip ", ip)
		dirChunks := strings.Split(netFile, "/")
		procDirName := dirChunks[len(dirChunks)-3]
		if procDirName == "self" || procDirName == "thread-self" {
			log.Debug("    skipping, got procDirName=", procDirName)
			continue
		}
		pid, err := strconv.Atoi(procDirName)
		if err != nil {
			log.Debug("    got error when extracting the pid:", err)
			return nil, err
		}

		processDir := ProcessDir{
			Pid:      pid,
			Protocol: protocol,
		}

		newUsers, err := processDir.getUsersUsingIp(ip, usersPrefix)
		if err != nil {
			log.Debug("    unable to read process network file ", netFile, " error:", err)
			continue
		}
		if len(newUsers) != 0 {
			log.Debug("        found users (", newUsers, ")")
			for _, user := range newUsers {
				usersSet[user] = true
			}
		} else {
			log.Debug("        got nothing xd! from dir ", netFile)
		}
	}

	users := make([]string, 0, len(usersSet))
	for user := range usersSet {
		users = append(users, user)
	}
	if len(users) == 0 {
		log.Debug("Found no process using the ip ", ip)
		return nil, fmt.Errorf("unable to find any processes using ip %v", ip)
	}
	userCache[cacheKey] = &UserCacheEntry{
		// TODO: configure the cache expiration time
		ExpiresAt: time.Now().Add(1 * time.Minute).Unix(),
		Users:     users,
	}
	return users, nil
}

// We parse the nf_conntrack file trying to find a line where the first sport is the port we want, and the last dst the
// ip of the service we want.
// An example for port 57090 and ip 172.16.0.119:
//
//	ipv4     2 tcp      6 91 TIME_WAIT src=192.168.231.167 dst=213.186.33.5 sport=57090 dport=80 src=213.186.33.5 dst=172.16.0.119 sport=80 dport=37966 [ASSURED] mark=0 zone=0 use=2
//
// or
// ipv4 2 tcp 6 119 TIME_WAIT src=192.168.231.167 dst=208.80.154.224 sport=34010 dport=80 src=208.80.154.224 dst=172.16.0.119 sport=80 dport=5439 [ASSURED] mark=0 zone=0 use=2
func findUsersForLocalPort(
	dstIp string,
	localPort int,
	foundService string,
	usersPrefix string,
	protocol string,
	usersCounts *map[string]map[string]int,
) error {
	log.Debug("Starting findUsersUsingInterestingServicesByLocalPort")
	nfConntrackFile := fmt.Sprintf("%s/self/net/nf_conntrack", ProcRoot)
	nfConntrackLines, err := readProcFile(nfConntrackFile)
	if err != nil {
		log.Debug("Got error when checking file ", nfConntrackFile, err)
		return err
	}

	log.Debug("Got lines ", nfConntrackLines)
	for _, lineChunks := range nfConntrackLines {
		if len(lineChunks) < 14 {
			log.Debug("Skipping conntrack line, too short (probably listening connection): ", lineChunks)
			continue
		}
		if (lineChunks[8] == fmt.Sprintf("sport=%d", localPort) && lineChunks[11] == fmt.Sprintf("dst=%s", dstIp)) ||
			(lineChunks[13] == fmt.Sprintf("dport=%d", localPort) && lineChunks[10] == fmt.Sprintf("src=%s", dstIp)) {
			log.Debug("Found a match in the nf_conntrack file!", lineChunks)
			nattedIp := strings.Split(lineChunks[6], "=")[1]
			users, error := getUsersForIP(nattedIp, usersPrefix, protocol)
			if error != nil {
				return error
			}
			for _, username := range users {
				if !strings.HasPrefix(username, usersPrefix) {
					continue
				}

				userCounts, ok := (*usersCounts)[username]
				if !ok {
					userCounts = make(map[string]int)
				}
				curCount, ok := userCounts[foundService]
				if ok {
					userCounts[foundService] = curCount + 1
					// loop around the int counter if hit max int value (that is, it becomes -1)
					if userCounts[foundService] <= 0 {
						userCounts[foundService] = 1
					}
				} else {
					userCounts[foundService] = 1
				}
				(*usersCounts)[username] = userCounts
			}
		}
	}
	return nil
}

// This pin-points the connection using the nf_conntrack data (NATed connections)
func FindUsersForLocalPort(
	packet gopacket.Packet,
	ip string,
	localPort int,
	foundService string,
	usersPrefix string,
	usersCounts *map[string]map[string]int,
) error {
	var protocol string
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		protocol = TCP
	} else if tcpLayer := packet.Layer(layers.LayerTypeUDP); tcpLayer != nil {
		protocol = UDP
	}

	return findUsersForLocalPort(ip, localPort, foundService, usersPrefix, protocol, usersCounts)
}

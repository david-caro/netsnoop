package netstat

import (
	"net"
	"os/user"
	"strconv"
)

// Connection contains the gathered information about an open network connection.
type Connection struct {
	// Pid contains the pid of the process. Is zero if open connection can't be assigned to a pid.
	Pid int

	// UserID represents the user account id of the user owning the socket.
	// On Linux systems it is usually a uint32.
	UserID int

	// IP holds the local IP for the connection.
	IP net.IP

	// Port holds the local port for the connection.
	Port int

	// RemoteIP holds the remote IP for the connection.
	RemoteIP net.IP

	// RemotePort holds the remote port for the connection.
	RemotePort int

	// Protocol contains the protocol this connection was discovered with.
	Protocol *Protocol
}

// User looks up the user owning the socket.
// If the user cannot be found, the returned error is of type UnknownUserIdError.
func (c *Connection) User() (*user.User, error) {
	return user.LookupId(strconv.Itoa(c.UserID))
}

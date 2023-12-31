// This tool detects hidden connections

/*
    Copyright (C) 2023  Maurice Lambert
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

// Compilation on Linux:
// go build -ldflags "-s -w" -trimpath -o DetectHiddenConnection DetectHiddenConnection.go

package main

import (
    "encoding/binary"
    "syscall"
    "os/user"
    "strings"
    "bufio"
    "fmt"
    "os"
)

/*
    This function reverses IP bytes.
*/
func reverse_bytes (ip []byte, destination []byte) []byte {
    length := len(ip)
    for index, value := range ip {
        destination[length - index - 1] = value
    }
    return destination
}

/*
    This function formats IPv4 TCP/UDP segment.
*/
func format_ipv4 (buffer []byte) (string, string) {
    ip1 := []byte{0, 0, 0, 0}
    ip2 := []byte{0, 0, 0, 0}

    source := fmt.Sprintf(
        "%08X:%04X", reverse_bytes(buffer[26:30], ip1), buffer[34:36],
    )
    destination := fmt.Sprintf(
        "%08X:%04X", reverse_bytes(buffer[30:34], ip2), buffer[36:38],
    )
    return source + " " + destination, destination + " " + source
}

/*
    This function formats IPv6 TCP/UDP segment.
*/
func format_ipv6 (buffer []byte) (string, string) {
    ip1 := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
    ip2 := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

    source := fmt.Sprintf(
        "%32X:%04X", reverse_bytes(buffer[22:38], ip1), buffer[54:56],
    )
    destination := fmt.Sprintf(
        "%32X:%04X", reverse_bytes(buffer[38:54], ip2), buffer[56:58],
    )
    return source + " " + destination, destination + " " + source
}

/*
    This function checks if packets is visible with netstat.
*/
func check_present (buffer []byte, filename string, version int) {
    var flux1 string
    var flux2 string

    switch version {
    case 4:
        flux1, flux2 = format_ipv4(buffer)
    case 6:
        flux1, flux2 = format_ipv6(buffer)
    }

    file, err := os.Open("/proc/net/" + filename)
    if err != nil {
        fmt.Fprintln(os.Stderr, "Error opening /proc/net file:", err)
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    scanner.Scan()
    for scanner.Scan() {
        line := scanner.Text()
        if strings.Contains(line, flux1) || strings.Contains(line, flux2) {
            return
        }
    }

    fmt.Println("Invisible packet", filename,":", flux1)
}

/*
    This function parses IPv4 packets.
*/
func parses_v4_packets (buffer []byte) {
    if len(buffer) < 38 {
        return
    }

    switch buffer[23] {
    case 0x06:
        if !(len(buffer) > 47 && buffer[47] & 2 == 2 && buffer[47] & 4 == 4) {
            check_present(buffer, "tcp", 4)
        }
    case 0x11:
        check_present(buffer, "udp", 4)
    }
}

/*
    This function parses IPv6 packets.
*/
func parses_v6_packets (buffer []byte) {
    if len(buffer) < 58 {
        return
    }

    switch buffer[20] {
    case 0x06:
        if !(len(buffer) > 67 && buffer[67] & 2 == 2 && buffer[67] & 4 == 4) {
            check_present(buffer, "tcp6", 6)
        }
    case 0x11:
        check_present(buffer, "udp6", 6)
    }
}

/*
    This function parses ethernet frame.
*/
func parse_frame (buffer []byte) {
    if len(buffer) <= 14 {
        return
    }

    ethertype := binary.BigEndian.Uint16(buffer[12:14])
    switch ethertype {
    case 0x0800:
        parses_v4_packets(buffer)
    case 0x86DD:
        parses_v6_packets(buffer)
    }
}

/*
    This function sniffs networks packets.
*/
func sniff () {
    fd, err := syscall.Socket(
        syscall.AF_PACKET,
        syscall.SOCK_RAW,
        int(htons(syscall.ETH_P_ALL)),
    )
    if err != nil {
        fmt.Fprintln(os.Stderr, "Error to get raw socket:", err)
        os.Exit(2)
    }
    defer syscall.Close(fd)

    buffer := make([]byte, 67)
    for {
        _, _, err := syscall.Recvfrom(fd, buffer, 0)
        if err != nil {
            fmt.Fprintln(os.Stderr, "Error to sniff packet:", err)
        }
        parse_frame(buffer)
    }
}

/*
    This function checks if process owner is root,
    if not print a error message and exit with error code.
*/
func check_starts_as_root () {
    if os.Geteuid() != 0 {
        owner, err := user.Current()

        if err != nil {
            owner.Username = "unknown"
        }

        fmt.Fprintln(
            os.Stderr,
            "You should starts this process as root not as",
            owner.Username,
        )
        os.Exit(1)
    }
}

/*
    This function reverts bytes on unsigned short integer.
*/
func htons (i uint16) uint16 {
    return (i << 8) & 0xff00 | i >> 8
}

/*
    The main function to starts the program,
    check root permissions and sniff network.
*/
func main () {
    check_starts_as_root()
    sniff()
}

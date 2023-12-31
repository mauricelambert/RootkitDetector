// This tool detects kernel hookings using kernel addresses

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
// go build -ldflags "-s -w" -trimpath -o DetectKernelHooking DetectKernelHooking.go

package main

import (
    "os/user"
    "strconv"
    "syscall"
    "strings"
    "unsafe"
    "errors"
    "regexp"
    "bufio"
    "bytes"
    "fmt"
    "os"
    "io"
)

/*
    This function loads a kernel module.
*/
func load_kernel_module () error {
    file, err := os.Open("./KernelAddresses.ko")
    if err != nil {
        fmt.Println("1:", err)
        return err
    }
    defer file.Close()

    parameters := ""
    parameters_pointer, err := syscall.BytePtrFromString(parameters)
    if err != nil {
        fmt.Println("2:", err)
        return err
    }
    c_parameters := uintptr(unsafe.Pointer(parameters_pointer))

    _, _, err = syscall.Syscall(
        313, // syscall.SYS_FINIT_MODULE,
        uintptr(int(file.Fd())),
        c_parameters,
        uintptr(0),
    )
    if !errors.Is(err, syscall.Errno(0x26)) {
        _, ok := err.(syscall.Errno)
        if ok {
            return nil
        }
        return err
    }

    buffer, err := io.ReadAll(file)
    if err != nil {
        fmt.Println("4:", err)
        return err
    }

    buffer_pointer := unsafe.Pointer(&buffer[0])
    _, _, err = syscall.Syscall(
        syscall.SYS_INIT_MODULE,
        uintptr(buffer_pointer),
        uintptr(len(buffer)),
        c_parameters,
    )

    _, ok := err.(syscall.Errno)
    if ok {
        return nil
    }
    return err
}

/*
    This function unloads the kernel module.
*/
func unload_kernel_module () error {
    name, err := syscall.BytePtrFromString("KernelAddresses")
    if err != nil {
        return err
    }

    _, _, err = syscall.Syscall(
        syscall.SYS_DELETE_MODULE,
        uintptr(unsafe.Pointer(name)),
        uintptr(0),
        0,
    )

    _, ok := err.(syscall.Errno)
    if ok {
        return nil
    }
    return err
}

/*
    This function returns kernel addresses from logs.
*/
func get_addresses (logs []byte) ([]uint64, error) {
    var addresses []uint64
    scanner := bufio.NewScanner(bytes.NewReader(logs))
    regex, err := regexp.Compile(
        " RootkiDetector - (Function \\w+|Syscall \\d+): [a-fA-F0-9]+",
    )
    if err != nil {
        return nil, err
    }

    for scanner.Scan() {
        result := regex.Find(scanner.Bytes())

        if result != nil {
            address, err := strconv.ParseUint(
                strings.TrimSpace(strings.Split(string(result), ":")[1]),
                16,
                64,
            )
            if err != nil {
                return nil, err
            }
            addresses = append(addresses, address)
        }
    }

    if err := scanner.Err(); err != nil {
        return nil, err
    }

    return addresses, nil
}

/*
    This function gets kernel logs.
*/
func get_kernel_logs() ([]byte, error) {
    length, err := syscall.Klogctl(10, nil)
    if err != nil {
        return nil, err
    }

    buffer := make([]byte, length, length)
    length, err = syscall.Klogctl(3, buffer)
    return buffer[:length], err
}

/*
    This function compares and analyzes kernel addresses.
*/
func compare_addresses(addresses []uint64) uint64 {
    max := addresses[0]
    min := addresses[0]

    for _, address := range addresses {
        if address > max {
            max = address
        } else if address < min {
            min = address
        }
    }

    return max - min
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
    The main function to starts the program,
    check root permissions, load and unload the kernel module,
    get kernel logs and analyze addresses.
*/
func main () {
    check_starts_as_root()
    err := load_kernel_module()
    if err != nil {
        fmt.Fprintln(os.Stderr, "Error loading module:", err)
        os.Exit(2)
    }

    err = unload_kernel_module()
    if err != nil {
        fmt.Fprintln(os.Stderr, "Error unloading module:", err)
    }

    logs, err := get_kernel_logs()
    if err != nil {
        fmt.Fprintln(os.Stderr, "Error reading kernel logs:", err)
        os.Exit(3)
    }

    addresses, err := get_addresses(logs)
    if err != nil {
        fmt.Fprintln(os.Stderr, "Error parsing kernel logs:", err)
        os.Exit(4)
    }

    difference := compare_addresses(addresses)
    fmt.Println("Addresses difference is:", strconv.FormatUint(difference, 10))
    // Default addresses difference      ~25000000
    // Addresses difference with hooking ~150000000
    // Threshold                          87500000
    if difference < 87500000 {
        fmt.Println("[+] There is probably no hooks !")
    } else {
        fmt.Println("[!] There is probably function or syscall hook !")
        os.Exit(127)
    }
}
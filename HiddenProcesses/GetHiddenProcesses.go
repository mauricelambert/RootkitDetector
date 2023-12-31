// This tool prints hidden process with normal PID

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
// go build -ldflags "-s -w" -trimpath -o GetHiddenProcesses GetHiddenProcesses.go

package main

import (
    "path/filepath"
    "os/user"
    "strconv"
    "fmt"
    "log"
    "os"
)

/*
    This function checks if PID is in directories
    list getted from '/proc/' subdirectories.
*/
func process_hidden (directories []int, pid int) bool {
    for _, directory := range directories {
        if directory == pid {
            return false
        }
    }
    return true
}

/*
    The last character for each argument is 0,
    this function modify all 0 bytes to blank character
    to get printable command line.
*/
func add_space (command []byte) []byte {
    for index, character := range command {
        if character == 0 {
            command[index] = 32
        }
    }

    return command
}

/*
    This function checks if process owner is root,
    if not print a error message but don't stop the process.
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
    }
}

/*
    The main function to starts the program,
    list entries in 'proc' and compare with
    accessible files in '/proc/<any valid PID>'.
*/
func main () {
    check_starts_as_root()

    entries, err := os.ReadDir("/proc/")
    if err != nil {
        log.Fatal(err)
    }

    var directories []int

    for _, e := range entries {
        integer, err := strconv.Atoi(e.Name())
        if err == nil {
            directories = append(directories, integer)
        }
    }

    self_pid := os.Getpid()
    for pid := 0; pid < self_pid; pid += 1 {
        directory := fmt.Sprintf("/proc/%d/", pid)
        executable, err1 := filepath.EvalSymlinks(directory + "exe")
        command_line, err2 := os.ReadFile(directory + "cmdline")

        if (err1 == nil || err2 == nil) && process_hidden(directories, pid) {
            fmt.Println(
                "[!] Hidden process found:", strconv.Itoa(pid), executable,
            )
            fmt.Println("\t", string(add_space(command_line)))
        }
    }
}
package buildinfo

import (
	"os"
	"runtime"
)

var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

type Info struct {
	Version  string `json:"version"`
	Commit   string `json:"commit"`
	Date     string `json:"date"`
	Hostname string `json:"hostname"`
	GoOS     string `json:"go_os"`
	GoArch   string `json:"go_arch"`
}

func Current() Info {
	hostname, _ := os.Hostname()
	return Info{
		Version:  Version,
		Commit:   Commit,
		Date:     Date,
		Hostname: hostname,
		GoOS:     runtime.GOOS,
		GoArch:   runtime.GOARCH,
	}
}

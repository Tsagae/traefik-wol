/*
From https://github.com/traefik/plugindemo?tab=readme-ov-file#logs:
Currently, the only way to send logs to Traefik is to use os.Stdout.WriteString("...") or os.Stderr.WriteString("...").
In the future, we will try to provide something better and based on levels.
*/

package traefik_wol

import (
	"fmt"
	"os"
)

type LogLevel int

const (
	DEBUG LogLevel = iota
	ERROR
)

func log(logLevel LogLevel, msg string) {
	switch logLevel {
	case DEBUG:
		_, errWrite := os.Stdout.WriteString(msg)
		if errWrite != nil {
			panic(fmt.Sprintf("Error while writing string to stdout: %e\n", errWrite))
		}
	case ERROR:
		_, errWrite := os.Stderr.WriteString(msg)
		if errWrite != nil {
			panic(fmt.Sprintf("Error while writing string to stdout: %e\n", errWrite))
		}
	default:
		panic("Unknown log level")
	}
}

func logWithError(logLevel LogLevel, msg string, err error) {
	if err == nil {
		log(ERROR, "Called logWithError with nil error")
	}
	log(logLevel, fmt.Sprintf("%s: %v", msg, err))
}

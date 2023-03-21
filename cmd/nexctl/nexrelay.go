package main

import (
	"fmt"
	"net"
	"net/rpc/jsonrpc"

	"github.com/urfave/cli/v2"
)

func callNexrelay(method string) (string, error) {
	conn, err := net.Dial("unix", "/run/nexrelay.sock")
	if err != nil {
		fmt.Printf("Failed to connect to nexrelay: %+v\n", err)
		return "", err
	}
	defer conn.Close()

	client := jsonrpc.NewClient(conn)

	var result string
	err = client.Call("NexrelayCtl."+method, nil, &result)
	if err != nil {
		fmt.Printf("Failed to execute method (%s): %+v\n", method, err)
		return "", err
	}
	return result, nil
}

func checkNexrelayVersion() error {
	result, err := callNexrelay("Version")
	if err != nil {
		fmt.Printf("Failed to get nexrelay version: %+v\n", err)
		return err
	}

	if Version != result {
		errMsg := fmt.Sprintf("Version mismatch: nexctl(%s) nexrelay(%s)\n", Version, result)
		fmt.Print(errMsg)
		return fmt.Errorf("%s", errMsg)
	}

	return nil
}

func cmdNexrelayVersion(cCtx *cli.Context) error {
	fmt.Printf("nexctl version: %s\n", Version)

	result, err := callNexrelay("Version")
	if err == nil {
		fmt.Printf("nexrelay version: %s\n", result)
	}
	return err
}

func cmdNexrelayStatus(cCtx *cli.Context) error {
	if err := checkNexrelayVersion(); err != nil {
		return err
	}

	result, err := callNexrelay("Status")
	if err == nil {
		fmt.Print(result)
	}
	return err
}

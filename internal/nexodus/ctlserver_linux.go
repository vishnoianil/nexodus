//go:build linux

package nexodus

import (
	"context"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"sync"

	"github.com/nexodus-io/nexodus/internal/util"
)

func CtlServerStart(ctx context.Context, wg *sync.WaitGroup, cs CtlServer) error {
	ctlServerLinuxStart(ctx, wg, cs)
	return nil
}

func ctlServerLinuxStart(ctx context.Context, wg *sync.WaitGroup, cs CtlServer) {
	util.GoWithWaitGroup(wg, func() {
		for {
			// Use a different waitgroup here, because we want to make sure
			// all of the subroutines have exited before we attempt to restart
			// the control server.
			ctlWg := &sync.WaitGroup{}
			err := ctlServerLinuxRun(ctx, ctlWg, cs)
			ctlWg.Done()
			if err == nil {
				// No error means it shut down cleanly because it got a message to stop
				break
			}
			cs.Logger().Error("Ctl interface error, restarting: ", err)
		}
	})
}

func ctlServerLinuxRun(ctx context.Context, ctlWg *sync.WaitGroup, cs CtlServer) error {
	unixSocketPath := cs.GetSocketPath()
	os.Remove(unixSocketPath)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: unixSocketPath, Net: "unix"})
	if err != nil {
		cs.Logger().Error("Error creating unix socket: ", err)
		return err
	}
	defer l.Close()

	err = rpc.Register(cs.GetReceiver())
	if err != nil {
		cs.Logger().Error("Error on rpc.Register(): ", err)
		return err
	}

	// This routine will exit when the listener is closed intentionally,
	// or some error occurs.
	errChan := make(chan error)
	util.GoWithWaitGroup(ctlWg, func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				errChan <- err
				break
			}
			util.GoWithWaitGroup(ctlWg, func() {
				jsonrpc.ServeConn(conn)
			})
		}
	})

	// Handle new connections until we get notified to stop the CtlServer,
	// or Accept() fails for some reason.
	stopNow := false
	for {
		select {
		case err = <-errChan:
			// Accept() failed, collect the error and stop the CtlServer
			stopNow = true
			cs.Logger().Error("Error on Accept(): ", err)
			break
		case <-ctx.Done():
			cs.Logger().Info("Stopping CtlServer")
			stopNow = true
			err = nil
		}
		if stopNow {
			break
		}
	}

	return err
}

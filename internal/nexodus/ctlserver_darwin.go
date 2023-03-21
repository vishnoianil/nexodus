//go:build darwin

package nexodus

import (
	"context"
	"errors"
	"sync"
)

func CtlServerStart(ctx context.Context, wg *sync.WaitGroup, cs CtlServer) error {
	return errors.New("Ctl interface not yet supported on OSX")
}

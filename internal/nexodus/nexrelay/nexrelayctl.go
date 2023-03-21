package nexrelay

import (
	"fmt"
)

type NexrelayCtl struct {
	nexr *Nexrelay
}

func (nrc *NexrelayCtl) Status(_ string, result *string) error {
	var statusStr string
	switch nrc.nexr.status {
	case NexdStatusStarting:
		statusStr = "Starting"
	case NexdStatusAuth:
		statusStr = "WaitingForAuth"
	case NexdStatusRunning:
		statusStr = "Running"
	default:
		statusStr = "Unknown"
	}
	res := fmt.Sprintf("Status: %s\n", statusStr)
	if len(nrc.nexr.statusMsg) > 0 {
		res += nrc.nexr.statusMsg
	}
	*result = res
	return nil
}

func (nrc *NexrelayCtl) Version(_ string, result *string) error {
	*result = nrc.nexr.version
	return nil
}

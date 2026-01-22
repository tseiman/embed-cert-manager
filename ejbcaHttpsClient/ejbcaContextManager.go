package ejbcaHttpsClient

import (
	"context"
	"sync"
	"time"
)

var (
	ctxMu      sync.Mutex
	storedCtx  context.Context
	storedStop context.CancelFunc
	defaultTimeout = 2 * time.Minute
)

func GetContext() context.Context {
	return GetContextRenewed(false, 0)
}

// renew=true: immer neuen Context erzeugen (und alten ggf. canceln)
// renew=false: bestehenden zurückgeben oder (falls keiner) neu erzeugen
func GetContextRenewed(renew bool, tout time.Duration) context.Context {
	ctxMu.Lock()
	defer ctxMu.Unlock()

	if renew {
		// alten (intern erzeugten) Context beenden
		if storedStop != nil {
			storedStop()
		}
		storedStop = nil
		storedCtx = nil // <-- WICHTIG: damit wirklich neu erzeugt wird
	}

	// bereits vorhanden?
	if storedCtx != nil {
		return storedCtx
	}

	// timeout wählen
	if tout <= 0 {
		tout = defaultTimeout
	}

	// neuen erzeugen
	newCtx, cancel := context.WithTimeout(context.Background(), tout)
	storedCtx = newCtx
	storedStop = cancel
	return storedCtx
}

func CancelStoredContext() {
	ctxMu.Lock()
	defer ctxMu.Unlock()

	if storedStop != nil {
		storedStop()
	}
	storedStop = nil
	storedCtx = nil
}

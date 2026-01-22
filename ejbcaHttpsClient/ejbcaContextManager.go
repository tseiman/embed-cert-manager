package ejbcaHttpsClient

/**
 *  Copyright (c) 2026 Thomas Schmidt
 *  SPDX-License-Identifier: MIT 
 *  home: https://github.com/tseiman/embed-cert-manager/
 * 
 *  Tool to check and eventually renew a certificate on an embedded client
 *  with limited software capabilities.
 * 
 *  Package ejbcaHttpsClient provides helpers to communicate with EJBCA via HTTPS/SOAP.
 *  This file manages a reusable context with a configurable timeout to control SOAP calls.
 *
 */

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

/**
 *  GetContext returns a stored context for EJBCA operations.
 *  If no context is stored yet, it will create one using the default timeout.
 *
 *  Returns:
 *    - context.Context: the stored (or newly created) context.
 *
 */
func GetContext() context.Context {
	return GetContextRenewed(false, 0)
}

/**
 *  GetContextRenewed returns a stored context and optionally renews it.
 *  If renew is true, any previously stored context is cancelled and a new context is created.
 *  If renew is false, the existing stored context is returned if present; otherwise a new one is created.
 *
 *  Params:
 *    - renew: whether to force creation of a new context and cancel the previous one.
 *    - tout: timeout to use when creating a new context. If <= 0, a default timeout is used.
 *
 *  Returns:
 *    - context.Context: the stored (possibly renewed) context.
 *
 */
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

/**
 *  CancelStoredContext cancels the currently stored context (if any) and clears internal references.
 *  This is useful to stop in-flight operations and ensure a fresh context is created next time.
 *
 */
func CancelStoredContext() {
	ctxMu.Lock()
	defer ctxMu.Unlock()

	if storedStop != nil {
		storedStop()
	}
	storedStop = nil
	storedCtx = nil
}

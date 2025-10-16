// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bitcoin/core"
)

// activeNetParams is a pointer to the parameters specific to the
// currently active bitcoin network.
var activeNetParams = &regressionNetParams

// params is used to group parameters for various networks such as the main
// network and test networks.
type params struct {
	*core.Params
	rpcPort string
}

// mainNetParams contains parameters specific to the main network
// (wire.MainNet).  NOTE: The RPC port is intentionally different from the
// reference implementation because btcd does not handle wallet requests.  The
// separate wallet process listens on the well-known port and forwards requests
// it does not handle on to btcd.  This approach allows the wallet process
// to emulate the full reference implementation RPC API.
var mainNetParams = params{
	Params: &core.MainNetParams,
}

// regressionNetParams contains parameters specific to the regression test
// network (wire.TestNet).  NOTE: The RPC port is intentionally different
// than the reference implementation - see the mainNetParams comment for
// details.
var regressionNetParams = params{
	Params: &core.RegressionNetParams,
}

// testNet3Params contains parameters specific to the test network (version 3)
// (wire.TestNet3).  NOTE: The RPC port is intentionally different from the
// reference implementation - see the mainNetParams comment for details.
var testNet3Params = params{
	Params: &core.TestNet3Params,
}

// testNet4Params contains parameters specific to the test network (version 4)
// (wire.TestNet4).  NOTE: The RPC port is intentionally different from the
// reference implementation - see the mainNetParams comment for details.
var testNet4Params = params{
	Params: &core.TestNet4Params,
}

// simNetParams contains parameters specific to the simulation test network
// (wire.SimNet).
var simNetParams = params{
	Params: &core.SimNetParams,
}

// sigNetParams contains parameters specific to the Signet network
// (wire.SigNet).
var sigNetParams = params{
	Params: &core.SigNetParams,
}

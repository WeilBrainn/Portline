//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	rpcCAuthnWinNT         = 10
	fwpmSessionFlagDynamic = 0x00000001

	fwpActionBlock  = 0x00001001
	fwpActionPermit = 0x00001002

	fwpMatchEqual        = 0
	fwpMatchFlagsAllSet  = 6
	fwpUint8             = 1
	fwpUint16            = 2
	fwpUint32            = 3
	fwpUint64            = 4
	fwpConditionFlagLoop = 0x00000001
)

type wfpGUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

var (
	fwpuclnt = syscall.NewLazyDLL("fwpuclnt.dll")
	iphlpapi = syscall.NewLazyDLL("iphlpapi.dll")

	procFwpmEngineOpen0               = fwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0              = fwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmSubLayerAdd0              = fwpuclnt.NewProc("FwpmSubLayerAdd0")
	procFwpmFilterAdd0                = fwpuclnt.NewProc("FwpmFilterAdd0")
	procConvertInterfaceIndexToLuid   = iphlpapi.NewProc("ConvertInterfaceIndexToLuid")
)

var (
	// {c38d57d1-05a7-4c33-904f-7fbceee60e82}
	fwpmLayerAleAuthConnectV4 = wfpGUID{0xc38d57d1, 0x05a7, 0x4c33, [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}}
	// {4a72393b-319f-44bc-84c3-ba54dcb3b6b4}
	fwpmLayerAleAuthConnectV6 = wfpGUID{0x4a72393b, 0x319f, 0x44bc, [8]byte{0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4}}
	// {4cd62a49-59c3-4969-b7f3-bda5d32890a4}
	fwpmConditionIPLocalInterface = wfpGUID{0x4cd62a49, 0x59c3, 0x4969, [8]byte{0xb7, 0xf3, 0xbd, 0xa5, 0xd3, 0x28, 0x90, 0xa4}}
	// {b235ae9a-1d64-49b8-a44c-5ff3d9095045}
	fwpmConditionIPRemoteAddress = wfpGUID{0xb235ae9a, 0x1d64, 0x49b8, [8]byte{0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45}}
	// {c35a604d-d22b-4e1a-91b4-68f674ee674b}
	fwpmConditionIPRemotePort = wfpGUID{0xc35a604d, 0xd22b, 0x4e1a, [8]byte{0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b}}
	// {3971ef2b-623e-4f9a-8cb1-6e79b806b9a7}
	fwpmConditionIPProtocol = wfpGUID{0x3971ef2b, 0x623e, 0x4f9a, [8]byte{0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7}}
	// {632ce23b-5167-435c-86d7-e903684aa80c}
	fwpmConditionFlags = wfpGUID{0x632ce23b, 0x5167, 0x435c, [8]byte{0x86, 0xd7, 0xe9, 0x03, 0x68, 0x4a, 0xa8, 0x0c}}

	// {7d4e9a10-2b8c-4c31-9e15-1a2b3c4d5e6f}
	portlineWFPSublayer = wfpGUID{0x7d4e9a10, 0x2b8c, 0x4c31, [8]byte{0x9e, 0x15, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f}}
)

type fwpmDisplayData0 struct {
	name        *uint16
	description *uint16
}

type fwpByteBlob struct {
	size uint32
	_pad uint32
	data *byte
}

type fwpmSession0 struct {
	sessionKey           wfpGUID
	displayData          fwpmDisplayData0
	flags                uint32
	txnWaitTimeoutInMSec uint32
	processId            uint32
	_pad                 uint32
	sid                  uintptr
	username             *uint16
	kernelMode           int32
	_pad2                uint32
}

type fwpmSublayer0 struct {
	subLayerKey  wfpGUID
	displayData  fwpmDisplayData0
	flags        uint32
	_pad         uint32
	providerKey  *wfpGUID
	providerData fwpByteBlob
	weight       uint16
	_pad2        [6]byte
}

type fwpValue0 struct {
	typ uint32
	_   uint32
	val uint64
}

type fwpmFilterCondition0 struct {
	fieldKey       wfpGUID
	matchType      uint32
	_              uint32
	conditionValue fwpValue0
}

type fwpmAction0 struct {
	typ        uint32
	_          uint32
	filterType wfpGUID
}

type fwpmFilter0 struct {
	filterKey           wfpGUID
	displayData         fwpmDisplayData0
	flags               uint32
	_                   uint32
	providerKey         *wfpGUID
	providerData        fwpByteBlob
	layerKey            wfpGUID
	subLayerKey         wfpGUID
	weight              fwpValue0
	numFilterConditions uint32
	_                   uint32
	filterCondition     *fwpmFilterCondition0
	action              fwpmAction0
	rawContext          [16]byte
	reserved            *wfpGUID
	filterId            uint64
	effectiveWeight     fwpValue0
}

type wfpGuard struct {
	engine uintptr
}

func (g *wfpGuard) Close() {
	if g != nil && g.engine != 0 {
		procFwpmEngineClose0.Call(g.engine)
		g.engine = 0
	}
}

func newWFPGuard(tunnelIfIndex int, endpointIP string, endpointPort int) (*wfpGuard, error) {
	ip := net.ParseIP(endpointIP).To4()
	if ip == nil || endpointPort < 1 || endpointPort > 65535 || tunnelIfIndex <= 0 {
		return nil, fmt.Errorf("invalid WFP guard parameters")
	}
	var tunnelLuid uint64
	ret, _, _ := procConvertInterfaceIndexToLuid.Call(uintptr(uint32(tunnelIfIndex)), uintptr(unsafe.Pointer(&tunnelLuid)))
	if ret != 0 || tunnelLuid == 0 {
		return nil, fmt.Errorf("ConvertInterfaceIndexToLuid failed: 0x%x", ret)
	}

	sessionName, _ := syscall.UTF16PtrFromString("Portline WFP Session")
	session := fwpmSession0{
		displayData: fwpmDisplayData0{name: sessionName},
		flags:       fwpmSessionFlagDynamic,
	}
	var engine uintptr
	ret, _, _ = procFwpmEngineOpen0.Call(0, rpcCAuthnWinNT, 0, uintptr(unsafe.Pointer(&session)), uintptr(unsafe.Pointer(&engine)))
	if ret != 0 || engine == 0 {
		return nil, fmt.Errorf("FwpmEngineOpen0 failed: 0x%x", ret)
	}
	guard := &wfpGuard{engine: engine}

	sublayerName, _ := syscall.UTF16PtrFromString("Portline Full-Tunnel Guard")
	sublayer := fwpmSublayer0{
		subLayerKey: portlineWFPSublayer,
		displayData: fwpmDisplayData0{name: sublayerName},
		weight:      0xFFFF,
	}
	ret, _, _ = procFwpmSubLayerAdd0.Call(engine, uintptr(unsafe.Pointer(&sublayer)), 0)
	if ret != 0 {
		guard.Close()
		return nil, fmt.Errorf("FwpmSubLayerAdd0 failed: 0x%x", ret)
	}

	addFilter := func(name string, layer wfpGUID, action uint32, weight uint8, conds []fwpmFilterCondition0) error {
		nPtr, _ := syscall.UTF16PtrFromString(name)
		var condPtr *fwpmFilterCondition0
		if len(conds) > 0 {
			condPtr = &conds[0]
		}
		f := fwpmFilter0{
			displayData:         fwpmDisplayData0{name: nPtr},
			layerKey:            layer,
			subLayerKey:         portlineWFPSublayer,
			weight:              fwpValue0{typ: fwpUint8, val: uint64(weight)},
			numFilterConditions: uint32(len(conds)),
			filterCondition:     condPtr,
			action:              fwpmAction0{typ: action},
		}
		var filterID uint64
		r, _, _ := procFwpmFilterAdd0.Call(engine, uintptr(unsafe.Pointer(&f)), 0, uintptr(unsafe.Pointer(&filterID)))
		if r != 0 {
			return fmt.Errorf("FwpmFilterAdd0(%s) failed: 0x%x", name, r)
		}
		return nil
	}

	loopbackCond := []fwpmFilterCondition0{{
		fieldKey:       fwpmConditionFlags,
		matchType:      fwpMatchFlagsAllSet,
		conditionValue: fwpValue0{typ: fwpUint32, val: fwpConditionFlagLoop},
	}}
	// Permit loopback on IPv4 & IPv6 so local GUI (127.0.0.1) is never blocked.
	if err := addFilter("Portline Permit Loopback v4", fwpmLayerAleAuthConnectV4, fwpActionPermit, 15, loopbackCond); err != nil {
		guard.Close()
		return nil, err
	}
	if err := addFilter("Portline Permit Loopback v6", fwpmLayerAleAuthConnectV6, fwpActionPermit, 15, loopbackCond); err != nil {
		guard.Close()
		return nil, err
	}

	// Permit all outbound IPv4 over the Portline Tunnel Wintun interface.
	luidCopy := tunnelLuid
	tunnelCond := []fwpmFilterCondition0{{
		fieldKey:       fwpmConditionIPLocalInterface,
		matchType:      fwpMatchEqual,
		conditionValue: fwpValue0{typ: fwpUint64, val: uint64(uintptr(unsafe.Pointer(&luidCopy)))},
	}}
	if err := addFilter("Portline Permit Tunnel v4", fwpmLayerAleAuthConnectV4, fwpActionPermit, 14, tunnelCond); err != nil {
		runtime.KeepAlive(luidCopy)
		guard.Close()
		return nil, err
	}
	runtime.KeepAlive(luidCopy)

	// Permit outbound TCP to the VPN server endpoint.
	epUint32 := binary.BigEndian.Uint32(ip)
	endpointCond := []fwpmFilterCondition0{
		{
			fieldKey:       fwpmConditionIPRemoteAddress,
			matchType:      fwpMatchEqual,
			conditionValue: fwpValue0{typ: fwpUint32, val: uint64(epUint32)},
		},
		{
			fieldKey:       fwpmConditionIPRemotePort,
			matchType:      fwpMatchEqual,
			conditionValue: fwpValue0{typ: fwpUint16, val: uint64(uint16(endpointPort))},
		},
		{
			fieldKey:       fwpmConditionIPProtocol,
			matchType:      fwpMatchEqual,
			conditionValue: fwpValue0{typ: fwpUint8, val: 6}, // TCP
		},
	}
	if err := addFilter("Portline Permit Endpoint TCP", fwpmLayerAleAuthConnectV4, fwpActionPermit, 14, endpointCond); err != nil {
		guard.Close()
		return nil, err
	}

	// Block all other outbound IPv4 and IPv6 connections.
	if err := addFilter("Portline Block Direct v4", fwpmLayerAleAuthConnectV4, fwpActionBlock, 1, nil); err != nil {
		guard.Close()
		return nil, err
	}
	if err := addFilter("Portline Block Direct v6", fwpmLayerAleAuthConnectV6, fwpActionBlock, 1, nil); err != nil {
		guard.Close()
		return nil, err
	}

	return guard, nil
}

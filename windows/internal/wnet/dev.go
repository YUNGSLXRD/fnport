package wnet

// Dev: a packet device, the Wintun adapter or a stand-in in tests.
// ReadPacket is called from one goroutine; WritePacket may be called from many.
type Dev interface {
	ReadPacket(buf []byte) (int, error)
	WritePacket(pkt []byte) error
	Close() error
}

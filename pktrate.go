package calltr

// PktRate is used to hold packet and byte rates for RTP streams.
// It is supposed to be updated or read only under a lock so it
// does not have atomic members. For now is just an alias for EvRate.
type PktRate = EvRate

package pieceurls

// ProbeCallback receives progress while probing candidate SP HTTP bases for one piece.
type ProbeCallback interface {
	ProbeStart(pieceCID string, endpointCount int)
	ProbeFinished(pieceCID string, completed, total int)
}

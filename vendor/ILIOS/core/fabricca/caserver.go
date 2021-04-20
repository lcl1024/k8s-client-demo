package fabricca

type Ca struct {
	CaName      string
	AutoCreate  bool
	CSRName     []CSRName
	Hostname    []string
	CommonName  string
	PeerNode    int
	PeerPorts   [][3]int32
	OrdererNode int
	OrdererPort [][1]int32
	CaAdmins    []CaAdmins
}
type OrgPeerNode struct {
	NodeCount int
}
type OrgOrdererNode struct {
	NodeCount int
}
type CaAdmins struct {
	Name     string
	Password string
}

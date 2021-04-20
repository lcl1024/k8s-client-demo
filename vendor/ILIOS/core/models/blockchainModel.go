package models

type BlockchainMSP struct {
	Admincerts *BlockchainCertFile
	Cacerts    *BlockchainCertFile
	Keystore   *BlockchainCertFile
	Signcerts  *BlockchainCertFile
	Tlscacerts *BlockchainCertFile
}

type BlockchainTLS struct {
	CaCrt     *BlockchainCertFile
	ServerCrt *BlockchainCertFile
	ServerKey *BlockchainCertFile
}

type BlockchainCertFile struct {
	Name    string
	Content []byte
	Path    string
}

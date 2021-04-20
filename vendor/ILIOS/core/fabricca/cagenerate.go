package fabricca

import (
	"ILIOS/common"
	"ILIOS/core/models"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"

	"ILIOS/core/fabricca/ca"
	"ILIOS/core/fabricca/csp"

	"github.com/astaxie/beego/logs"
	"github.com/hyperledger/fabric/bccsp"
)

type CaKeystore struct {
	CaKey  []byte
	CaCert []byte
}

func GenerateCaKeyAndCert(userid string, orgname string, commonname string) (*CaKeystore, error) {
	dir := CaKeystorePath(userid, orgname)
	signCA, err := ca.NewCA(dir, orgname, commonname, "", "", "", "", "", "")
	if err != nil {
		return nil, err
	}
	logs.Debug(signCA)
	if err := rename(userid, dir); err != nil {
		return nil, err
	}
	key, err := ioutil.ReadFile(path.Join(dir, "ca-key.pem"))
	if err != nil {
		return nil, err
	}
	cert, err := ioutil.ReadFile(path.Join(dir, "ca-cert.pem"))
	if err != nil {
		return nil, err
	}

	return &CaKeystore{
		CaKey:  key,
		CaCert: cert,
	}, nil
}

//GenerateOrGetTLSCa 生成一个tlsca，如果tlsca目录下已经存在ca的私钥和证书，通过私钥和证书重新构造tlsca
func GenerateOrGetTLSCa(userid string, orgname string, commonname string) (*ca.CA, error) {
	tlsdir := CaTLSKeystorePath(userid, orgname)
	if common.IsTlsAutoGenerate() == false {
		tlspath := CustomFabricTLSPath("tlsca-" + orgname)
		os.Mkdir(tlsdir, 0755)
		err := common.CopyFile(path.Join(tlspath, "tls-cert.pem"), path.Join(tlsdir, "tls-cert.pem"))
		if err != nil {
			return nil, err
		}
		/*err = common.CopyFile(path.Join(tlspath, "tls-key.pem"), path.Join(tlsdir, "tls-key.pem"))
		if err != nil {
			return nil, err
		}*/
		return nil, nil
	}

	tlsCA, err := ca.NewCA(tlsdir, orgname, commonname, "", "", "", "", "", "")
	if err != nil {
		return nil, err
	}
	if err := renameTLS(userid, tlsdir); err != nil {
		return nil, err
	}
	if common.IsTlsAutoGenerate() == true {
		err = generateVerifyingMSP(OrgMspPath(userid, orgname), tlsCA)
		if err != nil {
			return nil, err
		}
	}

	return tlsCA, nil
}

func GenerateTLS(tlsCA *ca.CA, userid string, orgname string, commonname string, username string) (*models.BlockchainTLS, error) {
	tlsdir := UserTLSKeystorePath(userid, orgname, username)
	if common.IsTlsAutoGenerate() == true {
		err := generateVerifyingMSP(OrgMspPath(userid, orgname), tlsCA)
		if err != nil {
			return nil, err
		}
		err = generateTLS(tlsdir, commonname, []string{}, tlsCA)
		if err != nil {
			return nil, err
		}
	} else {
		tlspath := CustomFabricTLSPath(commonname)
		os.Mkdir(tlsdir, 0755)
		err := common.CopyFile(path.Join(tlspath, "ca.crt"), path.Join(tlsdir, "ca.crt"))
		if err != nil {
			return nil, err
		}
		err = common.CopyFile(path.Join(tlspath, "server.key"), path.Join(tlsdir, "server.key"))
		if err != nil {
			return nil, err
		}
		err = common.CopyFile(path.Join(tlspath, "server.crt"), path.Join(tlsdir, "server.crt"))
		if err != nil {
			return nil, err
		}
	}

	ca, err := ioutil.ReadFile(path.Join(tlsdir, "ca.crt"))
	if err != nil {
		return nil, err
	}
	key, err := ioutil.ReadFile(path.Join(tlsdir, "server.key"))
	if err != nil {
		return nil, err
	}
	cert, err := ioutil.ReadFile(path.Join(tlsdir, "server.crt"))
	if err != nil {
		return nil, err
	}
	os.MkdirAll(tlscacertspath(userid, orgname, username), 0755)
	err = common.CopyFile(path.Join(tlsdir, "ca.crt"), path.Join(tlscacertspath(userid, orgname, username), "ca.pem"))
	if err != nil {
		return nil, err
	}
	return &models.BlockchainTLS{
		CaCrt: &models.BlockchainCertFile{
			Name:    "ca.crt",
			Content: ca,
			Path:    path.Join(tlsdir, "ca.crt"),
		},
		ServerKey: &models.BlockchainCertFile{
			Name:    "server.key",
			Content: key,
			Path:    path.Join(tlsdir, "server.key"),
		},
		ServerCrt: &models.BlockchainCertFile{
			Name:    "server.crt",
			Content: cert,
			Path:    path.Join(tlsdir, "server.crt"),
		},
	}, nil
}

func generateTLS(baseDir, name string, sans []string,
	tlsCA *ca.CA) error {

	// create folder structure
	tlsDir := baseDir

	err := os.MkdirAll(tlsDir, 0755)
	if err != nil {
		return err
	}

	/*
		Generate the TLS artifacts in the TLS folder
	*/

	// generate private key
	tlsPrivKey, _, err := csp.GeneratePrivateKey(tlsDir)
	if err != nil {
		return err
	}
	// get public key
	tlsPubKey, err := csp.GetECPublicKey(tlsPrivKey)
	if err != nil {
		return err
	}
	// generate X509 certificate using TLS CA
	_, err = tlsCA.SignCertificate(filepath.Join(tlsDir),
		name, sans, tlsPubKey, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	if err != nil {
		return err
	}
	err = x509Export(filepath.Join(tlsDir, "ca.crt"), tlsCA.SignCert)
	if err != nil {
		return err
	}

	// rename the generated TLS X509 cert
	err = os.Rename(filepath.Join(tlsDir, x509Filename(name)),
		filepath.Join(tlsDir, "server.crt"))
	if err != nil {
		return err
	}

	err = keyExport(tlsDir, filepath.Join(tlsDir, "server.key"), tlsPrivKey)
	if err != nil {
		return err
	}

	return nil
}

func generateVerifyingMSP(baseDir string, tlsCA *ca.CA) error {
	err := createFolderStructure(baseDir, true)
	if err != nil {
		return err
	}
	err = x509Export(filepath.Join(baseDir, "tlscacerts", x509Filename(tlsCA.Name)), tlsCA.SignCert)
	if err != nil {
		return err
	}

	return nil
}
func createFolderStructure(rootDir string, local bool) error {

	var folders []string
	// create admincerts, cacerts, keystore and signcerts folders
	folders = []string{
		filepath.Join(rootDir, "admincerts"),
		filepath.Join(rootDir, "cacerts"),
		filepath.Join(rootDir, "tlscacerts"),
	}
	if local {
		folders = append(folders, filepath.Join(rootDir, "keystore"),
			filepath.Join(rootDir, "signcerts"))
	}

	for _, folder := range folders {
		err := os.MkdirAll(folder, 0755)
		if err != nil {
			return err
		}
	}

	return nil
}

func x509Filename(name string) string {
	return name + "-cert.pem"
}

func rename(userid string, dir string) error {
	fileinfos, err := ioutil.ReadDir(dir)
	if err != nil {
		//logs.Error(err)
		return err
	}
	for _, v := range fileinfos {
		if strings.Contains(v.Name(), "_sk") {
			logs.Info("1", v.Name())
			err := os.Rename(filepath.Join(dir, v.Name()), filepath.Join(dir, "ca-key.pem"))
			if err != nil {
				return err
			}
		}
		if strings.Contains(v.Name(), "-cert") {
			logs.Info("2", v.Name())
			err := os.Rename(filepath.Join(dir, v.Name()), filepath.Join(dir, "ca-cert.pem"))
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func renameTLS(userid string, dir string) error {
	fileinfos, err := ioutil.ReadDir(dir)
	if err != nil {
		//logs.Error(err)
		return err
	}
	for _, v := range fileinfos {
		if strings.Contains(v.Name(), "_sk") {
			logs.Info("1", v.Name())
			err := os.Rename(filepath.Join(dir, v.Name()), filepath.Join(dir, "tls-key.pem"))
			if err != nil {
				return err
			}
		}
		if strings.Contains(v.Name(), "-cert") {
			logs.Info("2", v.Name())
			err := os.Rename(filepath.Join(dir, v.Name()), filepath.Join(dir, "tls-cert.pem"))
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func x509Export(path string, cert *x509.Certificate) error {
	return pemExport(path, "CERTIFICATE", cert.Raw)
}

func keyExport(keystore, output string, key bccsp.Key) error {
	id := hex.EncodeToString(key.SKI())

	return os.Rename(filepath.Join(keystore, id+"_sk"), output)
}

func pemExport(path, pemType string, bytes []byte) error {
	//write pem out to file
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	return pem.Encode(file, &pem.Block{Type: pemType, Bytes: bytes})
}

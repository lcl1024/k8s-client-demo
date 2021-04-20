package sdk

import (
	"fmt"
	"path"
	"testing"
	"time"
)

func TestNewConn(t *testing.T) {
	orgCA, err := ConstructCAFromDir(path.Join("/Users/liuqiang/go/src/wasabi/backEnd/msp", "baas1"))
	if err != nil {
		panic(fmt.Sprintln("InitSdkConfig", err))
	}

	tlsRootCrt := orgCA.TLSCACert()
	endpoint := Endpoint{Address: "127.0.0.1:50052", Override: "192.168.9.1", TLS: tlsRootCrt, Timeout: time.Second * 3}
	_, err = createConnection(&endpoint)
	fmt.Println(err)

}

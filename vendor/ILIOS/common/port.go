package common

import (
	"ILIOS/common/viper"
	"ILIOS/core/configpath"
	"path"
)

type PortConfig struct {
	Enabled    bool `json:"-"`
	PortRange  *PortRange
	PortUsered *PortUsered
}

type PortRange struct {
	OrdererPort     []int32
	KafkaPort       []int32
	ZookeeperPort   []int32
	PeerPort        []int32
	ElasticPort     []int32
	ExOrdererPort   []int32
	ExKafkaPort     []int32
	ExZookeeperPort []int32
}
type PortUsered struct {
	OrdererPort     []int32
	KafkaPort       []int32
	ZookeeperPort   []int32
	PeerPort        []int32
	ElasticPort     []int32
	ExOrdererPort   []int32
	ExKafkaPort     []int32
	ExZookeeperPort []int32
}

var portConfig *PortConfig

func init() {
	//如果是第一次启动，没有portConfig文件，先生成
	//portConfig = &PortConfig{
	//	Enabled: getCustomPortEnabled(),
	//	PortRange: &PortRange{
	//		OrdererPort:     getOrdererPort(),
	//		KafkaPort:       getKafkaPort(),
	//		ZookeeperPort:   getZookeeperPort(),
	//		PeerPort:        GetPeerPort(),
	//		ElasticPort:     getElasticPort(),
	//		ExOrdererPort:   getExOrdererPort(),
	//		ExKafkaPort:     getExKafkaPort(),
	//		ExZookeeperPort: getExZookeeperPort(),
	//	},
	//}
	//logs.Info("portConfig %+v", portConfig.PortRange)
}

func getPortConfigFileName() string {
	return path.Join(configpath.GetBaaSTmpPath(""), "port_config")
}

func getCustomPortEnabled() bool {
	return viper.GetBool("customPort.enabled")
}
func getOrdererPort() []int32 {
	from := viper.GetInt("customPort.port.orderer.from")
	to := viper.GetInt("customPort.port.orderer.to")
	port := []int32{}
	for i := from; i <= to; i++ {
		port = append(port, int32(i))
	}
	return port
}

func getKafkaPort() []int32 {
	from := viper.GetInt("customPort.port.kafka.from")
	to := viper.GetInt("customPort.port.kafka.to")
	port := []int32{}
	for i := from; i <= to; i++ {
		port = append(port, int32(i))
	}
	return port
}

func getZookeeperPort() []int32 {
	from := viper.GetInt("customPort.port.zookeeper.from")
	to := viper.GetInt("customPort.port.zookeeper.to")
	port := []int32{}
	for i := from; i <= to; i++ {
		port = append(port, int32(i))
	}
	return port
}
func GetPeerPort() []int32 {
	from := viper.GetInt("customPort.port.peer.from")
	to := viper.GetInt("customPort.port.peer.to")
	port := []int32{}
	for i := from; i <= to; i++ {
		port = append(port, int32(i))
	}
	return port
}
func getElasticPort() []int32 {
	from := viper.GetInt("customPort.port.elastic.from")
	to := viper.GetInt("customPort.port.elastic.to")
	port := []int32{}
	for i := from; i <= to; i++ {
		port = append(port, int32(i))
	}
	return port
}

func getExOrdererPort() []int32 {
	from := viper.GetInt("customPort.externalPort.orderer.from")
	to := viper.GetInt("customPort.externalPort.orderer.to")
	port := []int32{}
	for i := from; i <= to; i++ {
		port = append(port, int32(i))
	}
	return port
}

func getExKafkaPort() []int32 {
	from := viper.GetInt("customPort.externalPort.kafka.from")
	to := viper.GetInt("customPort.externalPort.kafka.to")
	port := []int32{}
	for i := from; i <= to; i++ {
		port = append(port, int32(i))
	}
	return port
}

func getExZookeeperPort() []int32 {
	from := viper.GetInt("customPort.externalPort.zookeeper.from")
	to := viper.GetInt("customPort.externalPort.zookeeper.to")
	port := []int32{}
	for i := from; i <= to; i++ {
		port = append(port, int32(i))
	}
	return port
}

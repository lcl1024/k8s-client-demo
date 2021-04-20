package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric/common/tools/configtxgen/encoder"
	"github.com/hyperledger/fabric/common/tools/configtxgen/localconfig"
	"github.com/hyperledger/fabric/common/tools/configtxlator/update"
	"github.com/hyperledger/fabric/common/util"
	"github.com/hyperledger/fabric/core/scc/cscc"
	"github.com/hyperledger/fabric/msp"
	cb "github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protos/orderer"
	ab "github.com/hyperledger/fabric/protos/orderer"
	"github.com/hyperledger/fabric/protos/orderer/etcdraft"
	pb "github.com/hyperledger/fabric/protos/peer"
	"github.com/hyperledger/fabric/protos/utils"
)

const (
	defaultMSPType               = "bccsp"
	defaultBatchTimeout          = 5 * time.Second
	defaultMaxMessageCount       = 10
	defaultAbsoluteMaxBytes      = 100 * 1024 * 1024
	defaultPreferredMaxBytes     = 512 * 1024
	defaultChannelCapability     = "V1_3"
	defaultOrdererCapability     = "V1_1"
	defaultApplicationCapability = "V1_2"
	defaultPolicyType            = encoder.ImplicitMetaPolicyType
)

const (
	// DefaultSystemChainID is the default name of system chain
	DefaultSystemChainID = "byfn-sys-channel"
)

const (
	// DefaultConsortium is the name of the default consortim
	DefaultConsortium = "SampleConsortium"
)

const (
	// error
	PartFail = "partial failed"
	AllFail  = "all failed"
)

var acceptAllPolicy = &localconfig.Policy{
	Type: encoder.SignaturePolicyType,
	Rule: "OutOf(0, 'None.member')",
}

// ImplicitMetaPolicy ...
type ImplicitMetaPolicy string

// policy
const (
	PolicyAnyAdmins      ImplicitMetaPolicy = "ANY Admins"
	PolicyMajorityAdmins ImplicitMetaPolicy = "MAJORITY Admins"
	PolicyAllAdmins      ImplicitMetaPolicy = "ALL Admins"

	PolicyAnyWriters      ImplicitMetaPolicy = "ANY Writers"
	PolicyAllWriters      ImplicitMetaPolicy = "ALL Writers"
	PolicyMajorityWriters ImplicitMetaPolicy = "MAJORITY Writers"

	PolicyAnyReaders      ImplicitMetaPolicy = "ANY Readers"
	PolicyAllReaders      ImplicitMetaPolicy = "ALL Readers"
	PolicyMajorityReaders ImplicitMetaPolicy = "MAJORITY Readers"
)

// GenesisConfig ...
type GenesisConfig struct {
	ChainID                 string
	OrdererType             string
	Addresses               []string
	BatchTimeout            time.Duration
	KafkaBrokers            []string
	EtcdRaft                *etcdraft.ConfigMetadata
	MaxMessageCount         uint32
	AbsoluteMaxBytes        uint32
	PreferredMaxBytes       uint32
	MaxChannels             uint64
	OrdererOrganizations    []*Organization
	ConsortiumOrganizations []*Organization
	ConsortiumName          string
	AdminsPolicy            ImplicitMetaPolicy
	WritersPolicy           ImplicitMetaPolicy
	ReadersPolicy           ImplicitMetaPolicy
}

// ChannelConfig ...
type ChannelConfig struct {
	ChainID       string
	Consortium    string
	Organizations []*Organization
	AdminsPolicy  ImplicitMetaPolicy
	WritersPolicy ImplicitMetaPolicy
	ReadersPolicy ImplicitMetaPolicy
}

// Organization ...
// Only support fabric msp type
// AnchorPeers: ["grpcs://192.168.9.11:3432", ...]
type Organization struct {
	Name        string
	ID          string
	MSPDir      string
	AnchorPeers []string
}

// SignChannelConfigUpdate ...
func (client *Client) SignChannelConfigUpdate(update []byte) ([]byte, []byte, error) {
	creator, err := client.signer.Serialize()
	if err != nil {
		logger.Error("Error serializing signer", err)
		return nil, nil, err
	}
	sigHeader, err := newSignatureHeaderWithCreator(creator)
	if err != nil {
		logger.Error("Error creating signature header", err)
		return nil, nil, err
	}
	signatureHeader := utils.MarshalOrPanic(sigHeader)

	toSignBytes := util.ConcatenateBytes(signatureHeader, update)

	signedSigHeader, err := client.signer.Sign(toSignBytes)
	if err != nil {
		logger.Error("Error signning sigHeader", err)
		return nil, nil, err
	}
	return signatureHeader, signedSigHeader, nil
}

// GetChannelConfigUpdate ...
func (client *Client) GetChannelConfigUpdate(add bool, chainID string, block *cb.Block, updateOrdererOrgs []*Organization,
	updateApplicationOrgs []*Organization, updateConsortiumOrgs map[string][]*Organization, updateOrdererAddrs []string, updateRaftNodes []etcdraft.Consenter) ([]byte, error) {
	tx, err := configUpdate(add, chainID, block, updateOrdererOrgs, updateApplicationOrgs, updateConsortiumOrgs, updateOrdererAddrs, updateRaftNodes)
	if err != nil {
		logger.Error("Error computing update", err)
		return nil, err
	}
	return utils.Marshal(tx)
}

// UpdateChannelAdd ...
func (client *Client) UpdateChannelAdd(chainID string, block *cb.Block, updateOrdererOrgs []*Organization,
	updateApplicationOrgs []*Organization, updateConsortiumOrgs map[string][]*Organization, updateOrdererAddrs []string, caster *Endpoint, updateRaftNodes []etcdraft.Consenter) error {
	return updateChannel(true, chainID, block, updateOrdererOrgs, updateApplicationOrgs, updateConsortiumOrgs, updateOrdererAddrs, caster, client.signer, updateRaftNodes)
}

// UpdateChannelDel ...
func (client *Client) UpdateChannelDel(chainID string, block *cb.Block, updateOrdererOrgs []*Organization, updateApplicationOrgs []*Organization,
	updateConsortiumOrgs map[string][]*Organization, updateOrdererAddrs []string, caster *Endpoint, updateRaftNodes []etcdraft.Consenter) error {
	return updateChannel(false, chainID, block, updateOrdererOrgs, updateApplicationOrgs, updateConsortiumOrgs, updateOrdererAddrs, caster, client.signer, updateRaftNodes)
}

// UpdateChannelByConfigUpdate ...
func (client *Client) UpdateChannelByConfigUpdate(chainID string, configUpdate []byte, sigs []*cb.ConfigSignature, caster *Endpoint) error {
	creator, err := client.signer.Serialize()
	if err != nil {
		logger.Error("Error serializing signer", err)
		return err
	}

	envelopeBytes, err := CreateChannelEnvelopeBytes(chainID, creator, configUpdate, sigs)
	if err != nil {
		logger.Error("Error creating newChannelEnvelope payload", err)
		return err
	}

	signature, err := client.signer.Sign(envelopeBytes)
	if err != nil {
		logger.Error("Error signning payload", err)
		return err
	}
	return Broadcast(envelopeBytes, signature, caster)
}

func configUpdate(add bool, chainID string, block *cb.Block, updateOrdererOrgs []*Organization, updateApplicationOrgs []*Organization,
	updateConsortiumOrgs map[string][]*Organization, updateOrdererAddrs []string, updateRaftNodes []etcdraft.Consenter) (*cb.ConfigUpdate, error) {
	env := utils.ExtractEnvelopeOrPanic(block, 0)
	payload, err := utils.GetPayload(env)
	if err != nil {
		logger.Error("Error getting payload from block", err)
		return nil, err
	}
	configEnv := &cb.ConfigEnvelope{}
	err = proto.Unmarshal(payload.Data, configEnv)
	if err != nil {
		logger.Error("Error Unmarshal ConfigEnvelope", err)
		return nil, err
	}

	oldConf := configEnv.Config
	newConf := proto.Clone(oldConf).(*cb.Config)

	if newConf.ChannelGroup.Groups[channelconfig.OrdererGroupKey] == nil {
		logger.Errorf("channel has closed, group: %+v is empty", channelconfig.OrdererGroupKey)
		return nil, fmt.Errorf("channel has closed")
	}

	// 应用链升级肯定会影响application,系统链升级不会
	if updateApplicationOrgs != nil && newConf.ChannelGroup.Groups[channelconfig.ApplicationGroupKey] == nil {
		logger.Errorf("channel has closed, group: %+s is empty", channelconfig.ApplicationGroupKey)
		return nil, fmt.Errorf("channel has closed")
	}

	if newConf.ChannelGroup.Values[channelconfig.OrdererAddressesKey] == nil {
		logger.Errorf("channel has closed, value %+v is empty", channelconfig.OrdererAddressesKey)
		return nil, fmt.Errorf("channel has closed")
	}

	// ordererAddrs
	if updateOrdererAddrs != nil {
		val := newConf.ChannelGroup.Values[channelconfig.OrdererAddressesKey].Value
		oa := &cb.OrdererAddresses{}
		if err = proto.Unmarshal(val, oa); err != nil {
			logger.Error("Error Unmarshal OrdererAddresses", err)
			return nil, err
		}
		// oldAddrMap := make(map[string]bool)
		newAddrMap := make(map[string]bool)
		for _, addr := range oa.Addresses {
			// oldAddrMap[addr] = true
			newAddrMap[addr] = true
		}
		for _, addr := range updateOrdererAddrs {
			if add {
				newAddrMap[addr] = true
			} else {
				delete(newAddrMap, addr)
			}
		}
		var newAddrs []string
		for addr, _ := range newAddrMap {
			newAddrs = append(newAddrs, addr)
		}

		oa.Addresses = newAddrs

		newConf.ChannelGroup.Values[channelconfig.OrdererAddressesKey].Value, err = proto.Marshal(oa)
		if err != nil {
			logger.Error("Error marshaling OrdererAddresses", err)
			return nil, err
		}
	}
	// etcdraft node update
	if updateRaftNodes != nil {
		oc := new(orderer.ConsensusType)
		consensus := newConf.ChannelGroup.Groups[channelconfig.OrdererGroupKey].Values[channelconfig.ConsensusTypeKey].Value
		if err = proto.Unmarshal(consensus, oc); err != nil {
			logger.Error("Error Unmarshal orderer's ConsensusType", err)
			return nil, err
		}
		om := new(etcdraft.ConfigMetadata)
		if err = proto.Unmarshal(oc.Metadata, om); err != nil {
			logger.Error("Error Unmarshal etcdraft's ConfigMetadata", err)
			return nil, err
		}

		updateNodeMap := make(map[string]*etcdraft.Consenter)
		for _, node := range om.Consenters {
			key := fmt.Sprintf("%s-%d", node.Host, node.Port)
			updateNodeMap[key] = &etcdraft.Consenter{
				Host:          node.Host,
				Port:          node.Port,
				ServerTlsCert: node.ServerTlsCert,
				ClientTlsCert: node.ClientTlsCert,
			}
		}

		if add { //新增或更新已存在的etcdraft节点的配置信息
			for _, node := range updateRaftNodes {
				key := fmt.Sprintf("%s-%d", node.Host, node.Port)
				updateNodeMap[key] = &etcdraft.Consenter{
					Host:          node.Host,
					Port:          node.Port,
					ServerTlsCert: node.ServerTlsCert,
					ClientTlsCert: node.ClientTlsCert,
				}
			}
		} else { //删除已存在的etcdraft节点的配置信息
			for _, node := range updateRaftNodes {
				key := fmt.Sprintf("%s-%d", node.Host, node.Port)
				delete(updateNodeMap, key)
			}
		}
		updateNodes := make([]*etcdraft.Consenter, 0)
		for _, node := range updateNodeMap {
			updateNodes = append(updateNodes, node)
		}

		om.Consenters = updateNodes

		if oc.Metadata, err = proto.Marshal(om); err != nil {
			logger.Error("Error marshaling etcdraft's ConfigMetadata", err)
			return nil, err
		}

		if consensus, err = proto.Marshal(oc); err != nil {
			logger.Error("Error marshaling orderer's ConsensusType", err)
			return nil, err
		}
		newConf.ChannelGroup.Groups[channelconfig.OrdererGroupKey].Values[channelconfig.ConsensusTypeKey].Value = consensus
	}

	if add {
		// add orgs
		if updateOrdererOrgs != nil {
			// system chain
			for _, org := range updateOrdererOrgs {
				newConf.ChannelGroup.Groups[channelconfig.OrdererGroupKey].Groups[org.Name], err = encoder.NewOrdererOrgGroup(&localconfig.Organization{
					Name:    org.Name,
					ID:      org.ID,
					MSPDir:  org.MSPDir,
					MSPType: defaultMSPType,
				})
				if err != nil {
					logger.Error("Error creating ordererOrgGroup", err)
					return nil, err
				}
			}
		}

		if updateConsortiumOrgs != nil {
			// update consortium orgs
			for name, orgs := range updateConsortiumOrgs {
				var localOrgs []*localconfig.Organization
				for _, org := range orgs {
					localOrgs = append(localOrgs, &localconfig.Organization{
						Name:    org.Name,
						ID:      org.ID,
						MSPDir:  org.MSPDir,
						MSPType: defaultMSPType,
					})
				}

				if _, ok := newConf.ChannelGroup.Groups[channelconfig.ConsortiumsGroupKey].Groups[name]; !ok {
					newConf.ChannelGroup.Groups[channelconfig.ConsortiumsGroupKey].Groups[name], err = encoder.NewConsortiumGroup(&localconfig.Consortium{
						Organizations: localOrgs,
					})
				} else {
					// 只有系统链更新会添加, Note, NewOrdererOrgGroup is correct here, as the structure is identical
					for _, org := range localOrgs {
						newConf.ChannelGroup.Groups[channelconfig.ConsortiumsGroupKey].Groups[name].Groups[org.Name], err = encoder.NewOrdererOrgGroup(org)
						if err != nil {
							logger.Error("Error creating ordererOrgGroup", err)
							return nil, err
						}
					}
				}
			}
		}
		if updateApplicationOrgs != nil {
			// application chain
			for _, org := range updateApplicationOrgs {
				anchorPeers := []*localconfig.AnchorPeer{}
				for _, ap := range org.AnchorPeers {
					anchorPeers = append(anchorPeers, &localconfig.AnchorPeer{
						Host: parseURL(ap).Host,
						Port: parseURL(ap).Port,
					})
				}
				newConf.ChannelGroup.Groups[channelconfig.ApplicationGroupKey].Groups[org.Name], err = encoder.NewApplicationOrgGroup(&localconfig.Organization{
					Name:        org.Name,
					ID:          org.ID,
					MSPDir:      org.MSPDir,
					MSPType:     defaultMSPType,
					AnchorPeers: anchorPeers,
				})
				if err != nil {
					logger.Error("Error creating applicationOrgGroup", err)
					return nil, err
				}
			}
		}

	} else {
		for _, organization := range updateOrdererOrgs {
			delOrgName := organization.Name
			if _, ok := newConf.ChannelGroup.Groups[channelconfig.OrdererGroupKey].Groups[delOrgName]; ok {
				delete(newConf.ChannelGroup.Groups[channelconfig.OrdererGroupKey].Groups, delOrgName)
			}
		}
		for _, organization := range updateApplicationOrgs {
			delOrgName := organization.Name
			if _, ok := newConf.ChannelGroup.Groups[channelconfig.ApplicationGroupKey].Groups[delOrgName]; ok {
				delete(newConf.ChannelGroup.Groups[channelconfig.ApplicationGroupKey].Groups, delOrgName)
			}
		}
		for delOrgName, _ := range updateConsortiumOrgs {
			if _, ok := newConf.ChannelGroup.Groups[channelconfig.ConsortiumsGroupKey].Groups[delOrgName]; ok {
				delete(newConf.ChannelGroup.Groups[channelconfig.ConsortiumsGroupKey].Groups, delOrgName)
			}
		}
	}

	updateTx, err := update.Compute(oldConf, newConf)
	if err != nil {
		return nil, err
	}
	updateTx.ChannelId = chainID
	return updateTx, nil

}

// 仅测试过系统链和公共链的删除 未对其它链进行过测试
func configDelOrgByName(chainID string, orgName string, block *cb.Block, delOrdererOrgs, delApplicationOrgs, delConsortiumOrgs, delOrdererAddrs, delRaftNodes bool) (*cb.ConfigUpdate, error) {

	env := utils.ExtractEnvelopeOrPanic(block, 0)
	payload, err := utils.GetPayload(env)
	if err != nil {
		logger.Error("Error getting payload from block", err)
		return nil, err
	}
	configEnv := &cb.ConfigEnvelope{}
	err = proto.Unmarshal(payload.Data, configEnv)
	if err != nil {
		logger.Error("Error unmarshaling ConfigEnvelope", err)
		return nil, err
	}

	oldConf := configEnv.Config
	newConf := proto.Clone(oldConf).(*cb.Config)

	if newConf.ChannelGroup.Groups[channelconfig.OrdererGroupKey] == nil {
		logger.Errorf("channel has closed, group: %+v is empty", channelconfig.OrdererGroupKey)
		return nil, fmt.Errorf("channel has closed")
	}

	if newConf.ChannelGroup.Values[channelconfig.OrdererAddressesKey] == nil {
		logger.Errorf("channel has closed, value %+v is empty", channelconfig.OrdererAddressesKey)
		return nil, fmt.Errorf("channel has closed")
	}

	// 删除orderer节点
	if delOrdererAddrs {
		val := newConf.ChannelGroup.Values[channelconfig.OrdererAddressesKey].Value
		oa := &cb.OrdererAddresses{}
		if err = proto.Unmarshal(val, oa); err != nil {
			logger.Error("Error unmarshaling OrdererAddresses", err)
			return nil, err
		}
		// TODO: Map这部分功能照搬的updateConfig的代码，没有必要，直接插入newAddrs就行
		newAddrMap := make(map[string]bool)
		for _, addr := range oa.Addresses {
			// TODO: 此处存在BUG，非跨网情况下的使用的addr是IP+Port，会无法删除
			if strings.Contains(addr, orgName) {
				continue
			}
			newAddrMap[addr] = true
		}
		var newAddrs []string
		for addr := range newAddrMap {
			newAddrs = append(newAddrs, addr)
		}

		oa.Addresses = newAddrs

		newConf.ChannelGroup.Values[channelconfig.OrdererAddressesKey].Value, err = proto.Marshal(oa)
		if err != nil {
			logger.Error("Error marshaling OrdererAddresses", err)
			return nil, err
		}
	}

	// 删除raft节点
	if delRaftNodes {
		oc := new(orderer.ConsensusType)
		consensus := newConf.ChannelGroup.Groups[channelconfig.OrdererGroupKey].Values[channelconfig.ConsensusTypeKey].Value
		if err = proto.Unmarshal(consensus, oc); err != nil {
			logger.Error("Error unmarshaling orderer's ConsensusType", err)
			return nil, err
		}
		om := new(etcdraft.ConfigMetadata)
		if err = proto.Unmarshal(oc.Metadata, om); err != nil {
			logger.Error("Error unmarshaling etcdraft's ConfigMetadata", err)
			return nil, err
		}

		updateNodeMap := make(map[string]*etcdraft.Consenter)
		for _, node := range om.Consenters {
			// TODO: 此处存在BUG，非跨网情况下的使用的host是IP，会无法删除
			if strings.Contains(node.Host, orgName) {
				continue
			}
			key := fmt.Sprintf("%s-%d", node.Host, node.Port)
			updateNodeMap[key] = &etcdraft.Consenter{
				Host:          node.Host,
				Port:          node.Port,
				ServerTlsCert: node.ServerTlsCert,
				ClientTlsCert: node.ClientTlsCert,
			}
		}

		updateNodes := make([]*etcdraft.Consenter, 0)
		for _, node := range updateNodeMap {
			updateNodes = append(updateNodes, node)
		}

		om.Consenters = updateNodes

		if oc.Metadata, err = proto.Marshal(om); err != nil {
			logger.Error("Error marshaling etcdraft's ConfigMetadata", err)
			return nil, err
		}

		if consensus, err = proto.Marshal(oc); err != nil {
			logger.Error("Error marshaling orderer's ConsensusType", err)
			return nil, err
		}
		newConf.ChannelGroup.Groups[channelconfig.OrdererGroupKey].Values[channelconfig.ConsensusTypeKey].Value = consensus
	}

	// 修改ordererOrgs
	if delOrdererOrgs {
		for key := range newConf.ChannelGroup.Groups[channelconfig.OrdererGroupKey].Groups {
			if strings.Contains(key, orgName) {
				delete(newConf.ChannelGroup.Groups[channelconfig.OrdererGroupKey].Groups, key)
			}
		}
	}

	// 修改applicationOrgs
	if delApplicationOrgs {
		for key := range newConf.ChannelGroup.Groups[channelconfig.ApplicationGroupKey].Groups {
			if strings.Contains(key, orgName) {
				delete(newConf.ChannelGroup.Groups[channelconfig.ApplicationGroupKey].Groups, key)
			}
		}
	}

	// 修改consortiumOrgs
	if delConsortiumOrgs {
		for key := range newConf.ChannelGroup.Groups[channelconfig.ConsortiumsGroupKey].Groups[localconfig.SampleConsortiumName].Groups {
			if strings.Contains(key, orgName) {
				delete(newConf.ChannelGroup.Groups[channelconfig.ConsortiumsGroupKey].Groups[localconfig.SampleConsortiumName].Groups, key)
			}
		}
	}

	updateTx, err := update.Compute(oldConf, newConf)
	if err != nil {
		return nil, err
	}
	updateTx.ChannelId = chainID
	return updateTx, nil
}

/*
 * FUNCTION:	生成删除指定名称的orderer节点后的配置块信息
 * 				被deleteOrdererDirectly方法调用
 * INPUT:		chainID	---	通道名
				ordererName	---	要删除的orderer名称
				endpoint	--- 要删除的orderer的地址IP，在非跨网情况下用到
				block	---	当前区块链网络上的配置块信息
				delApplicationOrgs	--- 是否是删除应用链（通道）上的信息，在修改应用链（通道）上的配置块信息时启用（publicchain也算应用链）
				delConsortiumOrgs	--- 是否是修改系统链（通道）上的信息，在修改系统链（通道）上的配置块信息时启用（byfn-sys-channel）
				注： 本方法参数相对configDelOrgByName方法的参数少了delOrdererOrgs（是否删除orderer）、delOrdererAddrs（是否删除orderer地址）这两项本方法默认为true
					还有一个delRaftNodes（是否删除raft节点）本方法将其抛出由外部调用方法决定，但是其实在添加组织或orderer的时候会默认将其添加到配置块的raftNode中。
 * OUTPUT:		*cb.ConfigUpdate	--- 删除了信息后的配置块信息，也就是后续签名广播更新的配置块
				error				--- 错误信息
 * AUTHOR:		刘成龙
 * CREATE:		2020/7/30
*/
func configDeleteOrdererByName(chainID, ordererName, endpoint string, block *cb.Block /* delApplicationOrgs, delConsortiumOrgs,*/, delRaftNodes bool) (*cb.ConfigUpdate, error) {
	env := utils.ExtractEnvelopeOrPanic(block, 0)
	payload, err := utils.GetPayload(env)
	if err != nil {
		logger.Error("Error getting payload from block", err)
		return nil, err
	}
	configEnv := &cb.ConfigEnvelope{}
	err = proto.Unmarshal(payload.Data, configEnv)
	if err != nil {
		logger.Error("Error unmarshaling ConfigEnvelope", err)
		return nil, err
	}

	oldConf := configEnv.Config
	newConf := proto.Clone(oldConf).(*cb.Config)

	if newConf.ChannelGroup.Groups[channelconfig.OrdererGroupKey] == nil {
		logger.Errorf("channel has closed, group: %+v is empty", channelconfig.OrdererGroupKey)
		return nil, fmt.Errorf("channel has closed")
	}

	if newConf.ChannelGroup.Values[channelconfig.OrdererAddressesKey] == nil {
		logger.Errorf("channel has closed, value %+v is empty", channelconfig.OrdererAddressesKey)
		return nil, fmt.Errorf("channel has closed")
	}
	err = proto.Unmarshal(payload.Data, configEnv)
	if err != nil {
		logger.Error("Error unmarshaling ConfigEnvelope", err)
		return nil, err
	}

	// 删除orderer不会影响到组织信息，不会将整个组织移出，因此无需更新ordererOrgs、applicationOrgs、consortiumOrgs
	//for key := range newConf.ChannelGroup.Groups[channelconfig.OrdererGroupKey].Groups {
	//	logger.Notice("ordererOrgs: ", key)
	//}
	//
	//if delApplicationOrgs {
	//	for key := range newConf.ChannelGroup.Groups[channelconfig.ApplicationGroupKey].Groups {
	//		logger.Notice("applicationOrgs: ", key)
	//	}
	//}
	//
	//if delConsortiumOrgs {
	//	for key := range newConf.ChannelGroup.Groups[channelconfig.ConsortiumsGroupKey].Groups[localconfig.SampleConsortiumName].Groups {
	//		logger.Notice("consortiumOrgs: ", key)
	//	}
	//}

	// 删除orderer节点的地址 -----BEGIN
	{
		val := newConf.ChannelGroup.Values[channelconfig.OrdererAddressesKey].Value
		oa := &cb.OrdererAddresses{}
		if err = proto.Unmarshal(val, oa); err != nil {
			logger.Error("Error unmarshaling OrdererAddresses", err)
			return nil, err
		}
		var newAddrs []string
		for _, addr := range oa.Addresses {
			// 						跨  网								非  跨  网
			if strings.Contains(addr, ordererName) || strings.Contains(addr, endpoint) {
				//logger.Notice("addr == endpoint: ", addr)
				continue
			}
			newAddrs = append(newAddrs, addr)
		}
		oa.Addresses = newAddrs

		newConf.ChannelGroup.Values[channelconfig.OrdererAddressesKey].Value, err = proto.Marshal(oa)
		if err != nil {
			logger.Error("Error marshaling OrdererAddresses", err)
			return nil, err
		}
	}
	// 删除orderer节点的地址 -----END

	// 删除raft节点		----BEGIN
	if delRaftNodes {
		oc := new(orderer.ConsensusType)
		consensus := newConf.ChannelGroup.Groups[channelconfig.OrdererGroupKey].Values[channelconfig.ConsensusTypeKey].Value
		if err = proto.Unmarshal(consensus, oc); err != nil {
			logger.Error("Error unmarshaling orderer's ConsensusType", err)
			return nil, err
		}
		om := new(etcdraft.ConfigMetadata)
		if err = proto.Unmarshal(oc.Metadata, om); err != nil {
			logger.Error("Error unmarshaling etcdraft's ConfigMetadata", err)
			return nil, err
		}

		updateNodes := make([]*etcdraft.Consenter, 0)
		for _, node := range om.Consenters {
			key := fmt.Sprintf("%s-%d", node.Host, node.Port)
			logger.Notice("node: ", key)
			//					  跨--------------网												非--------------跨--------------网，非跨网的时候可能会出现同一个IP上多个节点，所以仅凭Host无法确认
			if strings.Contains(node.Host, ordererName) || strings.Contains(fmt.Sprintf("%s:%d", node.Host, node.Port), endpoint) {
				continue
			}
			updateNodes = append(updateNodes, node)
		}

		om.Consenters = updateNodes

		if oc.Metadata, err = proto.Marshal(om); err != nil {
			logger.Error("Error marshaling etcdraft's ConfigMetadata", err)
			return nil, err
		}

		if consensus, err = proto.Marshal(oc); err != nil {
			logger.Error("Error marshaling orderer's ConsensusType", err)
			return nil, err
		}
		newConf.ChannelGroup.Groups[channelconfig.OrdererGroupKey].Values[channelconfig.ConsensusTypeKey].Value = consensus
	}
	// 删除raft节点		----END

	updateTx, err := update.Compute(oldConf, newConf)
	if err != nil {
		return nil, err
	}
	updateTx.ChannelId = chainID
	return updateTx, nil
}

func updateChannel(add bool, chainID string, block *cb.Block, updateOrdererOrgs []*Organization, updateApplicationOrgs []*Organization,
	updateConsortiumOrgs map[string][]*Organization, updateOrdererAddrs []string, caster *Endpoint, signer msp.SigningIdentity, updateRaftNodes []etcdraft.Consenter) error {
	updateTx, err := configUpdate(add, chainID, block, updateOrdererOrgs, updateApplicationOrgs, updateConsortiumOrgs, updateOrdererAddrs, updateRaftNodes)
	if err != nil {
		if isNoDiffError(err) {
			logger.Warning("No differences detected between original and updated config")
			return nil
		}
		logger.Error("Error computing config update", err)
		return err
	}

	return signUpdateConfigBlock(chainID, signer, caster, updateTx)
}

func delOrgDirectly(chainID string, orgName string, block *cb.Block, delOrdererOrgs, delApplicationOrgs, delConsortiumOrgs, delOrdererAddrs, delRaftNodes bool, signer msp.SigningIdentity, caster *Endpoint) error {
	updateTx, err := configDelOrgByName(chainID, orgName, block, delOrdererOrgs, delApplicationOrgs, delConsortiumOrgs, delOrdererAddrs, delRaftNodes)
	if err != nil {
		if isNoDiffError(err) {
			logger.Warning("No differences detected between original and updated config")
			return nil
		}
		logger.Error("Error computing config update", err)
		return err
	}

	return signUpdateConfigBlock(chainID, signer, caster, updateTx)
}

/*
 * FUNCTION:	生成删除指定名称的orderer节点后的配置块信息
 * 				被deleteOrdererDirectly方法调用
 * INPUT:		chainID	---	通道名
				ordererName	---	要删除的orderer名称
				endpoint	--- 要删除的orderer的地址IP，在非跨网情况下用到
				block	---	当前区块链网络上的配置块信息
				delApplicationOrgs	--- 是否是删除应用链（通道）上的信息，在修改应用链（通道）上的配置块信息时启用（publicchain也算应用链）
				delConsortiumOrgs	--- 是否是修改系统链（通道）上的信息，在修改系统链（通道）上的配置块信息时启用（byfn-sys-channel）
				delRaftNodes		---	是否删除raft节点
				signer				--- 签名信息
				注： 本方法参数相对configDelOrgByName方法的参数少了delOrdererOrgs（是否删除orderer）、delOrdererAddrs（是否删除orderer地址）这两项本方法默认为true
					还有一个delRaftNodes（是否删除raft节点）本方法将其抛出由外部调用方法决定，但是其实在添加组织或orderer的时候会默认将其添加到配置块的raftNode中。
 * OUTPUT:		*cb.ConfigUpdate	--- 删除了信息后的配置块信息，也就是后续签名广播更新的配置块
				error				--- 错误信息
 * AUTHOR:		刘成龙
 * CREATE:		2020/7/30
*/
func deleteOrdererDirectly(chainID, ordererName, endpoint string, block *cb.Block /*delApplicationOrgs, delConsortiumOrgs,*/, delRaftNodes bool, signer msp.SigningIdentity, caster *Endpoint) error {
	updateTx, err := configDeleteOrdererByName(chainID, ordererName, endpoint, block /*delApplicationOrgs, delConsortiumOrgs,*/, delRaftNodes)
	if err != nil {
		if isNoDiffError(err) {
			logger.Warning("No differences detected between original and updated config")
			return nil
		}
		logger.Error("Error computing config update", err)
		return err
	}

	return signUpdateConfigBlock(chainID, signer, caster, updateTx)
}

/*
 * FUNCTION:	对更新的配置块信息进行签名认证，然后广播给本次传入的orderer节点去更新自己的配置块信息
 * 				在updateChannel、delOrgDirectly、deleteOrdererDirectly方法中被调用
 * INPUT:		chainID	---	通道名，channelID更准确一些
				signer	--- 签名信息，用来对配置块信息进行更新
				caster	---	需要同步更新配置块的orderer节点
				updateTX	---	需要进行签名的更新后的配置块信息
 * OUTPUT:		error	---	错误信息
 * AUTHOR:		刘成龙
 * CREATE:		2020/7/31
*/
func signUpdateConfigBlock(chainID string, signer msp.SigningIdentity, caster *Endpoint, updateTx *cb.ConfigUpdate) error {

	creator, err := signer.Serialize()
	if err != nil {
		logger.Error("Error serializing signer", err)
		return err
	}

	configUpdate, signatureHeader, toSignBytes, err := CreateConfigUpdateEnvelopeBytes(creator, updateTx)
	if err != nil {
		logger.Error("Error creating configUpdateEnvelopeBytes", err)
		return err
	}
	signedSigHeader, err := signer.Sign(toSignBytes)
	if err != nil {
		logger.Error("Error signning sigHeader", err)
		return err
	}

	envelopeBytes, err := CreateChannelEnvelopeBytes(chainID, creator, configUpdate, []*cb.ConfigSignature{&cb.ConfigSignature{SignatureHeader: signatureHeader, Signature: signedSigHeader}})
	if err != nil {
		logger.Error("Error creating newChannelEnvelope payload", err)
		return err
	}

	signature, err := signer.Sign(envelopeBytes)
	if err != nil {
		logger.Error("Error signning payload", err)
		return err
	}

	return Broadcast(envelopeBytes, signature, caster)
}

func (client *Client) DelOrgDirectly(chainID string, orgName string, delOrdererOrgs, delApplicationOrgs, delConsortiumOrgs, delOrdererAddrs, delRaftNodes bool, casters []*Endpoint) error {
	for _, caster := range casters {
		logger.Info("Begin getting config block from chain ", chainID)
		block, err := client.GetConfigBlockByChannel(chainID, caster)
		if err != nil {
			logger.Error("Error getting config block from chain ", chainID, err)
			continue
		}
		logger.Info("Successfully getting config block from chain ", chainID)
		return delOrgDirectly(chainID, orgName, block, delOrdererOrgs, delApplicationOrgs, delConsortiumOrgs, delOrdererAddrs, delRaftNodes, client.signer, caster)
	}
	return errors.New("failed getChannelConfigUpdate after try all orderers")
}

/*
 * FUNCTION:	对区块链网络上的配置块进行更新，删除配置块中的指定名称的oderer的相关信息
 * 				被deleteOrdererDirectly方法调用
 * INPUT:		chainID	---	通道名
				ordererName	---	要删除的orderer名称
				endpoint	--- 要删除的orderer的地址IP，在非跨网情况下用到
				block	---	当前区块链网络上的配置块信息
				delApplicationOrgs	--- 是否是删除应用链（通道）上的信息，在修改应用链（通道）上的配置块信息时启用（publicchain也算应用链）
				delConsortiumOrgs	--- 是否是修改系统链（通道）上的信息，在修改系统链（通道）上的配置块信息时启用（byfn-sys-channel）
				delRaftNodes		---	是否删除raft节点
				signer				--- 签名信息
				注： 本方法参数相对configDelOrgByName方法的参数少了delOrdererOrgs（是否删除orderer）、delOrdererAddrs（是否删除orderer地址）这两项本方法默认为true
					还有一个delRaftNodes（是否删除raft节点）本方法将其抛出由外部调用方法决定，但是其实在添加组织或orderer的时候会默认将其添加到配置块的raftNode中。
 * OUTPUT:		error				--- 错误信息
 * AUTHOR:		刘成龙
 * CREATE:		2020/7/30
*/
func (client *Client) DeleteOrdererDirectly(chainID string, ordererName, endpoint string /*delApplicationOrgs, delConsortiumOrgs,*/, delRaftNodes bool, casters []*Endpoint) error {
	for _, caster := range casters {
		logger.Info("Begin getting config block from chain ", chainID)
		block, err := client.GetConfigBlockByChannel(chainID, caster)
		if err != nil {
			logger.Error("Error getting config block from chain ", chainID, err)
			continue
		}
		logger.Info("Successfully getting config block from chain ", chainID)
		return deleteOrdererDirectly(chainID, ordererName, endpoint, block /*delApplicationOrgs, delConsortiumOrgs,*/, delRaftNodes, client.signer, caster)
	}
	return errors.New("failed getChannelConfigUpdate after try all orderers")
}

// GetConfigBlockByChannel ...
func (client *Client) GetConfigBlockByChannel(chainID string, deliver *Endpoint) (*cb.Block, error) {
	return getConfigBlockByChannel(chainID, deliver, client.signer)
}

// GetRaftNodeInfo get raft node info from syschannel
func (client *Client) GetRaftNodeInfo(casters []*Endpoint) ([]etcdraft.Consenter, error) {
	for _, caster := range casters {
		logger.Info("Begin getting config block from chain ", DefaultSystemChainID)
		block, err := client.GetConfigBlockByChannel(DefaultSystemChainID, caster)
		if err != nil {
			logger.Error("Error getting config block from chain ", DefaultSystemChainID, err)
			continue
		}
		logger.Info("Successfully getting config block from chain ", DefaultSystemChainID)
		return getRaftConsenterFromConfig(block)
	}
	return nil, errors.New("failed GetRaftNodeInfo after try all orderers")
}

func (client *Client) GetNewestBlockByChannel(fromOrderer bool, chainID string, deliver *Endpoint) (*cb.Block, error) {
	seekI := seekInfo(seekNewest, seekNewest)
	var block *cb.Block
	var err error
	if fromOrderer {
		block, err = seekBlockByChannel(chainID, seekI, deliver, client.signer)
		if err != nil {
			logger.Error("Error getting block by channel", err)
			return nil, err
		}
	} else {
		block, err = seekBlockByChannelFromPeer(chainID, seekI, deliver, client.signer)
		if err != nil {
			logger.Error("Error getting block by channel", err)
			return nil, err
		}
	}

	return block, err
}

func (client *Client) GetChannelHeight(fromOrderer bool, chainID string, deliver *Endpoint) (int, error) {
	block, err := client.GetNewestBlockByChannel(fromOrderer, chainID, deliver)
	if err != nil {
		return 0, err
	}
	return int(block.GetHeader().Number) + 1, nil
}

func getConfigBlockByChannel(chainID string, deliver *Endpoint, signer msp.SigningIdentity) (*cb.Block, error) {
	seekI := seekInfo(seekNewest, seekNewest)
	block, err := seekBlockByChannel(chainID, seekI, deliver, signer)
	if err != nil {
		logger.Error("Error getting block by channel", err)
		return nil, err
	}
	lc, err := utils.GetLastConfigIndexFromBlock(block)
	if err != nil {
		logger.Error("Error getting last config index from block", err)
		return nil, err
	}
	return getBlockByChannel(chainID, lc, deliver, signer)
}

// GetBlockByChannel ...
func (client *Client) GetBlockByChannel(chainID string, index uint64, deliver *Endpoint) (*cb.Block, error) {
	return getBlockByChannel(chainID, index, deliver, client.signer)
}

func createBlockRequest(chainID string, seekI *ab.SeekInfo, signer msp.SigningIdentity) (*cb.Envelope, error) {
	creator, err := signer.Serialize()
	if err != nil {
		logger.Error("Error serializing", err)
		return nil, err
	}
	paylBytes, err := CreateDeliverEnvelopeBytes(chainID, seekI, creator)
	if err != nil {
		logger.Error("Error creating deliverEnvelope", err)
		return nil, err
	}
	sig, err := signer.Sign(paylBytes)
	if err != nil {
		logger.Error("Error signning", err)
		return nil, err
	}
	env := &cb.Envelope{Payload: paylBytes, Signature: sig}
	return env, nil
}

func seekBlockByChannel(chainID string, seekI *ab.SeekInfo, deliver *Endpoint, signer msp.SigningIdentity) (*cb.Block, error) {
	env, err := createBlockRequest(chainID, seekI, signer)
	if err != nil {
		logger.Error("Error creating block request envelope", err)
		return nil, err
	}
	return NewDeliverClient(deliver).RequestBlock(env)
}

func seekBlockByChannelFromPeer(chainID string, seekI *ab.SeekInfo, deliver *Endpoint, signer msp.SigningIdentity) (*cb.Block, error) {
	env, err := createBlockRequest(chainID, seekI, signer)
	if err != nil {
		logger.Error("Error creating block request envelope", err)
		return nil, err
	}
	// if
	return NewPeerClient(deliver).RequestBlock(env)
}

func getBlocksByChannel(chainID string, seekI *ab.SeekInfo, deliver *Endpoint, signer msp.SigningIdentity) (*BlockIterator, error) {
	env, err := createBlockRequest(chainID, seekI, signer)
	if err != nil {
		logger.Error("Error creating block request envelope", err)
		return nil, err
	}
	return NewDeliverClient(deliver).RequestBlocks(env)
}

// GetBlockByChannel ...
func getBlockByChannel(chainID string, index uint64, deliver *Endpoint, signer msp.SigningIdentity) (*cb.Block, error) {
	seekS := seekSpecified(index)
	seekI := seekInfo(seekS, seekS)
	return seekBlockByChannel(chainID, seekI, deliver, signer)
}

// GetNewBlocksByChannel ...
func (client *Client) GetNewBlocksByChannel(chainID string, deliver *Endpoint) (*BlockIterator, error) {
	return getNewBlocksByChannel(chainID, deliver, client.signer)
}

func getNewBlocksByChannel(chainID string, deliver *Endpoint, signer msp.SigningIdentity) (*BlockIterator, error) {
	seekI := seekInfo(seekNewest, seekMax)
	return getBlocksByChannel(chainID, seekI, deliver, signer)
}

func getNewCommittedFilteredBlocksByChannel(chainID string, committer *Endpoint, signer msp.SigningIdentity) (*BlockIterator, error) {
	seekI := seekInfo(seekNewest, seekMax)
	return getCommittedFilteredBlocksByChannel(chainID, seekI, committer, signer)

}

// GetNewCommittedFilteredBlocksByChannel ...
func (client *Client) GetNewCommittedFilteredBlocksByChannel(chainID string, committer *Endpoint) (*BlockIterator, error) {
	return getNewCommittedFilteredBlocksByChannel(chainID, committer, client.signer)
}

func getCommittedFilteredBlocksByChannel(chainID string, seekI *ab.SeekInfo, committer *Endpoint, signer msp.SigningIdentity) (*BlockIterator, error) {
	env, err := createBlockRequest(chainID, seekI, signer)
	if err != nil {
		logger.Error("Error creating block request envelope", err)
		return nil, err
	}

	return NewPeerDeliverClient(committer).RequestFilteredBlocks(env)
}

// JoinChannel ...
func (client *Client) JoinChannel(chainID string, gb *cb.Block, endorsers []*Endpoint) error {
	return joinChannel(chainID, gb, endorsers, client.signer)
}

func joinChannel(chainID string, block *cb.Block, endorsers []*Endpoint, signer msp.SigningIdentity) error {
	spec := &pb.ChaincodeSpec{
		Type:        pb.ChaincodeSpec_GOLANG,
		ChaincodeId: &pb.ChaincodeID{Name: "cscc"},
		Input:       &pb.ChaincodeInput{Args: [][]byte{[]byte(cscc.JoinChain), utils.MarshalOrPanic(block)}},
	}

	invocation := &pb.ChaincodeInvocationSpec{ChaincodeSpec: spec}
	creator, err := signer.Serialize()
	if err != nil {
		logger.Error("Error serializing identity", err)
		return err
	}

	prop, _, err := utils.CreateProposalFromCIS(cb.HeaderType_CONFIG, "", invocation, creator)
	if err != nil {
		logger.Error("Error creating proposal for join", err)
		return err
	}
	signedProp, err := utils.GetSignedProposal(prop, signer)
	if err != nil {
		logger.Error("Error creating signed proposal", err)
		return err
	}

	for _, endorser := range endorsers {
		ec, err := newEndorserClient(endorser)
		if err != nil {
			logger.Errorf("Error creating endorserClient %s, err: %s", endorser.Address, err)
			return err
		}
		defer ec.Close()
		proposalResp, err := ec.ProcessProposal(context.Background(), signedProp)
		if err != nil {
			logger.Errorf("Error processing proposal for %s: %s", endorser.Address, err)
			return err
		}

		if proposalResp == nil {
			logger.Errorf("Get nil proposal response from %s", endorser.Address)
			return errors.New("nil proposal response")
		}

		if proposalResp.Response.Status != 0 && proposalResp.Response.Status != 200 {
			logger.Errorf("bad proposal response %d: %s", proposalResp.Response.Status, proposalResp.Response.Message)
			return errors.New("bad proposal response")
		}
		logger.Infof("Successfully submitted proposal to join channel for %s", endorser.Address)
	}

	return nil
}

// CreateChannel ...
func (client *Client) CreateChannel(conf *ChannelConfig, caster *Endpoint) error {
	creator, err := client.signer.Serialize()
	fmt.Println("creator: ", string(creator))
	if err != nil {
		logger.Error("Error serializing identity", err)
		return err
	}
	config := newChannelProfile(conf)
	template, err := encoder.DefaultConfigTemplate(config)
	if err != nil {
		logger.Error("Error creating configTemplate", err)
		return err
	}
	newChannelConfigUpdate, err := encoder.NewChannelCreateConfigUpdate(conf.ChainID, config, template)
	data, _ := json.Marshal(newChannelConfigUpdate)

	fmt.Printf("newChannelConfigUpdate: %s\n", string(data))
	if err != nil {
		logger.Error("Error creating configUpdate", err)
		return err
	}

	configUpdate, sigHeader, toSign, err := CreateConfigUpdateEnvelopeBytes(creator, newChannelConfigUpdate)
	if err != nil {
		logger.Error("Error creating configUpdateEnvelopeBytes", err)
		return err
	}

	signedSigHeader, err := client.signer.Sign(toSign)
	if err != nil {
		logger.Error("Error signning sigHeader", err)
		return err
	}

	payload, err := CreateChannelEnvelopeBytes(conf.ChainID, creator, configUpdate, []*cb.ConfigSignature{&cb.ConfigSignature{SignatureHeader: sigHeader, Signature: signedSigHeader}})
	if err != nil {
		logger.Error("Error creating newChannelEnvelope payload", err)
		return err
	}

	signature, err := client.signer.Sign(payload)
	if err != nil {
		logger.Error("Error signning payload", err)
		return err
	}

	return Broadcast(payload, signature, caster)
}

// CreateChannelTx ...
func CreateChannelTx(config *ChannelConfig) (*cb.Envelope, error) {
	conf := newChannelProfile(config)
	return encoder.MakeChannelCreationTransaction(config.ChainID, nil, conf)
}

// WriteChannelTx ...
func WriteChannelTx(output string, env *cb.Envelope) error {
	logger.Info("Writing new channel tx")
	return ioutil.WriteFile(output, utils.MarshalOrPanic(env), 0644)
}

// CreateGenesisBlock ...
// No need to sign it
func CreateGenesisBlock(config *GenesisConfig) *cb.Block {
	conf := newGenesisProfile(config)
	pgen := encoder.New(conf)
	logger.Info("Generating genesis block")
	if conf.Consortiums == nil {
		logger.Warning("Genesis block does not contain a consortiums group definition.  This block cannot be used for orderer bootstrap.")
	}
	return pgen.GenesisBlockForChannel(config.ChainID)
}

// WriteGenesisBlock ...
func WriteGenesisBlock(output string, block *cb.Block) error {
	logger.Info("Writing genesis block")
	return ioutil.WriteFile(output, utils.MarshalOrPanic(block), 0644)

}

// format: 'grpcs://xxxx:xx'
func parseURL(rawURL string) *localconfig.AnchorPeer {
	anchor := &localconfig.AnchorPeer{}
	addr, err := url.Parse(rawURL)
	if err != nil {
		logger.Panic(err)
	}
	anchor.Host = addr.Hostname()
	anchor.Port, _ = strconv.Atoi(addr.Port())
	return anchor
}

func newChannelProfile(conf *ChannelConfig) *localconfig.Profile {
	profile := &localconfig.Profile{}

	profile.Consortium = conf.Consortium

	profile.Application = &localconfig.Application{}

	// add policy
	profile.Application.Policies = make(map[string]*localconfig.Policy)

	defaultAdmins := PolicyAnyAdmins
	if conf.AdminsPolicy != "" {
		defaultAdmins = conf.AdminsPolicy
	}
	profile.Application.Policies["Admins"] = &localconfig.Policy{
		Type: defaultPolicyType,
		Rule: string(defaultAdmins),
	}

	defaultWriters := PolicyAnyWriters
	if conf.WritersPolicy != "" {
		defaultWriters = conf.WritersPolicy
	}
	profile.Application.Policies["Writers"] = &localconfig.Policy{
		Type: defaultPolicyType,
		Rule: string(defaultWriters),
	}

	defaultReaders := PolicyAnyReaders
	if conf.ReadersPolicy != "" {
		defaultReaders = conf.ReadersPolicy
	}
	profile.Application.Policies["Readers"] = &localconfig.Policy{
		Type: defaultPolicyType,
		Rule: string(defaultReaders),
	}

	orgs := []*localconfig.Organization{}
	for _, org := range conf.Organizations {

		peers := []*localconfig.AnchorPeer{}
		for _, ap := range org.AnchorPeers {
			peers = append(peers, parseURL(ap))
		}
		orgs = append(orgs, &localconfig.Organization{
			Name:        org.Name,
			ID:          org.ID,
			MSPDir:      org.MSPDir,
			MSPType:     defaultMSPType,
			AnchorPeers: peers,
		})
	}
	profile.Application.Organizations = orgs
	profile.Application.Capabilities = make(map[string]bool)
	profile.Application.Capabilities[defaultChannelCapability] = true
	profile.Application.Capabilities[defaultOrdererCapability] = true
	profile.Application.Capabilities[defaultApplicationCapability] = true

	return profile
}

func newGenesisProfile(conf *GenesisConfig) *localconfig.Profile {
	profile := &localconfig.Profile{}
	orderer := &localconfig.Orderer{}
	profile.Application = &localconfig.Application{}
	orderer.Addresses = conf.Addresses
	orderer.OrdererType = conf.OrdererType

	orderer.BatchTimeout = conf.BatchTimeout
	if conf.BatchTimeout == time.Duration(0) {
		orderer.BatchTimeout = defaultBatchTimeout
	}

	orderer.BatchSize = localconfig.BatchSize{
		MaxMessageCount:   conf.MaxMessageCount,
		AbsoluteMaxBytes:  conf.AbsoluteMaxBytes,
		PreferredMaxBytes: conf.PreferredMaxBytes,
	}
	if conf.MaxMessageCount == 0 {
		orderer.BatchSize.MaxMessageCount = defaultMaxMessageCount
	}
	if conf.AbsoluteMaxBytes == 0 {
		orderer.BatchSize.AbsoluteMaxBytes = defaultAbsoluteMaxBytes
	}
	if conf.PreferredMaxBytes == 0 {
		orderer.BatchSize.PreferredMaxBytes = defaultPreferredMaxBytes
	}

	orderer.Kafka.Brokers = conf.KafkaBrokers

	orderer.EtcdRaft = conf.EtcdRaft

	orderer.MaxChannels = conf.MaxChannels

	orgs := []*localconfig.Organization{}
	for _, org := range conf.OrdererOrganizations {
		orgs = append(orgs, &localconfig.Organization{
			Name:    org.Name,
			ID:      org.ID,
			MSPDir:  org.MSPDir,
			MSPType: defaultMSPType,
		})
	}
	orderer.Organizations = orgs
	profile.Application.Organizations = orgs
	profile.Application.Capabilities = make(map[string]bool)
	profile.Application.Capabilities[defaultChannelCapability] = true
	profile.Application.Capabilities[defaultOrdererCapability] = true
	profile.Application.Capabilities[defaultApplicationCapability] = true

	policy := make(map[string]*localconfig.Policy)
	policy["Readers"] = &localconfig.Policy{Type: "ImplicitMeta", Rule: "ANY Readers"}
	policy["Writers"] = &localconfig.Policy{Type: "ImplicitMeta", Rule: "ANY Writers"}
	policy["Admins"] = &localconfig.Policy{Type: "ImplicitMeta", Rule: "ANY Admins"}
	policy["BlockValidation"] = &localconfig.Policy{Type: "ImplicitMeta", Rule: "ANY Writers"}

	orderer.Capabilities = make(map[string]bool)
	orderer.Capabilities[defaultOrdererCapability] = true
	orderer.Policies = policy

	profile.Orderer = orderer
	profile.Policies = policy

	profile.Consortiums = make(map[string]*localconfig.Consortium)

	consortiumOrgs := []*localconfig.Organization{}
	for _, org := range conf.ConsortiumOrganizations {
		consortiumOrgs = append(consortiumOrgs, &localconfig.Organization{
			Name:    org.Name,
			ID:      org.ID,
			MSPDir:  org.MSPDir,
			MSPType: defaultMSPType,
		})
	}

	consortium := &localconfig.Consortium{
		Organizations: consortiumOrgs,
	}

	if conf.ConsortiumName == "" {
		profile.Consortiums[DefaultConsortium] = consortium
	} else {
		profile.Consortiums[conf.ConsortiumName] = consortium
	}

	profile.Capabilities = make(map[string]bool)
	profile.Capabilities[defaultChannelCapability] = true

	return profile

}

func isNoDiffError(err error) bool {
	if err == nil {
		return false
	}
	return err.Error() == "no differences detected between original and updated config"
}

// get etcdraft node info from config， Generally syschannel's config block
func getRaftConsenterFromConfig(block *cb.Block) (raftNodes []etcdraft.Consenter, err error) {

	env := utils.ExtractEnvelopeOrPanic(block, 0)
	payload, err := utils.GetPayload(env)
	if err != nil {
		logger.Error("Error getting payload from block", err)
		return nil, err
	}
	configEnv := &cb.ConfigEnvelope{}
	err = proto.Unmarshal(payload.Data, configEnv)
	if err != nil {
		logger.Error("Error unmarshaling ConfigEnvelope", err)
		return nil, err
	}

	oldConf := configEnv.Config
	newConf := proto.Clone(oldConf).(*cb.Config)

	oc := new(orderer.ConsensusType)
	consensus := newConf.ChannelGroup.Groups[channelconfig.OrdererGroupKey].Values[channelconfig.ConsensusTypeKey].Value
	if err = proto.Unmarshal(consensus, oc); err != nil {
		logger.Error("Error unmarshaling orderer's ConsensusType", err)
		return nil, err
	}

	if oc.Type != "etcdraft" {
		return nil, nil
	}

	om := new(etcdraft.ConfigMetadata)
	if err = proto.Unmarshal(oc.Metadata, om); err != nil {
		logger.Error("Error unmarshaling etcdraft's ConfigMetadata", err)
		return nil, err
	}

	var resData []etcdraft.Consenter
	for _, v := range om.Consenters {
		resData = append(resData, *v)
	}

	return resData, nil
}

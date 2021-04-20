#!/bin/bash
export CHANNEL_NAME=mychannel
export FABRIC_CFG_PATH=$PWD
export OS_ARCH=$(echo "$(uname -s|tr '[:upper:]' '[:lower:]'|sed 's/mingw64_nt.*/windows/')-$(uname -m | sed 's/x86_64/amd64/g')" | awk '{print tolower($0)}')
export FABRIC_ROOT=$PWD/../..
export PATH=$FABRIC_ROOT/release/$OS_ARCH/bin:${PWD}:$PATH
export BCCSP=GM
export CONSENSUS_TYPE=etcdraft
CRYPTOGEN=$FABRIC_ROOT/release/$OS_ARCH/bin/cryptogen

if [ -f "$CRYPTOGEN" ]; then
     echo "Using cryptogen -> $CRYPTOGEN"
else
     make -C $FABRIC_ROOT release
fi
cryptogen generate --config=./crypto-config.yaml

if [ "${CONSENSUS_TYPE}" == "kafka" ]; then
    configtxgen -profile SampleDevModeKafka  -outputBlock ./channel-artifacts/genesis.block -bccsp $BCCSP
elif [ "${CONSENSUS_TYPE}" == "etcdraft" ]; then
    configtxgen -profile SampleMultiNodeEtcdRaft  -outputBlock ./channel-artifacts/genesis.block -bccsp $BCCSP
fi

configtxgen -profile TwoOrgsChannel -outputCreateChannelTx ./channel-artifacts/channel.tx -channelID $CHANNEL_NAME

configtxgen -profile TwoOrgsChannel -outputAnchorPeersUpdate ./channel-artifacts/Org1MSPanchors.tx -channelID $CHANNEL_NAME -asOrg Org1MSP

sleep 5
if [ "${CONSENSUS_TYPE}" == "kafka" ]; then
    docker-compose -f docker-compose-org1.yaml -f  docker-compose-kafka.yaml up -d
elif [ "${CONSENSUS_TYPE}" == "etcdraft" ]; then
    docker-compose -f docker-compose-org1.yaml up -d
fi
sleep 20
docker exec -it cli sh -c "./scripts/script.sh"

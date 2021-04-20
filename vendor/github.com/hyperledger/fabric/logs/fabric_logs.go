package logs

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"

	yxlogs "github.com/hyperledger/fabric/logs/yxlogs"
	"github.com/spf13/viper"
)

// Log levels to control the logging output.
const (
	LevelEmergency = iota
	LevelAlert
	LevelCritical
	LevelError
	LevelWarning
	LevelNotice
	LevelInformational
	LevelDebug
)

const defaultFormat = "%s"

type FabricLogger struct {
	logger *yxlogs.BeeLogger
}

type yxLogInfo struct {
	isOpenYxlog     bool
	filepath        string
	filename        string
	maxlinesPerFile int
	maxsizePerFile  int
	maxTotalSize    int64
	isAutoDelete    bool
	daily           bool
	rotate          bool
	maxdays         int
}

const (
	Orderer_Prefix = "ORDERER"
	Peer_Prefix    = "CORE"
	FilenameLenMax = 128
	FilepathLenMax = 128

	//===============DefaultArg====================
	DefaultCCFileName      = "cc_log"
	DefaultFilePath        = "/var/fabric_logs"
	DefaultFileName        = "yx_log"
	DefaultMaxlinesPerFile = 10000000
	DefaultMaxsizePerFile  = 102400000
	DefaultMaxTotalSize    = 4096000000
	DefaultLogLevel        = LevelInformational
	DefaultMaxDays         = 15
)

var once sync.Once
var fl *FabricLogger
var loglevel int = LevelDebug
var levelNames = [...]string{"emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"}
var logsBeforeInit = make([][]string, 8)

func SetFabricLogger(containerType string) *FabricLogger {
	once.Do(func() {
		var fabricCfgPath = os.Getenv("FABRIC_CFG_PATH")
		var configName string
		var loginfo yxLogInfo

		if containerType == "orderer" || containerType == "peer" {
			loginfo = SetNodeLogger(containerType, configName, fabricCfgPath, loginfo)
		} else if containerType == "chaincode" {
			var err error
			loglevel, err = strconv.Atoi(os.Getenv("CHAINCODE_LOG_LEVEL"))
			if err != nil {
				panic(fmt.Sprintf("Error convert CHAINCODE_LOG_LEVEL to int, err: %s", err))
			}
			loginfo.isOpenYxlog, err = strconv.ParseBool(os.Getenv("CHAINCODE_LOG_ISOPENYXLOG"))
			if err != nil {
				panic(fmt.Sprintf("Error convert CHAINCODE_LOG_ISOPENYXLOG to bool, err: %s", err))
			}

			loginfo.filepath = os.Getenv("CHAINCODE_LOG_DESTINATION")
			loginfo.filename = DefaultCCFileName

			loginfo.maxlinesPerFile, err = strconv.Atoi(os.Getenv("CHAINCODE_LOG_MAXLINES"))
			if err != nil {
				panic(fmt.Sprintf("Error convert CHAINCODE_LOG_MAXLINES to int, err: %s", err))
			}
			loginfo.maxsizePerFile, err = strconv.Atoi(os.Getenv("CHAINCODE_LOG_MAXSIZE"))
			if err != nil {
				panic(fmt.Sprintf("Error convert CHAINCODE_LOG_MAXSIZE to int, err: %s", err))
			}
			loginfo.maxTotalSize, err = strconv.ParseInt(os.Getenv("CHAINCODE_LOG_MAXTOTALSIZE"), 10, 64)
			if err != nil {
				panic(fmt.Sprintf("Error convert CHAINCODE_LOG_MAXTOTALSIZE to int64, err: %s", err))
			}
			loginfo.isAutoDelete, err = strconv.ParseBool(os.Getenv("CHAINCODE_LOG_ISAUTODELETE"))
			if err != nil {
				panic(fmt.Sprintf("Error convert CHAINCODE_LOG_ISAUTODELETE to bool, err: %s", err))
			}
			loginfo.daily, err = strconv.ParseBool(os.Getenv("CHAINCODE_LOG_DAILY"))
			if err != nil {
				panic(fmt.Sprintf("Error convert CHAINCODE_LOG_DAILY to bool, err: %s", err))
			}
			// loginfo.rotate, err = strconv.ParseBool(os.Getenv("CHAINCODE_LOG_ROTATE"))
			// if err != nil {
			// 	panic(fmt.Sprintf("Error convert CHAINCODE_LOG_DAILY to bool, err: %s", err))
			// }
			loginfo.maxdays, err = strconv.Atoi(os.Getenv("CHAINCODE_LOG_MAXDAYS"))
			if err != nil {
				panic(fmt.Sprintf("Error convert CHAINCODE_LOG_DAILY to int, err: %s", err))
			}
		} else {
			panic(fmt.Sprintln("containerType should not be orderer or peer or chaincode"))
		}

		loginfo.rotate = loginfo.isOpenYxlog

		if loginfo.filepath == "" || len(loginfo.filepath) > FilenameLenMax {

			fl.logBeforeInit(LevelError, fmt.Sprintf("log config args err, filepath:%s, filepath_len:%d, use default arg: %s.\n", loginfo.filepath, len(loginfo.filepath), DefaultFilePath))
			loginfo.filepath = DefaultFilePath
		}

		if loginfo.filename == "" || len(loginfo.filename) > FilepathLenMax {
			fl.logBeforeInit(LevelError, fmt.Sprintf("log config args err,filename:%s,filename_len:%d,use default arg: %s.\n", loginfo.filename, len(loginfo.filename), DefaultFileName))
			loginfo.filename = DefaultFileName
		}

		if loginfo.maxlinesPerFile <= 0 || loginfo.maxlinesPerFile > math.MaxInt32 {
			fl.logBeforeInit(LevelError, fmt.Sprintf("log config args err,maxlinesPerFile:%d,use default arg: %d.\n", loginfo.maxlinesPerFile, DefaultMaxlinesPerFile))
			loginfo.maxlinesPerFile = DefaultMaxlinesPerFile
		}

		if loginfo.maxsizePerFile <= 0 || loginfo.maxsizePerFile > math.MaxInt32 {
			fl.logBeforeInit(LevelError, fmt.Sprintf("log config args err,maxsizePerFile:%d,use default arg: %d.\n", loginfo.maxsizePerFile, DefaultMaxsizePerFile))
			loginfo.maxsizePerFile = DefaultMaxsizePerFile
		}

		if loginfo.maxTotalSize <= 0 || loginfo.maxTotalSize > math.MaxInt64 {
			fl.logBeforeInit(LevelError, fmt.Sprintf("log config args err,maxTotalSize:%d,use default arg: %d.\n", loginfo.maxTotalSize, DefaultMaxTotalSize))
			loginfo.maxTotalSize = DefaultMaxTotalSize
		}

		if loginfo.maxdays <= 0 || loginfo.maxdays > math.MaxInt32 {
			fl.logBeforeInit(LevelError, fmt.Sprintf("log config args err,maxdays:%d,use default arg: %d.\n", loginfo.maxdays, DefaultMaxDays))
			loginfo.maxdays = DefaultMaxDays
		}

		if loglevel < 0 || loglevel > 7 {
			fl.logBeforeInit(LevelError, fmt.Sprintf("log config args err,loglevel:%d,use default arg: %d.\n", loglevel, DefaultLogLevel))
			loglevel = DefaultLogLevel
		}
		fl = GetLogger(loginfo)

		for level, logs := range logsBeforeInit {
			logFunc := []func(...interface{}){fl.Emergency, fl.Alert, fl.Critical, fl.Error, fl.Warning, fl.Notice, fl.Info, fl.Debug}

			for _, log := range logs {
				logFunc[level](log)
			}
		}
		logsBeforeInit = nil
	})
	return fl
}

func GetFabricLogger() *FabricLogger {
	return fl
}

func GetLogger(loginfo yxLogInfo) *FabricLogger {
	var separateFile []string

	if loginfo.isOpenYxlog == false {
		fmt.Println("use default log.")
		return nil
	}

	os.MkdirAll(loginfo.filepath, 0755)

	l := yxlogs.NewLogger(10000)
	l.EnableFuncCallDepth(true)

	for i := LevelEmergency; i <= loglevel; i++ {
		separateFile = append(separateFile, levelNames[i])
	}
	separateFileJson, _ := json.Marshal(separateFile)
	separate := fmt.Sprintf(`"separate":%s`, separateFileJson)

	config := fmt.Sprintf(`"filename":"%s/%s", "maxlines":%d, "maxsize":%d, "maxtotalsize":%d, "daily": %t, "rotate": %t, "maxdays": %d, "isautodelete":%t, `, loginfo.filepath, loginfo.filename, loginfo.maxlinesPerFile, loginfo.maxsizePerFile, loginfo.maxTotalSize, loginfo.daily, loginfo.rotate, loginfo.maxdays, loginfo.isAutoDelete)
	config = "{" + config + separate + "}"

	l.SetLogger(yxlogs.AdapterMultiFile, config)
	// default to be 2, because we wrap log with a new method, so adjust the args to 4.
	l.SetLogFuncCallDepth(4)
	fabricLogger := &FabricLogger{
		logger: l,
	}
	return fabricLogger
}

func concat(args ...interface{}) string {
	resultString := fmt.Sprintln(args...)
	// Sprintln will add space between args, and always add an extra '\n' character at the end
	resultString = resultString[0 : len(resultString)-1]
	return resultString
}

func (l *FabricLogger) logBeforeInit(level int, log string) {
	logsBeforeInit[level] = append(logsBeforeInit[level], log)
}

func (l *FabricLogger) Debug(v ...interface{}) {
	if loglevel < LevelDebug {
		return
	}
	l.logger.Debug(defaultFormat, concat(v...))
}

func (l *FabricLogger) Debugf(formatString string, v ...interface{}) {
	if loglevel < LevelDebug {
		return
	}
	l.logger.Debug(formatString, v...)
}

func (l *FabricLogger) Info(v ...interface{}) {
	if loglevel < LevelInformational {
		return
	}
	l.logger.Info(defaultFormat, concat(v...))
}

func (l *FabricLogger) Infof(formatString string, v ...interface{}) {
	if loglevel < LevelInformational {
		return
	}
	l.logger.Info(formatString, v...)
}

func (l *FabricLogger) Notice(v ...interface{}) {
	if loglevel < LevelNotice {
		return
	}
	l.logger.Notice(defaultFormat, concat(v...))
}

func (l *FabricLogger) Noticef(formatString string, v ...interface{}) {
	if loglevel < LevelNotice {
		return
	}
	l.logger.Notice(formatString, v...)
}

func (l *FabricLogger) Warning(v ...interface{}) {
	if loglevel < LevelWarning {
		return
	}
	l.logger.Warning(defaultFormat, concat(v...))
}

func (l *FabricLogger) Warningf(formatString string, v ...interface{}) {
	if loglevel < LevelWarning {
		return
	}
	l.logger.Warning(formatString, v...)
}

func (l *FabricLogger) Error(v ...interface{}) {
	if loglevel < LevelError {
		return
	}
	l.logger.Error(defaultFormat, concat(v...))
}

func (l *FabricLogger) Errorf(formatString string, v ...interface{}) {
	if loglevel < LevelError {
		return
	}
	l.logger.Error(formatString, v...)
}

func (l *FabricLogger) Critical(v ...interface{}) {
	if loglevel < LevelCritical {
		return
	}
	l.logger.Critical(defaultFormat, concat(v...))
}

func (l *FabricLogger) Criticalf(formatString string, v ...interface{}) {
	if loglevel < LevelCritical {
		return
	}
	l.logger.Critical(formatString, v...)
}

func (l *FabricLogger) Alert(v ...interface{}) {
	if loglevel < LevelAlert {
		return
	}
	l.logger.Alert(defaultFormat, concat(v...))
}

func (l *FabricLogger) Alertf(formatString string, v ...interface{}) {
	if loglevel < LevelAlert {
		return
	}
	l.logger.Alert(formatString, v...)
}

func (l *FabricLogger) Emergency(v ...interface{}) {
	if loglevel < LevelEmergency {
		return
	}
	l.logger.Emergency(defaultFormat, concat(v...))
}

func (l *FabricLogger) Emergencyf(formatString string, v ...interface{}) {
	if loglevel < LevelEmergency {
		return
	}
	l.logger.Emergency(formatString, v...)
}

//SetNodeLogger 设置 orderer 或 peer 节点的日志信息
func SetNodeLogger(nodeType, configName, fabricCfgPath string, loginfo yxLogInfo) yxLogInfo {
	config := viper.New()
	var logInfoPrefix string
	if nodeType == "orderer" {
		configName = strings.ToLower(Orderer_Prefix)
		config.SetEnvPrefix("ORDERER")
		logInfoPrefix = "general"
	} else {
		configName = strings.ToLower(Peer_Prefix)
		config.SetEnvPrefix("CORE")
		logInfoPrefix = "logging"
	}
	config.SetConfigName(configName)
	config.AddConfigPath(fabricCfgPath)
	config.ReadInConfig()
	config.AutomaticEnv()
	replacer := strings.NewReplacer(".", "_")
	config.SetEnvKeyReplacer(replacer)
	config.SetConfigType("yaml")

	loginfo.filepath = config.GetString(strings.Join([]string{logInfoPrefix, "logpath"}, "."))
	loginfo.filename = config.GetString(strings.Join([]string{logInfoPrefix, "logname"}, "."))

	loginfo.isOpenYxlog = ReadYXLogInfoConfig(loginfo.isOpenYxlog, config, strings.Join([]string{logInfoPrefix, "isOpenYxlog"}, ".")).(bool)
	loginfo.maxlinesPerFile = ReadYXLogInfoConfig(loginfo.maxlinesPerFile, config, strings.Join([]string{logInfoPrefix, "maxlinesPerFile"}, ".")).(int)
	loginfo.maxsizePerFile = ReadYXLogInfoConfig(loginfo.maxsizePerFile, config, strings.Join([]string{logInfoPrefix, "maxsizePerFile"}, ".")).(int)
	loginfo.maxTotalSize = ReadYXLogInfoConfig(loginfo.maxTotalSize, config, strings.Join([]string{logInfoPrefix, "maxTotalSize"}, "."), 10, 64).(int64)
	loginfo.maxdays = ReadYXLogInfoConfig(loginfo.maxdays, config, strings.Join([]string{logInfoPrefix, "maxdays"}, ".")).(int)
	loginfo.daily = ReadYXLogInfoConfig(loginfo.daily, config, strings.Join([]string{logInfoPrefix, "daily"}, ".")).(bool)
	//loginfo.rotate = ReadYXLogInfoConfig(loginfo.rotate, config, strings.Join([]string{logInfoPrefix, "rotate"},".")).(bool)
	loginfo.isAutoDelete = ReadYXLogInfoConfig(loginfo.isAutoDelete, config, strings.Join([]string{logInfoPrefix, "isautodelete"}, ".")).(bool)
	loglevel = ReadYXLogInfoConfig(loglevel, config, strings.Join([]string{logInfoPrefix, "yxLogLevel"}, ".")).(int)
	//fmt.Printf("%s loglevel:%d\n\n", nodeType, loglevel)
	return loginfo
}

//ReadYXLogInfoConfig 读取yx日志信息
func ReadYXLogInfoConfig(logInfo interface{}, config *viper.Viper, key string, v ...int) interface{} {
	value := config.GetString(key)
	var err error

	//判断采用哪种解析方式
	switch logInfo.(type) {
	case int:
		logInfo, err = strconv.Atoi(value)
	case bool:
		logInfo, err = strconv.ParseBool(value)
	case int64:
		logInfo, err = strconv.ParseInt(value, v[0], v[1])
	default:
		fmt.Printf("This configuration read mode is not currently supported!\n")
		return nil
	}
	if err != nil {
		fmt.Printf("An error occurred when reading the config【%s】, %s\n", key, err)
	}
	return logInfo
}

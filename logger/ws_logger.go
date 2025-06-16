package logger

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

var logger *logrus.Logger

// LogEntry is the standard structure for logs
type (
	WSGate_LogEntry struct {
		Serivce     string      `json:"service"`
		Agent       Agent       `json:"agent"`
		Source      string      `json:"source"`
		Destination string      `json:"destination"`
		Event       Event       `json:"event"`
		Level       string      `json:"level"`
		Type        string      `json:"type"`
		Action      Action      `json:"action"`
		Metrix      Metrix      `json:"metrix"`
		Message     string      `json:"message"`
		RawRequest  interface{} `json:"raw_request"`
		Timestamps  Timestamps  `json:"timestamps"`
	}

	Agent struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		RunningMode string `json:"running_mode"`
	}

	Event struct {
		ID   string `json:"id"`
		Info string `json:"info"`
	}

	Action struct {
		Type   string `json:"type"`
		Result string `json:"result"`
		Status string `json:"status"`
	}

	Metrix struct {
		WebAttackDetectionPredictScore float64 `json:"web_attack_detection_predict_score"`
		DGADetectionPredictScore       float64 `json:"dga_detection_predict_score"`
		CrossSiteScriptingDetection    bool    `json:"cross_site_scripting_detection"`
		SQLInjectionDetection          bool    `json:"sql_injection_detection"`
		HttpVerbTamperingDetection     bool    `json:"http_verb_tampering_detection"`
		HttpLargeRequestDetection      bool    `json:"http_large_request_detection"`
		UnknowAttackDetection          bool    `json:"unknow_attack_detection"`
	}

	Timestamps struct {
		RequestCreatedAt   int64  `json:"request_created_at"`
		RequestProcessedAt int64  `json:"request_processed_at"`
		LoggedAt           string `json:"logged_at"`
	}
)

func SetupWSLogger(serviceName string, logMaxSize int, logMaxBackups int, logMaxAge int, logCompress bool) {
	// Ensure directory exists
	logDir := "/var/log/whale-sentinel/ws-services/" + serviceName
	err := os.MkdirAll(logDir, 0755)
	if err != nil {
		log.Fatalf("Failed to create log directory: %v", err)
	}

	// Set up the log file path
	logFile := fmt.Sprintf("%s/app.log", logDir)

	logger = logrus.New()
	logger.SetOutput(&lumberjack.Logger{
		Filename:   logFile,
		MaxSize:    logMaxSize,
		MaxBackups: logMaxBackups,
		MaxAge:     logMaxAge,
		Compress:   logCompress,
	})
	logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339,
		PrettyPrint:     false,
	})
	logger.SetLevel(logrus.InfoLevel)
}

// SanitizeRawRequest masks sensitive fields from the raw request string
func SanitizeRawRequest(raw string) string {
	// Mask Authorization headers
	authRegex := regexp.MustCompile(`(?i)(Authorization:\s*)(\S+)`)
	raw = authRegex.ReplaceAllString(raw, `$1****MASKED****`)

	// Mask password fields in JSON or query parameters
	passwordRegex := regexp.MustCompile(`(?i)("password"\s*:\s*)"[^"]*"`)
	raw = passwordRegex.ReplaceAllString(raw, `$1"****MASKED****"`)

	passwordQueryRegex := regexp.MustCompile(`(?i)(password=)([^&\s]+)`)
	raw = passwordQueryRegex.ReplaceAllString(raw, `$1****MASKED****`)

	// Mask credential-like values
	credsRegex := regexp.MustCompile(`(?i)("?(username|email|credential|token)"?\s*:\s*)"[^"]*"`)
	raw = credsRegex.ReplaceAllString(raw, `$1"****MASKED****"`)

	// Mask credit card numbers (basic Luhn-compatible 13–19 digits)
	cardRegex := regexp.MustCompile(`(?i)\b(?:\d[ -]*?){13,19}\b`)
	raw = cardRegex.ReplaceAllString(raw, "****CARD****")

	// Trim excessive whitespace
	raw = strings.TrimSpace(raw)

	return raw
}

// Helper function to convert a timestamp string to Unix time
func toUnixTime(timestamp interface{}) int64 {
	// Check if the timestamp is a string
	timestampStr, ok := timestamp.(string)
	if !ok {
		return 0 // Return 0 if not a string
	}
	// Parse the timestamp string
	parsedTime, err := time.Parse(time.RFC3339, timestampStr)
	if err != nil {
		return 0 // Return 0 if parsing fails
	}
	return parsedTime.Unix()
}

func getFloat64OrDefault(data map[string]interface{}, key string, defaultValue float64) float64 {
	if val, ok := data[key]; ok {
		if f, ok := val.(float64); ok {
			return f
		}
	}
	return defaultValue
}

func getBoolOrDefault(data map[string]interface{}, key string, defaultValue bool) bool {
	if val, ok := data[key]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return defaultValue
}

// Log function to create and log entries based on the service name
func Log(level string, log_data map[string]interface{}) {

	var jsonData []byte
	var err error

	entry := WSGate_LogEntry{
		Serivce: log_data["service"].(string),
		Agent: Agent{
			ID:          log_data["agent_id"].(string),
			Name:        log_data["agent_name"].(string),
			RunningMode: log_data["agent_running_mode"].(string),
		},
		Source:      log_data["source"].(string),
		Destination: log_data["destination"].(string),
		Event: Event{
			ID:   log_data["event_id"].(string),
			Info: log_data["event_info"].(string),
		},
		Level: strings.ToUpper(level),
		Type:  log_data["type"].(string),
		Action: Action{
			Type:   log_data["action_type"].(string),
			Result: log_data["action_result"].(string),
			Status: log_data["action_status"].(string),
		},
		Metrix: Metrix{
			WebAttackDetectionPredictScore: getFloat64OrDefault(log_data, "web_attack_detection_predict_score", 0.0),
			DGADetectionPredictScore:       getFloat64OrDefault(log_data, "dga_detection_predict_score", 0.0),
			CrossSiteScriptingDetection:    getBoolOrDefault(log_data, "cross_site_scripting_detection", false),
			SQLInjectionDetection:          getBoolOrDefault(log_data, "sql_injection_detection", false),
			HttpVerbTamperingDetection:     getBoolOrDefault(log_data, "http_verb_tampering_detection", false),
			HttpLargeRequestDetection:      getBoolOrDefault(log_data, "http_large_request_detection", false),
			UnknowAttackDetection:          getBoolOrDefault(log_data, "unknow_attack_detection", false),
		},
		Message: log_data["message"].(string),
		RawRequest: func() interface{} {
			switch v := log_data["raw_request"].(type) {
			case string:
				return SanitizeRawRequest(v)
			case []byte:
				return SanitizeRawRequest(string(v))
			default:
				// Try to marshal to JSON string if possible
				if b, err := json.Marshal(v); err == nil {
					return SanitizeRawRequest(string(b))
				}
				return v
			}
		}(),
		Timestamps: Timestamps{
			RequestCreatedAt:   toUnixTime(log_data["request_created_at"]),
			RequestProcessedAt: toUnixTime(log_data["request_processed_at"]),
			LoggedAt:           time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		},
	}
	jsonData, err = json.Marshal(entry)

	if err != nil {
		log.Printf("Failed to marshal log entry: %v", err)
		return
	}

	UPPER_LOG_LEVEL := strings.ToUpper(level)

	if UPPER_LOG_LEVEL == "INFO" {
		logger.Info(string(jsonData))
	} else if UPPER_LOG_LEVEL == "WARNING" {
		logger.Warn(string(jsonData))
	} else if UPPER_LOG_LEVEL == "ERROR" {
		logger.Error(string(jsonData))
	} else if UPPER_LOG_LEVEL == "FATAL" {
		logger.Fatal(string(jsonData))
	} else if UPPER_LOG_LEVEL == "DEBUG" {
		logger.Debug(string(jsonData))
	} else if UPPER_LOG_LEVEL == "TRACE" {
		logger.Trace(string(jsonData))
	} else {
		logger.Println("Unknown log level:", string(jsonData))
	}
}

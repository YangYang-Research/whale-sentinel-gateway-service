package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/YangYang-Research/whale-sentinel-services/whale-sentinel-gateway-service/helper"
	"github.com/YangYang-Research/whale-sentinel-services/whale-sentinel-gateway-service/logger"
	"github.com/YangYang-Research/whale-sentinel-services/whale-sentinel-gateway-service/shared"
	"github.com/YangYang-Research/whale-sentinel-services/whale-sentinel-gateway-service/validation"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

var (
	ctx         = context.Background()
	log         *logrus.Logger
	redisClient *redis.Client
)

// Load environment variables
func init() {
	// Initialize the application logger
	log = logrus.New()
	log.SetFormatter(&logrus.TextFormatter{})
	log.SetOutput(os.Stdout)
	log.SetLevel(logrus.DebugLevel)

	if err := godotenv.Load(); err != nil {
		log.WithFields(logrus.Fields{
			"msg": err,
		}).Error("Error loading .env file")
	} else {
		log.Info("Loaded environment variables from .env file")
	}

	redisClient = redis.NewClient(&redis.Options{
		Addr:     os.Getenv("REDIS_HOST") + ":" + os.Getenv("REDIS_PORT"),
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       0,
	})

	// Check Redis connection
	if err := redisClient.Ping(ctx).Err(); err != nil {
		log.WithFields(logrus.Fields{
			"msg": err,
		}).Error("Error connecting to Redis")
	} else {
		log.Info("Connected to Redis")
	}
}

// handlerRedis set and get value from Redis
func handlerRedis(key string, value string) (string, error) {
	if value == "" {
		// Get value from Redis
		val, err := redisClient.Get(ctx, key).Result()
		if err != nil {
			log.WithFields(logrus.Fields{
				"msg": err,
				"key": key,
			}).Error("Cannot GET - Not found key in Redis")
		}
		return val, err
	} else {
		// Set value in Redis
		err := redisClient.Set(ctx, key, value, 0).Err()
		if err != nil {
			log.WithFields(logrus.Fields{
				"msg": err,
			}).Error("Cannot SET - Cannot set value in Redis")
		}
		return value, err
	}
}

// handleGateway processes incoming requests
func handleGateway(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		helper.SendErrorResponse(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var req shared.GW_RequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.SendErrorResponse(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if err := validation.ValidateGW_Request(req); err != nil {
		helper.SendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	eventInfo, eventID := helper.GenerateGW_EventInfo(req)

	var (
		status string
	)

	status, agentProfile, err := processAgentProfile(req.GW_Payload.GW_Data.AgentID, req.GW_Payload.GW_Data.AgentName, "", eventInfo)
	if err != nil || status != "Success" {
		log.WithFields(logrus.Fields{
			"msg": err,
		}).Warn("Agent profile retrieval failed.")

		response := shared.GW_ResponseBody{
			Status:             status,
			Message:            "Agent profile retrieval failed.",
			GW_ResponseData:    shared.GW_ResponseData{},
			AnalysisResult:     "SERVICE_ROUTING_FAILED_MISSING_AGENT_PROFILE",
			EventInfo:          eventInfo,
			RequestCreatedAt:   req.RequestCreatedAt,
			RequestProcessedAt: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)

		log.Infof("POST %v - 200", r.URL)
		// Log the request to the log collector
		go func(agentID string, agentName string, eventInfo string, rawRequest interface{}) {
			// Log the request to the log collector
			logData := map[string]interface{}{
				"service":              "ws-gateway-service",
				"agent_id":             agentID,
				"agent_name":           agentName,
				"agent_running_mode":   "N/A",
				"source":               agentName,
				"destination":          "ws-gateway-service",
				"event_info":           eventInfo,
				"event_id":             eventID,
				"type":                 "AGENT_TO_SERVICE_EVENT",
				"action_type":          "SERVICE_ROUTING_ANALYSIS",
				"action_result":        "SERVICE_ROUTING_FAILED_MISSING_AGENT_PROFILE",
				"action_status":        "FAILED",
				"request_created_at":   req.RequestCreatedAt,
				"request_processed_at": time.Now().UTC().Format("2006-01-02T15:04:05Z"),
				"message":              "Cannot process request due to missing agent profile.",
				"raw_request":          rawRequest,
			}

			logger.Log("INFO", logData)
		}(req.GW_Payload.GW_Data.AgentID, req.GW_Payload.GW_Data.AgentName, eventInfo, req)
		return
	}

	var agent shared.AgentProfileRaw

	err = json.Unmarshal([]byte(agentProfile), &agent)
	if err != nil {
		log.WithField("msg", err).Error("Failed to parse agent configuration from Redis")
		http.Error(w, "Whale Sentinel - Internal Server Error", http.StatusInternalServerError)
		return
	}

	wad := agent.Profile["ws_module_web_attack_detection"].(map[string]interface{})
	dgad := agent.Profile["ws_module_dga_detection"].(map[string]interface{})
	cad := agent.Profile["ws_module_common_attack_detection"].(map[string]interface{})

	var (
		webAttackDetectionPredictScore                                   float64
		DGADetectionPredictScore                                         float64
		crossSiteScriptingDetection                                      bool
		sqlInjectionDetection                                            bool
		httpVerbTamperingDetection                                       bool
		httpLargeRequestDetection                                        bool
		unknownAttackDetection                                           bool
		insecureFileUploadDetection                                      bool
		insecureRedirectDetection                                        bool
		wg                                                               sync.WaitGroup
		webAttackDetectionErr, commonAttackDetectionErr, dgaDetectionErr error
	)

	wg.Add(3)
	go func() {
		defer wg.Done()
		if wad["enable"].(bool) {
			webAttackDetectionPredictScore, webAttackDetectionErr = processWebAttackDetection(req, eventInfo, wad)
		} else {
			webAttackDetectionPredictScore = 0
		}
	}()

	go func() {
		defer wg.Done()
		if cad["enable"].(bool) {
			crossSiteScriptingDetection, sqlInjectionDetection, httpVerbTamperingDetection, httpLargeRequestDetection, unknownAttackDetection, insecureFileUploadDetection, insecureRedirectDetection, commonAttackDetectionErr = processCommonAttackDetection(req, eventInfo, cad)
		}
	}()

	go func() {
		defer wg.Done()
		if dgad["enable"].(bool) {
			DGADetectionPredictScore, dgaDetectionErr = processDGADetection(req, eventInfo, dgad)
		} else {
			DGADetectionPredictScore = 0
		}
	}()

	wg.Wait()

	if webAttackDetectionErr != nil {
		log.WithFields(logrus.Fields{
			"msg": webAttackDetectionErr,
		}).Error("Error processing Web Attack Detection")
	}

	if commonAttackDetectionErr != nil {
		log.WithFields(logrus.Fields{
			"msg": commonAttackDetectionErr,
		}).Error("Error processing Common Attack Detection")
	}

	if dgaDetectionErr != nil {
		log.WithFields(logrus.Fields{
			"msg": dgaDetectionErr,
		}).Error("Error processing DGA Detection")
	}

	mapData := shared.GW_ResponseData{
		WebAttackDetectionPredictScore: webAttackDetectionPredictScore,
		DGADetectionPredictScore:       DGADetectionPredictScore,
		CommonAttackDetection: map[string]bool{
			"cross_site_scripting_detection": crossSiteScriptingDetection,
			"sql_injection_detection":        sqlInjectionDetection,
			"http_verb_tampering_detection":  httpVerbTamperingDetection,
			"http_large_request_detection":   httpLargeRequestDetection,
			"unknown_attack_detection":       unknownAttackDetection,
			"insecure_file_upload_detection": insecureFileUploadDetection,
			"insecure_redirect_detection":    insecureRedirectDetection,
		},
	}
	wadThreshold := int(wad["threshold"].(float64))
	dgaThreshold := int(dgad["threshold"].(float64))
	var analysisResult string
	if webAttackDetectionPredictScore >= float64(wadThreshold) || DGADetectionPredictScore >= float64(dgaThreshold) ||
		crossSiteScriptingDetection || sqlInjectionDetection || httpVerbTamperingDetection || httpLargeRequestDetection || unknownAttackDetection || insecureFileUploadDetection || insecureRedirectDetection {
		analysisResult = "ABNORMAL_REQUEST"
	} else {
		analysisResult = "NORMAL_REQUEST"
	}

	response := shared.GW_ResponseBody{
		Status:             "Success",
		Message:            "Analysis completed successfully.",
		GW_ResponseData:    mapData,
		AnalysisResult:     analysisResult,
		EventInfo:          eventInfo,
		RequestCreatedAt:   req.RequestCreatedAt,
		RequestProcessedAt: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	log.Infof("POST %v - 200", r.URL)
	// Log the request to the logg collector
	go func(agentID string, agentName string, eventInfo string, rawRequest interface{}) {
		// Log the request to the log collector
		logData := map[string]interface{}{
			"service":                            "ws-gateway-service",
			"agent_id":                           agentID,
			"agent_name":                         agentName,
			"agent_running_mode":                 agent.Profile["running_mode"].(string),
			"source":                             agentName,
			"destination":                        "ws-gateway-service",
			"event_info":                         eventInfo,
			"event_id":                           eventID,
			"type":                               "AGENT_TO_SERVICE_EVENT",
			"action_type":                        "SERVICE_ROUTING_ANALYSIS",
			"action_result":                      "SERVICE_ANALYSIS_SUCCESSED_" + analysisResult,
			"action_status":                      "SUCCESSED",
			"web_attack_detection_predict_score": webAttackDetectionPredictScore,
			"dga_detection_predict_score":        DGADetectionPredictScore,
			"cross_site_scripting_detection":     crossSiteScriptingDetection,
			"sql_injection_detection":            sqlInjectionDetection,
			"http_verb_tampering_detection":      httpVerbTamperingDetection,
			"http_large_request_detection":       httpLargeRequestDetection,
			"unknown_attack_detection":           unknownAttackDetection,
			"request_created_at":                 req.RequestCreatedAt,
			"request_processed_at":               time.Now().UTC().Format("2006-01-02T15:04:05Z"),
			"message":                            "Analysis completed successfully.",
			"raw_request":                        rawRequest,
		}

		logger.Log("INFO", logData)
	}(req.GW_Payload.GW_Data.AgentID, req.GW_Payload.GW_Data.AgentName, eventInfo, (req))
}

// HandleAgentProfile processes incoming requests for agent profile
func HandleAgentProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		helper.SendErrorResponse(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var req shared.AP_RequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.SendErrorResponse(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if err := validation.ValidateAP_Request(req); err != nil {
		helper.SendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	eventInfo, eventID := helper.GenerateAP_EventInfo(req)

	var (
		status string
	)

	status, agentProfile, err := processAgentProfile(req.AP_Payload.AP_Data.AgentID, req.AP_Payload.AP_Data.AgentName, "", eventInfo)
	if err != nil || status != "Success" || agentProfile == "" {
		log.WithFields(logrus.Fields{
			"msg": err,
		}).Warn("Profile retrieval failed.")

		response := shared.AP_ResponseBody{
			Status:  status,
			Message: "Profile retrieval failed.",
			AP_ResponseData: shared.AP_ResponseData{
				AgentProfile: shared.AgentProfile{},
			},
			EventInfo:          eventInfo,
			RequestCreatedAt:   req.RequestCreatedAt,
			RequestProcessedAt: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)

		log.Infof("POST %v - 200", r.URL)
		// Log the request to the logg collector
		go func(agentID string, agentName string, eventInfo string, rawRequest interface{}) {
			// Log the request to the log collector
			logData := map[string]interface{}{
				"service":              "ws-gateway-service",
				"agent_id":             agentID,
				"agent_name":           agentName,
				"agent_running_mode":   "N/A",
				"source":               agentID,
				"destination":          "ws-gateway-service",
				"event_info":           eventInfo,
				"event_id":             eventID,
				"type":                 "AGENT_TO_SERVICE_EVENT",
				"action_type":          "SERVICE_GET_AGENT_PROFILE",
				"action_result":        "SERVICE_GET_PROFILE_FAILED",
				"action_status":        "FAILED",
				"request_created_at":   req.RequestCreatedAt,
				"request_processed_at": time.Now().UTC().Format("2006-01-02T15:04:05Z"),
				"message":              "Cannot fetch agent profile from Redis / ws-configuration-service.",
				"raw_request":          rawRequest,
			}

			logger.Log("INFO", logData)
		}(req.AP_Payload.AP_Data.AgentID, req.AP_Payload.AP_Data.AgentName, eventInfo, (req))
		return
	}

	var agent shared.AgentProfileRaw

	err = json.Unmarshal([]byte(agentProfile), &agent)
	if err != nil {
		log.WithField("msg", err).Error("Failed to parse agent profile from Redis / ws-configuration-service")
		http.Error(w, "Whale Sentinel - Internal Server Error", http.StatusInternalServerError)
		return
	}

	wad := agent.Profile["ws_module_web_attack_detection"].(map[string]interface{})
	rrl := agent.Profile["ws_request_rate_limit"].(map[string]interface{})
	dgad := agent.Profile["ws_module_dga_detection"].(map[string]interface{})
	cad := agent.Profile["ws_module_common_attack_detection"].(map[string]interface{})
	srh := agent.Profile["secure_response_headers"].(map[string]interface{})

	mapData := shared.AgentProfile{
		RunningMode:                   agent.Profile["running_mode"].(string),
		LastRunMode:                   agent.Profile["last_run_mode"].(string),
		LiteModeDataIsSynchronized:    agent.Profile["lite_mode_data_is_synchronized"].(bool),
		LiteModeDataSynchronizeStatus: agent.Profile["lite_mode_data_synchronize_status"].(string),
		WebAttackDetection: shared.WebAttackDetectionConfig{
			Enable:       wad["enable"].(bool),
			DetectHeader: wad["detect_header"].(bool),
			Threshold:    int(wad["threshold"].(float64)),
		},
		RequestRateLimit: shared.RequestRateLimitConfig{
			Enable:    rrl["enable"].(bool),
			Threshold: int(rrl["threshold"].(float64)),
		},
		DGADetection: shared.DGADetectionConfig{
			Enable:    dgad["enable"].(bool),
			Threshold: int(dgad["threshold"].(float64)),
		},
		CommonAttackDetection: shared.CommonAttackDetectionConfig{
			Enable:                   cad["enable"].(bool),
			DetectCrossSiteScripting: cad["detect_cross_site_scripting"].(bool),
			DetectSqlInjection:       cad["detect_sql_injection"].(bool),
			DetectHTTPVerbTampering:  cad["detect_http_verb_tampering"].(bool),
			DetectHTTPLargeRequest:   cad["detect_http_large_request"].(bool),
			DetectUnknownAttack:      cad["detect_unknown_attack"].(bool),
			DetectInsecureFileUpload: cad["detect_insecure_file_upload"].(bool),
			DetectInsecureRedirect:   cad["detect_insecure_redirect"].(bool),
		},
		SecureResponseHeaders: shared.SecureResponseHeaderConfig{
			Enable:        srh["enable"].(bool),
			SecureHeaders: srh["headers"].(map[string]interface{}),
		},
	}

	response := shared.AP_ResponseBody{
		Status:  status,
		Message: "Profile retrieved successfully.",
		AP_ResponseData: shared.AP_ResponseData{
			AgentProfile: mapData,
		},
		EventInfo:          eventInfo,
		RequestCreatedAt:   req.RequestCreatedAt,
		RequestProcessedAt: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	log.Infof("POST %v - 200", r.URL)
	// Log the request to the logg collector
	go func(agentID string, agentName string, eventInfo string, rawRequest interface{}) {
		// Log the request to the log collector
		logData := map[string]interface{}{
			"service":              "ws-gateway-service",
			"agent_id":             agentID,
			"agent_name":           agentName,
			"agent_running_mode":   agent.Profile["running_mode"].(string),
			"source":               agentName,
			"destination":          "ws-gateway-service",
			"event_info":           eventInfo,
			"event_id":             eventID,
			"type":                 "AGENT_TO_SERVICE_EVENT",
			"action_type":          "SERVICE_GET_AGENT_PROFILE",
			"action_result":        "SERVICE_GET_PROFILE_SUCCESSED",
			"action_status":        "SUCCESSED",
			"request_created_at":   req.RequestCreatedAt,
			"request_processed_at": time.Now().UTC().Format("2006-01-02T15:04:05Z"),
			"message":              "Profile retrieved successfully.",
			"raw_request":          rawRequest,
		}

		logger.Log("INFO", logData)
	}(req.AP_Payload.AP_Data.AgentID, req.AP_Payload.AP_Data.AgentName, eventInfo, (req))
}

// HandleAgentSynchronize processes incoming requests for agent synchronization
func HandleAgentSynchronize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		helper.SendErrorResponse(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var req shared.AS_RequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.SendErrorResponse(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if err := validation.ValidateAS_Request(req); err != nil {
		helper.SendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	eventInfo, eventID := helper.GenerateAS_EventInfo(req)

	var (
		status string
	)

	status, agentProfile, err := processAgentSynchronize(req, eventInfo)
	if err != nil || status != "Success" || agentProfile == "" {
		log.WithFields(logrus.Fields{
			"msg": err,
		}).Warn("Profile synchronization failed.")

		response := shared.AS_ResponseBody{
			Status:  status,
			Message: "Profile synchronization failed.",
			AS_ResponseData: shared.AS_ResponseData{
				AgentProfile: shared.AgentProfile{},
			},
			EventInfo:          eventInfo,
			RequestCreatedAt:   req.RequestCreatedAt,
			RequestProcessedAt: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)

		log.Infof("POST %v - 200", r.URL)
		// Log the request to the logg collector
		go func(agentID string, agentName string, eventInfo string, rawRequest interface{}) {
			// Log the request to the log collector
			logData := map[string]interface{}{
				"service":              "ws-gateway-service",
				"agent_id":             agentID,
				"agent_name":           agentName,
				"agent_running_mode":   "N/A",
				"source":               agentName,
				"destination":          "ws-gateway-service",
				"event_info":           eventInfo,
				"event_id":             eventID,
				"type":                 "AGENT_TO_SERVICE_EVENT",
				"action_type":          "SERVICE_SYNC_AGENT_PROFILE",
				"action_result":        "SERVICE_SYNC_AGENT_PROFILE_FAILED",
				"action_status":        "FAILED",
				"request_created_at":   req.RequestCreatedAt,
				"request_processed_at": time.Now().UTC().Format("2006-01-02T15:04:05Z"),
				"message":              "Cannot synchronize agent profile to ws-configuration-service.",
				"raw_request":          rawRequest,
			}

			logger.Log("INFO", logData)
		}(req.AS_Payload.AS_Data.AgentID, req.AS_Payload.AS_Data.AgentName, eventInfo, (req))
		return
	}

	var agent shared.AgentProfileRaw

	err = json.Unmarshal([]byte(agentProfile), &agent)
	if err != nil {
		log.WithField("msg", err).Error("Failed to parse agent profile from Redis / ws-configuration-service")
		http.Error(w, "Whale Sentinel - Internal Server Error", http.StatusInternalServerError)
		return
	}

	wad := agent.Profile["ws_module_web_attack_detection"].(map[string]interface{})
	rrl := agent.Profile["ws_request_rate_limit"].(map[string]interface{})
	dgad := agent.Profile["ws_module_dga_detection"].(map[string]interface{})
	cad := agent.Profile["ws_module_common_attack_detection"].(map[string]interface{})
	srh := agent.Profile["secure_response_headers"].(map[string]interface{})

	mapData := shared.AgentProfile{
		RunningMode:                   agent.Profile["running_mode"].(string),
		LastRunMode:                   agent.Profile["last_run_mode"].(string),
		LiteModeDataIsSynchronized:    agent.Profile["lite_mode_data_is_synchronized"].(bool),
		LiteModeDataSynchronizeStatus: agent.Profile["lite_mode_data_synchronize_status"].(string),
		WebAttackDetection: shared.WebAttackDetectionConfig{
			Enable:       wad["enable"].(bool),
			DetectHeader: wad["detect_header"].(bool),
			Threshold:    int(wad["threshold"].(float64)),
		},
		RequestRateLimit: shared.RequestRateLimitConfig{
			Enable:    rrl["enable"].(bool),
			Threshold: int(rrl["threshold"].(float64)),
		},
		DGADetection: shared.DGADetectionConfig{
			Enable:    dgad["enable"].(bool),
			Threshold: int(dgad["threshold"].(float64)),
		},
		CommonAttackDetection: shared.CommonAttackDetectionConfig{
			Enable:                   cad["enable"].(bool),
			DetectCrossSiteScripting: cad["detect_cross_site_scripting"].(bool),
			DetectSqlInjection:       cad["detect_sql_injection"].(bool),
			DetectHTTPVerbTampering:  cad["detect_http_verb_tampering"].(bool),
			DetectHTTPLargeRequest:   cad["detect_http_large_request"].(bool),
			DetectUnknownAttack:      cad["detect_unknown_attack"].(bool),
			DetectInsecureFileUpload: cad["detect_insecure_file_upload"].(bool),
			DetectInsecureRedirect:   cad["detect_insecure_redirect"].(bool),
		},
		SecureResponseHeaders: shared.SecureResponseHeaderConfig{
			Enable:        srh["enable"].(bool),
			SecureHeaders: srh["headers"].(map[string]interface{}),
		},
	}

	response := shared.AS_ResponseBody{
		Status:  status,
		Message: "Profile synchronized successfully.",
		AS_ResponseData: shared.AS_ResponseData{
			AgentProfile: mapData,
		},
		EventInfo:          eventInfo,
		RequestCreatedAt:   req.RequestCreatedAt,
		RequestProcessedAt: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	log.Infof("POST %v - 200", r.URL)
	// Log the request to the logg collector
	go func(agentID string, agentName string, eventInfo string, rawRequest interface{}) {
		// Log the request to the log collector
		logData := map[string]interface{}{
			"service":              "ws-gateway-service",
			"agent_id":             agentID,
			"agent_name":           agentName,
			"agent_running_mode":   agent.Profile["running_mode"].(string),
			"source":               agentID,
			"destination":          "ws-gateway-service",
			"event_info":           eventInfo,
			"event_id":             eventID,
			"type":                 "AGENT_EVENT",
			"action_type":          "SERVICE_SYNC_AGENT_PROFILE",
			"action_result":        "SERVICE_SYNC_AGENT_PROFILE_SUCCESSED",
			"action_status":        "SUCCESSED",
			"request_created_at":   req.RequestCreatedAt,
			"request_processed_at": time.Now().UTC().Format("2006-01-02T15:04:05Z"),
			"message":              "Profile synchronized successfully.",
			"raw_request":          rawRequest,
		}

		logger.Log("INFO", logData)
	}(req.AS_Payload.AS_Data.AgentID, req.AS_Payload.AS_Data.AgentName, eventInfo, (req))
}

func makeHTTPRequest(url, endpoint string, body interface{}) ([]byte, error) {
	jsonData, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %v", err)
	}

	secretValue, err := getSecret(os.Getenv("WHALE_SENTINEL_SERVICE_SECRET_KEY_NAME"))
	if err != nil {
		return nil, fmt.Errorf("failed to get Secret key: %v", err)
	}

	req, err := http.NewRequest("POST", url+endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	auth := "ws:" + secretValue
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))

	verifyTLS, err := strconv.ParseBool(os.Getenv("WHALE_SENTINEL_VERIFY_TLS"))
	if err != nil {
		log.Fatalf("Invalid boolean value for WHALE_SENTINEL_VERIFY_TLS: %v", err)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !verifyTLS},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call endpoint: %v", err)
	}
	defer resp.Body.Close()

	log.Infof("POST %v - %v", url+endpoint, resp.StatusCode)
	return io.ReadAll(resp.Body)

}

func processWebAttackDetection(req shared.GW_RequestBody, eventInfo string, wad map[string]interface{}) (float64, error) {
	log.WithFields(logrus.Fields{
		"msg": "Event Info: " + eventInfo,
	}).Debug("Processing Web Attack Detection")

	httpRequest := req.GW_Payload.GW_Data.HTTPRequest
	var concatenatedData string
	if wad["detect_header"].(bool) {
		concatenatedData = fmt.Sprintf("%s %s \n Host: %s \n User-Agent: %s \n Content-Type: %s \n Content-Length: %d \n\n %s%s",
			httpRequest.Method, httpRequest.URL, httpRequest.Host, httpRequest.Headers.UserAgent, httpRequest.Headers.ContentType, httpRequest.Headers.ContentLength, httpRequest.QueryParams, httpRequest.Body)
	} else {
		concatenatedData = fmt.Sprintf("%s %s",
			httpRequest.QueryParams,
			httpRequest.Body)
	}

	requestBody := map[string]interface{}{
		"event_info": eventInfo,
		"payload": map[string]interface{}{
			"data": map[string]interface{}{
				"agent_id":   req.GW_Payload.GW_Data.AgentID,
				"agent_name": req.GW_Payload.GW_Data.AgentName,
				"sentence":   concatenatedData,
			},
		},
		"request_created_at": time.Now().UTC().Format("2006-01-02T15:04:05Z"),
	}

	responseData, err := makeHTTPRequest(os.Getenv("WS_MODULE_WEB_ATTACK_DETECTION_URL"), os.Getenv("WS_MODULE_WEB_ATTACK_DETECTION_ENDPOINT"), requestBody)
	if err != nil {
		return 0, err
	}

	var response map[string]interface{}
	if err := json.Unmarshal(responseData, &response); err != nil {
		return 0, fmt.Errorf("failed to parse response data: %v", err)
	}

	//Debug: Log the response JSON
	// log.Printf("Response JSON: %+v", response)
	log.WithFields(logrus.Fields{
		"msg": "Event ID: " + eventInfo,
	}).Debug("Processed Web Attack Detection")

	// Check if the "data" key exists and is not nil
	dataValue, ok := response["data"]
	if !ok || dataValue == nil {
		return 0, fmt.Errorf("key 'data' is missing or nil in the response")
	}

	// Perform type assertion for the "data" key
	data, ok := dataValue.(map[string]interface{})
	if !ok {
		return 0, fmt.Errorf("invalid type for 'data': expected map[string]interface{}")
	}

	// Check if the "threat_metrix" key exists and is not nil
	threatMetrixValue, ok := data["threat_metrix"]
	if !ok || threatMetrixValue == nil {
		return 0, fmt.Errorf("key 'threat_metrix' is missing or nil in the response")
	}

	// Perform type assertion for the "threat_metrix" key
	threatMetrix, ok := threatMetrixValue.(map[string]interface{})
	if !ok {
		return 0, fmt.Errorf("invalid type for 'threat_metrix': expected map[string]interface{}")
	}

	// Check if the "score" key exists and is not nil
	scoreValue, ok := threatMetrix["score"]
	if !ok || scoreValue == nil {
		return 0, fmt.Errorf("key 'score' is missing or nil in the response")
	}

	// Perform type assertion for the "score" key
	score, ok := scoreValue.(float64)
	if !ok {
		return 0, fmt.Errorf("invalid type for 'score': expected float64, got %T", scoreValue)
	}

	return score, nil
}

func processCommonAttackDetection(req shared.GW_RequestBody, eventInfo string, _ map[string]interface{}) (bool, bool, bool, bool, bool, bool, bool, error) {
	log.WithFields(logrus.Fields{
		"msg": "Event Info: " + eventInfo,
	}).Debug("Processing Common Attack Detection")

	requestBody := map[string]interface{}{
		"event_info": eventInfo,
		"payload": map[string]interface{}{
			"data": map[string]interface{}{
				"agent_id":   req.GW_Payload.GW_Data.AgentID,
				"agent_name": req.GW_Payload.GW_Data.AgentName,
				"client_information": map[string]interface{}{
					"ip":              req.GW_Payload.GW_Data.ClientInformation.IP,
					"device_type":     req.GW_Payload.GW_Data.ClientInformation.DeviceType,
					"network_type":    req.GW_Payload.GW_Data.ClientInformation.NetworkType,
					"platform":        req.GW_Payload.GW_Data.ClientInformation.Platform,
					"browser":         req.GW_Payload.GW_Data.ClientInformation.Browser,
					"browser_version": req.GW_Payload.GW_Data.ClientInformation.BrowserVersion,
				},
				"http_request": map[string]interface{}{
					"method": req.GW_Payload.GW_Data.HTTPRequest.Method,
					"url":    req.GW_Payload.GW_Data.HTTPRequest.URL,
					"host":   req.GW_Payload.GW_Data.HTTPRequest.Host,
					"headers": map[string]interface{}{
						"user-agent":     req.GW_Payload.GW_Data.HTTPRequest.Headers.UserAgent,
						"content-type":   req.GW_Payload.GW_Data.HTTPRequest.Headers.ContentType,
						"content-length": req.GW_Payload.GW_Data.HTTPRequest.Headers.ContentLength,
						"referrer":       req.GW_Payload.GW_Data.HTTPRequest.Headers.Referrer,
					},
					"query_parameters": req.GW_Payload.GW_Data.HTTPRequest.QueryParams,
					"body":             req.GW_Payload.GW_Data.HTTPRequest.Body,
					"files":            req.GW_Payload.GW_Data.HTTPRequest.Files,
				},
			},
		},
		"request_created_at": time.Now().UTC().Format("2006-01-02T15:04:05Z"),
	}

	responseData, err := makeHTTPRequest(os.Getenv("WS_MODULE_COMMON_ATTACK_DETECTION_URL"), os.Getenv("WS_MODULE_COMMON_ATTACK_DETECTION_ENDPOINT"), requestBody)
	if err != nil {
		return false, false, false, false, false, false, false, err
	}

	var response map[string]interface{}
	if err := json.Unmarshal(responseData, &response); err != nil {
		return false, false, false, false, false, false, false, fmt.Errorf("failed to parse response data: %v", err)
	}

	//Debug: Log the response JSON
	//log.Printf("Response JSON: %+v", response)
	log.WithFields(logrus.Fields{
		"msg": "Event Info: " + eventInfo,
	}).Debug("Processed Common Attack Detection")

	data := response["data"].(map[string]interface{})
	return data["cross_site_scripting_detection"].(bool),
		data["sql_injection_detection"].(bool),
		data["http_verb_tampering_detection"].(bool),
		data["http_large_request_detection"].(bool),
		data["unknown_attack_detection"].(bool),
		data["insecure_file_upload_detection"].(bool),
		data["insecure_redirect_detection"].(bool),
		nil
}

func processDGADetection(req shared.GW_RequestBody, eventInfo string, _ map[string]interface{}) (float64, error) {
	log.WithFields(logrus.Fields{
		"msg": "Event Info: " + eventInfo,
	}).Debug("Processing DGA Detection")

	referrerURL := req.GW_Payload.GW_Data.HTTPRequest.Headers.Referrer

	domain, err := helper.GetDomain(referrerURL)
	if err != nil {
		return 0, err
	}

	requestBody := map[string]interface{}{
		"event_info": eventInfo,
		"payload": map[string]interface{}{
			"data": map[string]interface{}{
				"agent_id":   req.GW_Payload.GW_Data.AgentID,
				"agent_name": req.GW_Payload.GW_Data.AgentName,
				"sentence":   domain,
			},
		},
		"request_created_at": time.Now().UTC().Format("2006-01-02T15:04:05Z"),
	}

	responseData, err := makeHTTPRequest(os.Getenv("WS_MODULE_DGA_DETECTION_URL"), os.Getenv("WS_MODULE_DGA_DETECTION_ENDPOINT"), requestBody)
	if err != nil {
		return 0, err
	}

	var response map[string]interface{}
	if err := json.Unmarshal(responseData, &response); err != nil {
		return 0, fmt.Errorf("failed to parse response data: %v", err)
	}

	//Debug: Log the response JSON
	// log.Printf("Response JSON: %+v", response)
	log.WithFields(logrus.Fields{
		"msg": "Event Info: " + eventInfo,
	}).Debug("Processed DGA Detection")

	// Check if the "data" key exists and is not nil
	dataValue, ok := response["data"]
	if !ok || dataValue == nil {
		return 0, fmt.Errorf("key 'data' is missing or nil in the response")
	}

	// Perform type assertion for the "data" key
	data, ok := dataValue.(map[string]interface{})
	if !ok {
		return 0, fmt.Errorf("invalid type for 'data': expected map[string]interface{}")
	}

	// Check if the "threat_metrix" key exists and is not nil
	threatMetrixValue, ok := data["threat_metrix"]
	if !ok || threatMetrixValue == nil {
		return 0, fmt.Errorf("key 'threat_metrix' is missing or nil in the response")
	}

	// Perform type assertion for the "threat_metrix" key
	threatMetrix, ok := threatMetrixValue.(map[string]interface{})
	if !ok {
		return 0, fmt.Errorf("invalid type for 'threat_metrix': expected map[string]interface{}")
	}

	// Check if the "score" key exists and is not nil
	scoreValue, ok := threatMetrix["score"]
	if !ok || scoreValue == nil {
		return 0, fmt.Errorf("key 'score' is missing or nil in the response")
	}

	// Perform type assertion for the "score" key
	score, ok := scoreValue.(float64)
	if !ok {
		return 0, fmt.Errorf("invalid type for 'score': expected float64, got %T", scoreValue)
	}

	return score, nil
}

func processAgentProfile(agentId string, agentName string, agentValue string, eventInfo string) (string, string, error) {
	getAgentProfile, err := handlerRedis(agentName, agentValue)
	if err != nil {
		log.Warn("Unable to retrieve the agent profile from Redis. Proceeding to fetch the agent profile from ws-configuration-service.")
	}

	if getAgentProfile == "" {
		requestBody := map[string]interface{}{
			"event_info": eventInfo,
			"payload": map[string]interface{}{
				"data": map[string]interface{}{
					"type": "agent",
					"name": agentName,
					"id":   agentId,
				},
			},
			"request_created_at": time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		}
		responseData, err := makeHTTPRequest(os.Getenv("WS_MODULE_CONFIGURATION_SERVICE_URL"), os.Getenv("WS_MODULE_CONFIGURATION_SERVICE_ENDPOINT")+"/profile", requestBody)
		if err != nil {
			log.WithFields(logrus.Fields{
				"msg": err,
			}).Error("Error calling WS Module Configuration Service")
			return "Error", "", fmt.Errorf("failed to call WS Module Configuration Service: %v", err)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(responseData, &response); err != nil {
			return "Error", "", fmt.Errorf("failed to parse response data: %v", err)
		}

		data := response["data"].(map[string]interface{})
		return response["status"].(string), data["profile"].(string), nil
	}
	return "Success", getAgentProfile, nil
}

func processAgentSynchronize(req shared.AS_RequestBody, eventInfo string) (string, string, error) {

	requestBody := map[string]interface{}{
		"event_info": eventInfo,
		"payload": map[string]interface{}{
			"data": map[string]interface{}{
				"type":             "agent",
				"name":             req.AS_Payload.AS_Data.AgentName,
				"id":               req.AS_Payload.AS_Data.AgentID,
				"profile":          req.AS_Payload.AS_Data.AS_Profile,
				"host_information": req.AS_Payload.AS_Data.HostInformation,
			},
		},
		"request_created_at": time.Now().UTC().Format("2006-01-02T15:04:05Z"),
	}

	responseData, err := makeHTTPRequest(os.Getenv("WS_MODULE_CONFIGURATION_SERVICE_URL"), os.Getenv("WS_MODULE_CONFIGURATION_SERVICE_ENDPOINT")+"/profile/synchronize", requestBody)
	if err != nil {
		log.WithFields(logrus.Fields{
			"msg": err,
		}).Error("Error calling WS Module Configuration Service")
		return "Error", "", fmt.Errorf("failed to call WS Module Configuration Service: %v", err)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(responseData, &response); err != nil {
		return "Error", "", fmt.Errorf("failed to parse response data: %v", err)
	}

	data := response["data"].(map[string]interface{})
	return response["status"].(string), data["profile"].(string), nil
}

// getSecret retrieves the API key based on the configuration
func getSecret(key string) (string, error) {
	awsRegion := os.Getenv("AWS_REGION")
	awsSecretName := os.Getenv("AWS_SECRET_NAME")
	awsSecretKeyName := key

	awsSecretVaule, err := helper.GetAWSSecret(awsRegion, awsSecretName, awsSecretKeyName)

	return awsSecretVaule, err
}

// apiKeyAuthMiddleware is a middleware that handles API Key authentication
func apiKeyAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secretValue, err := getSecret(os.Getenv("WHALE_SENTINEL_AGENT_SECRET_KEY_NAME"))
		if err != nil {
			helper.SendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			helper.SendErrorResponse(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Decode the Base64-encoded Authorization header
		authHeader = authHeader[len("Basic "):]
		decodedAuthHeader, err := base64.StdEncoding.DecodeString(authHeader)
		if err != nil {
			helper.SendErrorResponse(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		expectedAuthValue := fmt.Sprintf("ws-agent:%s", secretValue)
		if string(decodedAuthHeader) != expectedAuthValue {
			helper.SendErrorResponse(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Main function
func main() {
	log.Info("WS Gateway Service is running on port 5000...")
	// Initialize the logger
	logMaxSize, _ := strconv.Atoi(os.Getenv("LOG_MAX_SIZE"))
	logMaxBackups, _ := strconv.Atoi(os.Getenv("LOG_MAX_BACKUPS"))
	logMaxAge, _ := strconv.Atoi(os.Getenv("LOG_MAX_AGE"))
	logCompression, _ := strconv.ParseBool(os.Getenv("LOG_COMPRESSION"))
	logger.SetupWSLogger("ws-gateway-service", logMaxSize, logMaxBackups, logMaxAge, logCompression)
	// Wrap the handler with a 30-second timeout
	timeoutHandlerGW := http.TimeoutHandler(apiKeyAuthMiddleware(http.HandlerFunc(handleGateway)), 30*time.Second, "Request timed out")
	timeOutHandlerAP := http.TimeoutHandler(apiKeyAuthMiddleware(http.HandlerFunc(HandleAgentProfile)), 30*time.Second, "Request timed out")
	timeOutHandlerAS := http.TimeoutHandler(apiKeyAuthMiddleware(http.HandlerFunc(HandleAgentSynchronize)), 30*time.Second, "Request timed out")
	// Register the timeout handler
	http.Handle("/api/v1/ws/services/gateway", timeoutHandlerGW)
	http.Handle("/api/v1/ws/services/gateway/agent/profile", timeOutHandlerAP)
	http.Handle("/api/v1/ws/services/gateway/agent/synchronize", timeOutHandlerAS)
	log.Fatal(http.ListenAndServe(":5000", nil))
}

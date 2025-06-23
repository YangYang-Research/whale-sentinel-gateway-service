package shared

type (
	GW_RequestBody struct {
		GW_Payload       GW_Payload `json:"payload"`
		RequestCreatedAt string     `json:"request_created_at"`
	}

	GW_Payload struct {
		GW_Data GW_Data `json:"data"`
	}

	GW_Data struct {
		AgentID            string             `json:"agent_id"`
		AgentName          string             `json:"agent_name"`
		ClientInformation  ClientInformation  `json:"client_information"`
		HTTPRequest        HTTPRequest        `json:"http_request"`
		RunTimeInformation RunTimeInformation `json:"runtime_information"`
	}

	ClientInformation struct {
		IP             string `json:"ip"`
		DeviceType     string `json:"device_type"`
		NetworkType    string `json:"network_type"`
		Platform       string `json:"platform"`
		Browser        string `json:"browser"`
		BrowserVersion string `json:"browser_version"`
	}

	HTTPRequest struct {
		Method      string            `json:"method"`
		URL         string            `json:"url"`
		Host        string            `json:"host"`
		Headers     HTTPRequestHeader `json:"headers"`
		QueryParams string            `json:"query_parameters"`
		Body        string            `json:"body"`
		Files       []UploadedFile    `json:"files"`
	}

	HTTPRequestHeader struct {
		UserAgent     string `json:"user-agent"`
		ContentType   string `json:"content-type"`
		ContentLength int    `json:"content-length"`
		Referer       string `json:"referer"`
	}

	UploadedFile struct {
		FileName    string `json:"file_name"`
		FileSize    int    `json:"file_size"`
		FileContent string `json:"file_content"`
		FileType    string `json:"file_type"`
		FileHash256 string `json:"file_hash256"`
	}

	RunTimeInformation struct {
		IPAddress         string   `json:"ip_address"`
		PID               int      `json:"pid"`
		RunAs             string   `json:"run_as"`
		ExecutablePath    string   `json:"executable_path"`
		ExecutableName    string   `json:"executable_name"`
		ExecutableVersion string   `json:"executable_version"`
		ProcessName       string   `json:"process_name"`
		ProcessPath       string   `json:"process_path"`
		ProcessCommand    []string `json:"process_command"`
		Platform          string   `json:"platform"`
		CPUUsage          float64  `json:"cpu_usage"`
		MemoryUsage       float64  `json:"memory_usage"`
		Architecture      string   `json:"architecture"`
		OSVersion         string   `json:"os_version"`
		OSName            string   `json:"os_name"`
		OSBuild           string   `json:"os_build"`
	}

	AP_RequestBody struct {
		AP_Payload       AP_Payload `json:"payload"`
		RequestCreatedAt string     `json:"request_created_at"`
	}

	AP_Payload struct {
		AP_Data AP_Data `json:"data"`
	}

	AP_Data struct {
		AgentID   string `json:"agent_id"`
		AgentName string `json:"agent_name"`
	}

	AgentProfileRaw struct {
		Profile map[string]interface{} `json:"profile"`
	}

	GW_ResponseBody struct {
		Status             string          `json:"status"`
		Message            string          `json:"message"`
		GW_ResponseData    GW_ResponseData `json:"data"`
		AnalysisResult     string          `json:"analysis_result"`
		EventInfo          string          `json:"event_info"`
		RequestCreatedAt   string          `json:"request_created_at"`
		RequestProcessedAt string          `json:"request_processed_at"`
	}

	GW_ResponseData struct {
		WebAttackDetectionPredictScore float64         `json:"ws_module_web_attack_detection_predict_score"`
		DGADetectionPredictScore       float64         `json:"ws_module_dga_detection_predict_score"`
		CommonAttackDetection          map[string]bool `json:"ws_module_common_attack_detection"`
	}

	AP_ResponseBody struct {
		Status             string          `json:"status"`
		Message            string          `json:"message"`
		AP_ResponseData    AP_ResponseData `json:"data"`
		EventInfo          string          `json:"event_info"`
		RequestCreatedAt   string          `json:"request_created_at"`
		RequestProcessedAt string          `json:"request_processed_at"`
	}

	AP_ResponseData struct {
		AgentProfile AgentProfile `json:"profile"`
	}

	AS_RequestBody struct {
		AS_Payload       AS_Payload `json:"payload"`
		RequestCreatedAt string     `json:"request_created_at"`
	}

	AS_Payload struct {
		AS_Data AS_Data `json:"data"`
	}

	AS_Data struct {
		AgentID         string          `json:"agent_id"`
		AgentName       string          `json:"agent_name"`
		AS_Profile      AS_Profile      `json:"profile"`
		HostInformation HostInformation `json:"host_information"`
	}

	AS_Profile struct {
		LiteModeDataIsSynchronized    bool   `json:"lite_mode_data_is_synchronized"`
		LiteModeDataSynchronizeStatus string `json:"lite_mode_data_synchronize_status"`
	}

	HostInformation struct {
		IPAddress         string   `json:"ip_address"`
		PID               int      `json:"pid"`
		RunAs             string   `json:"run_as"`
		ExecutablePath    string   `json:"executable_path"`
		ExecutableName    string   `json:"executable_name"`
		ExecutableVersion string   `json:"executable_version"`
		ProcessName       string   `json:"process_name"`
		ProcessPath       string   `json:"process_path"`
		ProcessCommand    []string `json:"process_command"`
		Platform          string   `json:"platform"`
		CPUUsage          float64  `json:"cpu_usage"`
		MemoryUsage       float64  `json:"memory_usage"`
		Architecture      string   `json:"architecture"`
		OSVersion         string   `json:"os_version"`
		OSName            string   `json:"os_name"`
		OSBuild           string   `json:"os_build"`
	}

	AS_ResponseBody struct {
		Status             string          `json:"status"`
		Message            string          `json:"message"`
		AS_ResponseData    AS_ResponseData `json:"data"`
		EventInfo          string          `json:"event_info"`
		RequestCreatedAt   string          `json:"request_created_at"`
		RequestProcessedAt string          `json:"request_processed_at"`
	}

	AS_ResponseData struct {
		AgentProfile AgentProfile `json:"profile"`
	}

	AgentProfile struct {
		RunningMode                   string                      `json:"running_mode"`
		LastRunMode                   string                      `json:"last_run_mode"`
		LiteModeDataIsSynchronized    bool                        `json:"lite_mode_data_is_synchronized"`
		LiteModeDataSynchronizeStatus string                      `json:"lite_mode_data_synchronize_status"`
		WebAttackDetection            WebAttackDetectionConfig    `json:"ws_module_web_attack_detection"`
		RequestRateLimit              RequestRateLimitConfig      `json:"ws_request_rate_limit"`
		DGADetection                  DGADetectionConfig          `json:"ws_module_dga_detection"`
		CommonAttackDetection         CommonAttackDetectionConfig `json:"ws_module_common_attack_detection"`
		SecureResponseHeaders         SecureResponseHeaderConfig  `json:"secure_response_headers"`
	}

	WebAttackDetectionConfig struct {
		Enable       bool `json:"enable"`
		DetectHeader bool `json:"detect_header"`
		Threshold    int  `json:"threshold"`
	}

	RequestRateLimitConfig struct {
		Enable    bool `json:"enable"`
		Threshold int  `json:"threshold"`
	}

	DGADetectionConfig struct {
		Enable    bool `json:"enable"`
		Threshold int  `json:"threshold"`
	}

	CommonAttackDetectionConfig struct {
		Enable                   bool `json:"enable"`
		DetectCrossSiteScripting bool `json:"detect_cross_site_scripting"`
		DetectSqlInjection       bool `json:"detect_sql_injection"`
		DetectHTTPVerbTampering  bool `json:"detect_http_verb_tampering"`
		DetectHTTPLargeRequest   bool `json:"detect_http_large_request"`
		DetectUnknownAttack      bool `json:"detect_unknown_attack"`
	}

	SecureResponseHeaderConfig struct {
		Enable        bool                   `json:"enable"`
		SecureHeaders map[string]interface{} `json:"headers"`
	}

	ErrorResponse struct {
		Status    string `json:"status"`
		Message   string `json:"message"`
		ErrorCode int    `json:"error_code"`
	}
)

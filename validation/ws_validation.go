package validation

import (
	"fmt"
	"net"
	"regexp"
	"time"

	"github.com/YangYang-Research/whale-sentinel-services/whale-sentinel-gateway-service/shared"
)

// Helper functions
func ValidateGW_Request(req shared.GW_RequestBody) error {
	if req.GW_Payload.GW_Data.ClientInformation.IP == "" || req.GW_Payload.GW_Data.HTTPRequest.Method == "" || req.GW_Payload.GW_Data.HTTPRequest.URL == "" || req.GW_Payload.GW_Data.HTTPRequest.Headers.UserAgent == "" || req.GW_Payload.GW_Data.HTTPRequest.Headers.ContentType == "" {
		return fmt.Errorf("missing required fields")
	}

	if matched, _ := regexp.MatchString(`^ws_agent_.*`, req.GW_Payload.GW_Data.AgentName); !matched {
		return fmt.Errorf("invalid AgentName format")
	}

	if _, err := time.Parse(time.RFC3339, req.RequestCreatedAt); err != nil {
		return fmt.Errorf("invalid timestamp format")
	}
	return nil
}

func ValidateAP_Request(req shared.AP_RequestBody) error {
	if req.AP_Payload.AP_Data.AgentID == "" || req.AP_Payload.AP_Data.AgentName == "" {
		return fmt.Errorf("missing required fields")
	}

	if matched, _ := regexp.MatchString(`^ws_agent_.*`, req.AP_Payload.AP_Data.AgentName); !matched {
		return fmt.Errorf("invalid AgentName format")
	}

	if _, err := time.Parse(time.RFC3339, req.RequestCreatedAt); err != nil {
		return fmt.Errorf("invalid timestamp format")
	}
	return nil
}

func ValidateAS_Request(req shared.AS_RequestBody) error {
	if req.AS_Payload.AS_Data.AgentID == "" || req.AS_Payload.AS_Data.AgentName == "" {
		return fmt.Errorf("missing required fields")
	}

	if matched, _ := regexp.MatchString(`^ws_agent_.*`, req.AS_Payload.AS_Data.AgentName); !matched {
		return fmt.Errorf("invalid AgentName format")
	}

	if _, err := time.Parse(time.RFC3339, req.RequestCreatedAt); err != nil {
		return fmt.Errorf("invalid timestamp format")
	}

	ip := req.AS_Payload.AS_Data.IPAddress
	if ip != "" && net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address format")
	}

	return nil
}

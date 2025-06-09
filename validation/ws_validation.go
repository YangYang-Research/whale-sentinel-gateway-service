package validation

import (
	"fmt"
	"regexp"
	"time"

	"github.com/YangYang-Research/whale-sentinel-services/whale-sentinel-gateway-service/shared"
)

// Helper functions
func ValidateGW_Request(req shared.GW_RequestBody) error {
	if req.GW_Payload.GW_Data.ClientInformation.IP == "" || req.GW_Payload.GW_Data.HTTPRequest.Method == "" || req.GW_Payload.GW_Data.HTTPRequest.URL == "" || req.GW_Payload.GW_Data.HTTPRequest.Headers.UserAgent == "" || req.GW_Payload.GW_Data.HTTPRequest.Headers.ContentType == "" {
		return fmt.Errorf("missing required fields")
	}

	if matched, _ := regexp.MatchString(`^ws_agent_.*`, req.AgentName); !matched {
		return fmt.Errorf("invalid AgentName format")
	}

	if _, err := time.Parse(time.RFC3339, req.RequestCreatedAt); err != nil {
		return fmt.Errorf("invalid timestamp format")
	}
	return nil
}

func ValidateAP_Request(req shared.AP_RequestBody) error {
	if req.AgentID == "" {
		return fmt.Errorf("missing required fields")
	}

	if req.AgentName == "" {
		return fmt.Errorf("missing required fields")
	}

	if matched, _ := regexp.MatchString(`^ws_agent_.*`, req.AgentName); !matched {
		return fmt.Errorf("invalid AgentName format")
	}

	if _, err := time.Parse(time.RFC3339, req.RequestCreatedAt); err != nil {
		return fmt.Errorf("invalid timestamp format")
	}
	return nil
}

func ValidateAS_Request(req shared.AS_RequestBody) error {
	if req.AgentID == "" {
		return fmt.Errorf("missing required fields")
	}

	if req.AgentName == "" {
		return fmt.Errorf("missing required fields")
	}

	if matched, _ := regexp.MatchString(`^ws_agent_.*`, req.AgentName); !matched {
		return fmt.Errorf("invalid AgentName format")
	}

	if req.AS_Profile == nil {
		return fmt.Errorf("missing payload")
	}

	if _, err := time.Parse(time.RFC3339, req.RequestCreatedAt); err != nil {
		return fmt.Errorf("invalid timestamp format")
	}
	return nil
}

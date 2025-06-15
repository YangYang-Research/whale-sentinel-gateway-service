package helper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"net/url"

	"github.com/YangYang-Research/whale-sentinel-services/whale-sentinel-gateway-service/shared"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go/aws"
)

func GetAWSSecret(awsRegion string, secretName string, secretKeyName string) (string, error) {
	config, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(awsRegion))
	if err != nil {
		log.Fatal(err)
	}

	// Create Secrets Manager client
	svc := secretsmanager.NewFromConfig(config)

	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(secretName),
		VersionStage: aws.String("AWSCURRENT"), // VersionStage defaults to AWSCURRENT if unspecified
	}

	result, err := svc.GetSecretValue(context.TODO(), input)
	if err != nil {
		// For a list of exceptions thrown, see
		// https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
		log.Fatal(err.Error())
	}

	// Decrypts secret using the associated KMS key.
	var secretString string = *result.SecretString

	// Parse the JSON string to extract the apiKey
	var secretData map[string]string
	if err := json.Unmarshal([]byte(secretString), &secretData); err != nil {
		log.Fatalf("Failed to parse secret string: %v", err)
	}

	secretVaule, exists := secretData[secretKeyName]
	if !exists {
		log.Fatalf("apiKey not found in secret string")
	}

	// Use the apiKey as needed
	return secretVaule, nil
}

func GetDomain(fullUrl string) (string, error) {
	parsedUrl, err := url.Parse(fullUrl)
	if err != nil {
		return "", err
	}
	return parsedUrl.Host, nil
}

func GenerateGW_EventInfo(req shared.GW_RequestBody) (string, string) {
	hashInput := req.RequestCreatedAt + req.GW_Payload.GW_Data.ClientInformation.IP + req.GW_Payload.GW_Data.ClientInformation.DeviceType + req.GW_Payload.GW_Data.HTTPRequest.Method + req.GW_Payload.GW_Data.HTTPRequest.Host + req.GW_Payload.GW_Data.HTTPRequest.QueryParams + req.GW_Payload.GW_Data.HTTPRequest.Body
	eventID := sha256.Sum256([]byte(hashInput))
	eventInfo := req.GW_Payload.GW_Data.AgentName + "|" + "WS_GATEWAY_SERVICE" + "|" + hex.EncodeToString(eventID[:])
	return eventInfo, hex.EncodeToString(eventID[:])
}

func GenerateAP_EventInfo(req shared.AP_RequestBody) (string, string) {
	hashInput := req.RequestCreatedAt + req.AP_Payload.AP_Data.AgentName
	eventID := sha256.Sum256([]byte(hashInput))
	eventInfo := req.AP_Payload.AP_Data.AgentName + "|" + "WS_GATEWAY_SERVICE" + "|" + hex.EncodeToString(eventID[:])
	return eventInfo, hex.EncodeToString(eventID[:])
}

func GenerateAS_EventInfo(req shared.AS_RequestBody) (string, string) {
	hashInput := req.RequestCreatedAt + req.AS_Payload.AS_Data.AgentID
	eventID := sha256.Sum256([]byte(hashInput))
	eventInfo := req.AS_Payload.AS_Data.AgentName + "|" + "WS_GATEWAY_SERVICE" + "|" + hex.EncodeToString(eventID[:])
	return eventInfo, hex.EncodeToString(eventID[:])
}

func SendErrorResponse(w http.ResponseWriter, message string, errorCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(errorCode)
	json.NewEncoder(w).Encode(shared.ErrorResponse{
		Status:    "Error",
		Message:   message,
		ErrorCode: errorCode,
	})
}

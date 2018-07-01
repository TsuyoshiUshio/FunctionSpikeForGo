package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/web/mgmt/2018-02-01/web"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure/cli"
	"github.com/Azure/go-autorest/autorest/to"
)

type AccessToken struct {
	ClientID     string
	AccessToken  *adal.Token
	IsCloudShell bool
}

type KeyManagemetResponse struct {
	Keys  *[]KeyManagementKey  `json:"keys"`
	Links *[]KeyManagementLink `json:"links"`
}

type KeyManagementKey struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type KeyManagementLink struct {
	Rel  string `json:"rel"`
	Href string `json:"href"`
}

func findValidAccessTokenForTenant(tokens []cli.Token, tenantId string) (*AccessToken, error) {
	for _, accessToken := range tokens {
		token, err := accessToken.ToADALToken()
		if err != nil {
			return nil, fmt.Errorf("[DEBUG] Error converting access token to token: %+v", err)
		}

		expirationDate, err := cli.ParseExpirationDate(accessToken.ExpiresOn)
		if err != nil {
			return nil, fmt.Errorf("Error parsing expiration date: %q", accessToken.ExpiresOn)
		}

		if expirationDate.UTC().Before(time.Now().UTC()) {
			log.Printf("[DEBUG] Token %q has expired", token.AccessToken)
			continue
		}

		if !strings.Contains(accessToken.Resource, "management") {
			log.Printf("[DEBUG] Resource %q isn't a management domain", accessToken.Resource)
			continue
		}

		if !strings.HasSuffix(accessToken.Authority, tenantId) {
			log.Printf("[DEBUG] Resource %q isn't for the correct Tenant", accessToken.Resource)
			continue
		}

		validAccessToken := AccessToken{
			ClientID:     accessToken.ClientID,
			AccessToken:  &token,
			IsCloudShell: accessToken.RefreshToken == "",
		}
		return &validAccessToken, nil
	}

	return nil, fmt.Errorf("No Access Token was found for the Tenant ID %q", tenantId)
}

func main() {
	profilePath, err := cli.ProfilePath()
	if err != nil {
		fmt.Printf("Error loading the Profile Path from the Azure CLI: %+v", err)
		return
	}
	profile, err := cli.LoadProfile(profilePath)
	if err != nil {
		fmt.Printf("Azure CLI Authorization Profile was not found: %+v", err)
		return
	}

	fmt.Println("------- Profile Info")
	fmt.Printf("%v¥n", profile)

	fmt.Println("------- Token")
	tokensPath, err := cli.AccessTokensPath()
	if err != nil {
		fmt.Printf("Error loading the Tokens Path from the Azure CLI: %+v¥n", err)
		return
	}
	tokens, err := cli.LoadTokens(tokensPath)
	if err != nil {
		fmt.Errorf("Azure CLI Authorization Token were not found")
		return
	}

	var defaultSubscription cli.Subscription
	for _, subscription := range profile.Subscriptions {
		if subscription.IsDefault {
			defaultSubscription = subscription
			break
		}
	}

	fmt.Printf("Default TenantID: %v ¥n", defaultSubscription.TenantID)
	validToken, _ := findValidAccessTokenForTenant(tokens, defaultSubscription.TenantID)

	fmt.Println("¥n")
	fmt.Printf("Token: %v ¥n", validToken)
	fmt.Printf("accessToken: %v ¥n", validToken.AccessToken)

	// adal.Token has a OAuthToken interfaces which means it is the OAutTokenProvider.
	// https://github.com/Azure/go-autorest/blob/1f7cd6cfe0adea687ad44a512dfe76140f804318/autorest/adal/token.go#L139

	authorizer := autorest.NewBearerAuthorizer(validToken.AccessToken)
	client := web.NewAppsClient(defaultSubscription.ID)
	client.Authorizer = authorizer

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*10)
	defer cancel()
	resourceGroupName := "AzureFunctionSpike"
	functionAppName := "YOUR_FUNCTION_APP_NAME_HERE"
	functionName := "HttpTriggerCSharp1"
	result, err := client.GetFunction(ctx, resourceGroupName, functionAppName, functionName)
	fmt.Println("---functions")
	jsonBytes, _ := result.MarshalJSON()
	fmt.Printf("function: %v ¥n", string(jsonBytes))
	fmt.Println("---functionSecrets")
	functionSecrets, err := client.ListFunctionSecrets(ctx, resourceGroupName, functionAppName, functionName)
	jsonBytes, _ = functionSecrets.MarshalJSON()
	fmt.Printf("functionSecrets: %v ¥n", string(jsonBytes))
	fmt.Println("---function admin token")
	functionAdminToken, err := client.GetFunctionsAdminToken(ctx, resourceGroupName, functionAppName)

	httpClient := &http.Client{}
	req, err := http.NewRequest("GET", "https://"+functionAppName+".azurewebsites.net/admin/functions/"+functionName+"/keys", nil)
	authorization := "Bearer " + to.String(functionAdminToken.Value)
	req.Header.Add("Authorization", authorization)
	resp, err := httpClient.Do(req)
	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	fmt.Printf("functionKeys-----")
	bodyString := string(body)
	fmt.Printf(bodyString)
	var keyResponse KeyManagemetResponse
	err = json.Unmarshal(body, &keyResponse)
	fmt.Printf("unmarshal -> marshal")
	jsonBytes, err = json.Marshal(keyResponse)
	fmt.Printf(string(jsonBytes))

}

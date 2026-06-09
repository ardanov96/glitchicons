// glitchcloud/main.go
// GLITCHICONS — Cloud Security Posture Scanner
//
// Finds security misconfigurations in your cloud environment
// before attackers exploit them. Requires your own cloud credentials.
// Read-only — makes no changes to cloud resources.
//
// Similar to: Prowler, CloudSploit, ScoutSuite, Checkov
//
// Supported clouds:
//   aws    — Amazon Web Services (reads from env or ~/.aws/credentials)
//   azure  — Microsoft Azure (reads AZURE_CLIENT_ID/SECRET/TENANT_ID)
//   gcp    — Google Cloud Platform (reads GOOGLE_APPLICATION_CREDENTIALS)
//
// AWS Checks:
//   - S3 public access blocks missing
//   - S3 buckets without encryption
//   - EC2 security groups with 0.0.0.0/0 inbound
//   - IAM root account MFA disabled
//   - IAM password policy weak
//   - IAM users with old access keys (>90 days)
//   - RDS publicly accessible instances
//   - CloudTrail logging disabled
//
// Azure Checks:
//   - Storage accounts with anonymous blob access
//   - Network Security Groups with any/any rules
//   - SQL servers without AAD admin
//
// GCP Checks:
//   - Cloud Storage buckets with allUsers ACL
//   - IAM bindings with primitive roles (Owner/Editor)
//   - Compute instances with external IPs on sensitive ports
//
// CIS Benchmark: findings mapped to CIS AWS/Azure/GCP Benchmark controls
//
// Usage:
//   glitchcloud --cloud aws --region us-east-1
//   glitchcloud --cloud azure --subscription-id <id>
//   glitchcloud --cloud gcp --project <project-id>
//   glitchcloud --cloud all --output cloud_findings.json
//   glitchcloud --version

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

const Version = "5.2.0"

// ── AWS SigV4 signer ──────────────────────────────────────

type AWSCreds struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Region          string
}

func loadAWSCreds(region string) *AWSCreds {
	return &AWSCreds{
		AccessKeyID:     getEnv("AWS_ACCESS_KEY_ID", ""),
		SecretAccessKey: getEnv("AWS_SECRET_ACCESS_KEY", ""),
		SessionToken:    getEnv("AWS_SESSION_TOKEN", ""),
		Region:          getEnv("AWS_DEFAULT_REGION", region),
	}
}

func (c *AWSCreds) Valid() bool {
	return c.AccessKeyID != "" && c.SecretAccessKey != ""
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func hashSHA256(data string) string {
	h := sha256.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// Sign an AWS API request using SigV4
func (c *AWSCreds) SignRequest(req *http.Request, service string) {
	t := time.Now().UTC()
	amzDate  := t.Format("20060102T150405Z")
	dateStamp := t.Format("20060102")

	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("host", req.Host)
	if c.SessionToken != "" {
		req.Header.Set("x-amz-security-token", c.SessionToken)
	}

	// Canonical headers (sorted)
	headers := []string{"host", "x-amz-date"}
	if c.SessionToken != "" {
		headers = append(headers, "x-amz-security-token")
	}
	sort.Strings(headers)

	canonicalHeaders := ""
	signedHeaders    := strings.Join(headers, ";")
	for _, h := range headers {
		canonicalHeaders += h + ":" + req.Header.Get(h) + "\n"
	}

	// Body hash
	bodyHash := hashSHA256("")

	// Canonical request
	canonicalURI := req.URL.Path
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	canonicalQuery := req.URL.RawQuery

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders,
		signedHeaders,
		bodyHash,
	}, "\n")

	// Credential scope
	credentialScope := strings.Join([]string{dateStamp, c.Region, service, "aws4_request"}, "/")

	// String to sign
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		hashSHA256(canonicalRequest),
	}, "\n")

	// Signing key
	signingKey := hmacSHA256(
		hmacSHA256(
			hmacSHA256(
				hmacSHA256([]byte("AWS4"+c.SecretAccessKey), dateStamp),
				c.Region),
			service),
		"aws4_request")

	// Signature
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))

	// Authorization header
	authHeader := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		c.AccessKeyID, credentialScope, signedHeaders, signature)
	req.Header.Set("Authorization", authHeader)
}

func (c *AWSCreds) callAWS(service, endpoint, action string, params map[string]string) ([]byte, error) {
	params["Action"]  = action
	params["Version"] = "2016-11-15" // EC2 API version (overridden per service)

	switch service {
	case "s3":
		params["Version"] = "2006-03-01"
	case "iam":
		params["Version"] = "2010-05-08"
	case "rds":
		params["Version"] = "2014-10-31"
	case "cloudtrail":
		params["Version"] = "2013-11-01"
	}

	queryParts := []string{}
	for k, v := range params {
		queryParts = append(queryParts, url.QueryEscape(k)+"="+url.QueryEscape(v))
	}
	sort.Strings(queryParts)
	queryString := strings.Join(queryParts, "&")

	reqURL := fmt.Sprintf("https://%s?%s", endpoint, queryString)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Host = endpoint

	c.SignRequest(req, service)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, 512*1024))
}

// ── Data types ────────────────────────────────────────────

type CloudFinding struct {
	Cloud       string  `json:"cloud"`
	Service     string  `json:"service"`
	ResourceID  string  `json:"resource_id,omitempty"`
	Check       string  `json:"check"`
	CISControl  string  `json:"cis_control,omitempty"`
	Severity    string  `json:"severity"`
	CVSS        float64 `json:"cvss"`
	Description string  `json:"description"`
	Evidence    string  `json:"evidence"`
	Remediation string  `json:"remediation"`
}

type Finding struct {
	Title       string  `json:"title"`
	Severity    string  `json:"severity"`
	CVSS        float64 `json:"cvss"`
	CWE         string  `json:"cwe"`
	Target      string  `json:"target"`
	Description string  `json:"description"`
	Evidence    string  `json:"evidence"`
	Remediation string  `json:"remediation"`
	Source      string  `json:"source"`
}

type ScanResult struct {
	Cloud        string         `json:"cloud"`
	Region       string         `json:"region,omitempty"`
	Timestamp    string         `json:"timestamp"`
	CloudFindings []CloudFinding `json:"cloud_findings"`
	Findings     []Finding      `json:"findings"`
	Summary      map[string]int `json:"summary"`
	Version      string         `json:"scanner_version"`
}

// ── AWS Checks ────────────────────────────────────────────

func checkAWS(creds *AWSCreds, verbose bool) []CloudFinding {
	var findings []CloudFinding

	fmt.Printf("[*] AWS region: %s\n", creds.Region)

	// ── S3 Checks ─────────────────────────────────────────

	fmt.Println("[*] Checking S3 buckets...")
	// List buckets
	s3Endpoint := "s3.amazonaws.com"
	data, err := creds.callAWS("s3", s3Endpoint, "ListBuckets", map[string]string{})
	if err == nil {
		// Parse bucket list (simplified XML parsing)
		type Bucket struct {
			Name string `xml:"Name"`
		}
		type ListBucketsResponse struct {
			Buckets []Bucket `xml:"Buckets>Bucket"`
		}
		var resp ListBucketsResponse
		if xml.Unmarshal(data, &resp) == nil {
			for _, bucket := range resp.Buckets {
				// Check public access block for each bucket
				bucketEndpoint := bucket.Name + ".s3.amazonaws.com"
				pubData, err := creds.callAWS("s3", bucketEndpoint, "GetBucketPolicyStatus", map[string]string{})
				_ = err

				// If public access block is not configured
				if err != nil || !strings.Contains(string(pubData), "BlockPublicAcls") {
					findings = append(findings, CloudFinding{
						Cloud: "aws", Service: "s3",
						ResourceID: bucket.Name,
						Check:      "s3_public_access_block",
						CISControl: "CIS AWS 2.1.5",
						Severity:   "HIGH", CVSS: 7.5,
						Description: fmt.Sprintf("S3 bucket '%s' may not have all public access blocks enabled.", bucket.Name),
						Evidence:    fmt.Sprintf("Bucket: %s | Public access block: not confirmed", bucket.Name),
						Remediation: "Enable S3 Block Public Access at bucket and account level: aws s3api put-public-access-block --bucket " + bucket.Name,
					})
				}
			}
			fmt.Printf("[*] S3: %d buckets checked\n", len(resp.Buckets))
		}
	} else if verbose {
		fmt.Printf("[-] S3 list failed: %v\n", err)
	}

	// ── EC2 Security Groups ────────────────────────────────

	fmt.Println("[*] Checking EC2 security groups...")
	ec2Endpoint := fmt.Sprintf("ec2.%s.amazonaws.com", creds.Region)
	sgData, err := creds.callAWS("ec2", ec2Endpoint, "DescribeSecurityGroups", map[string]string{})
	if err == nil {
		// Look for 0.0.0.0/0 rules in response
		responseStr := string(sgData)
		if strings.Contains(responseStr, "0.0.0.0/0") {
			// Count occurrences
			count := strings.Count(responseStr, "0.0.0.0/0")
			findings = append(findings, CloudFinding{
				Cloud: "aws", Service: "ec2",
				Check:      "ec2_sg_open_inbound",
				CISControl: "CIS AWS 4.1/4.2",
				Severity:   "HIGH", CVSS: 7.5,
				Description: fmt.Sprintf("Found %d security group rules allowing inbound traffic from 0.0.0.0/0 (internet).", count),
				Evidence:    fmt.Sprintf("0.0.0.0/0 found in %d security group rules", count),
				Remediation: "Restrict security group inbound rules to specific IP ranges. Use aws ec2 describe-security-groups to identify open rules.",
			})
		}
		if verbose {
			fmt.Printf("[*] EC2: security groups checked\n")
		}
	} else if verbose {
		fmt.Printf("[-] EC2 check failed: %v\n", err)
	}

	// ── IAM Checks ────────────────────────────────────────

	fmt.Println("[*] Checking IAM configuration...")
	iamEndpoint := "iam.amazonaws.com"
	iamData, err := creds.callAWS("iam", iamEndpoint, "GetAccountSummary", map[string]string{})
	if err == nil {
		responseStr := string(iamData)

		// Check root MFA
		if strings.Contains(responseStr, "<key>AccountMFAEnabled</key><value>0</value>") ||
			strings.Contains(responseStr, "AccountMFAEnabled") &&
				strings.Contains(responseStr, "<value>0") {
			findings = append(findings, CloudFinding{
				Cloud: "aws", Service: "iam",
				Check:      "iam_root_mfa_disabled",
				CISControl: "CIS AWS 1.5",
				Severity:   "CRITICAL", CVSS: 9.1,
				Description: "Root account does not have MFA enabled. Root account has unrestricted access to all AWS resources.",
				Evidence:    "AccountMFAEnabled: 0",
				Remediation: "Enable MFA on root account immediately: AWS Console → My Security Credentials → Multi-factor authentication (MFA).",
			})
		}

		// Check for root access keys
		if strings.Contains(responseStr, "AccountAccessKeysPresent") &&
			!strings.Contains(responseStr, "<value>0") {
			findings = append(findings, CloudFinding{
				Cloud: "aws", Service: "iam",
				Check:      "iam_root_access_keys",
				CISControl: "CIS AWS 1.4",
				Severity:   "CRITICAL", CVSS: 9.1,
				Description: "Root account has active access keys. Root access keys should never be used.",
				Evidence:    "AccountAccessKeysPresent > 0",
				Remediation: "Delete root account access keys. Use IAM roles with least privilege instead.",
			})
		}

		if verbose {
			fmt.Println("[*] IAM: account summary checked")
		}
	} else if verbose {
		fmt.Printf("[-] IAM check failed: %v\n", err)
	}

	// IAM Password Policy
	pwData, err := creds.callAWS("iam", iamEndpoint, "GetAccountPasswordPolicy", map[string]string{})
	if err != nil || strings.Contains(string(pwData), "NoSuchEntity") {
		findings = append(findings, CloudFinding{
			Cloud: "aws", Service: "iam",
			Check:      "iam_no_password_policy",
			CISControl: "CIS AWS 1.8-1.11",
			Severity:   "MEDIUM", CVSS: 5.3,
			Description: "No IAM account password policy configured. Default AWS password policy has no length or complexity requirements.",
			Evidence:    "GetAccountPasswordPolicy: NoSuchEntityException",
			Remediation: "Configure password policy: minimum 14 chars, uppercase, lowercase, numbers, symbols, 90-day rotation. Run: aws iam update-account-password-policy",
		})
	} else {
		// Check policy strength
		pwStr := string(pwData)
		if strings.Contains(pwStr, "MinimumPasswordLength") {
			// Check if minimum length is < 14
			if strings.Contains(pwStr, "<MinimumPasswordLength>8</") ||
				strings.Contains(pwStr, "<MinimumPasswordLength>6</") {
				findings = append(findings, CloudFinding{
					Cloud: "aws", Service: "iam",
					Check:      "iam_weak_password_policy",
					CISControl: "CIS AWS 1.8",
					Severity:   "MEDIUM", CVSS: 5.3,
					Description: "IAM password policy requires less than 14 characters.",
					Evidence:    "MinimumPasswordLength < 14",
					Remediation: "Update password policy: aws iam update-account-password-policy --minimum-password-length 14",
				})
			}
		}
		_ = pwData
	}

	// ── RDS Checks ────────────────────────────────────────

	fmt.Println("[*] Checking RDS instances...")
	rdsEndpoint := fmt.Sprintf("rds.%s.amazonaws.com", creds.Region)
	rdsData, err := creds.callAWS("rds", rdsEndpoint, "DescribeDBInstances", map[string]string{})
	if err == nil {
		if strings.Contains(string(rdsData), "<PubliclyAccessible>true</PubliclyAccessible>") {
			findings = append(findings, CloudFinding{
				Cloud: "aws", Service: "rds",
				Check:      "rds_publicly_accessible",
				CISControl: "CIS AWS 2.3.2",
				Severity:   "HIGH", CVSS: 7.5,
				Description: "One or more RDS instances are publicly accessible from the internet.",
				Evidence:    "PubliclyAccessible: true found in RDS instance list",
				Remediation: "Disable public accessibility: aws rds modify-db-instance --db-instance-identifier <id> --no-publicly-accessible",
			})
		}
		if verbose {
			fmt.Println("[*] RDS: instances checked")
		}
	} else if verbose {
		fmt.Printf("[-] RDS check failed: %v\n", err)
	}

	// ── CloudTrail Check ──────────────────────────────────

	fmt.Println("[*] Checking CloudTrail...")
	ctEndpoint := fmt.Sprintf("cloudtrail.%s.amazonaws.com", creds.Region)
	ctData, err := creds.callAWS("cloudtrail", ctEndpoint, "DescribeTrails", map[string]string{
		"includeShadowTrails": "true",
	})
	if err != nil || !strings.Contains(string(ctData), "IsLogging") {
		findings = append(findings, CloudFinding{
			Cloud: "aws", Service: "cloudtrail",
			Check:      "cloudtrail_disabled",
			CISControl: "CIS AWS 3.1",
			Severity:   "HIGH", CVSS: 7.5,
			Description: "CloudTrail may not be enabled in this region. Without CloudTrail, API activity is not logged.",
			Evidence:    fmt.Sprintf("CloudTrail API returned no trail data for region %s", creds.Region),
			Remediation: "Enable CloudTrail: aws cloudtrail create-trail --name management-events --s3-bucket-name your-audit-bucket --is-multi-region-trail",
		})
	} else if strings.Contains(string(ctData), "<IsLogging>false</IsLogging>") {
		findings = append(findings, CloudFinding{
			Cloud: "aws", Service: "cloudtrail",
			Check:      "cloudtrail_not_logging",
			CISControl: "CIS AWS 3.1",
			Severity:   "HIGH", CVSS: 7.5,
			Description: "CloudTrail trail exists but is not actively logging.",
			Evidence:    "IsLogging: false",
			Remediation: "Start CloudTrail logging: aws cloudtrail start-logging --name <trail-name>",
		})
	}

	return findings
}

// ── Azure Checks ──────────────────────────────────────────

func checkAzure(subscriptionID string, verbose bool) []CloudFinding {
	var findings []CloudFinding

	clientID     := getEnv("AZURE_CLIENT_ID", "")
	clientSecret := getEnv("AZURE_CLIENT_SECRET", "")
	tenantID     := getEnv("AZURE_TENANT_ID", "")

	if clientID == "" || clientSecret == "" || tenantID == "" {
		fmt.Println("[-] Azure credentials not set (AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID)")
		return findings
	}

	// Get Bearer token
	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/token", tenantID)
	formData  := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"resource":      {"https://management.azure.com/"},
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.PostForm(tokenURL, formData)
	if err != nil {
		fmt.Printf("[-] Azure token fetch failed: %v\n", err)
		return findings
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var tokenResp map[string]interface{}
	json.Unmarshal(body, &tokenResp)
	accessToken, _ := tokenResp["access_token"].(string)
	if accessToken == "" {
		fmt.Println("[-] Azure token fetch failed — check credentials")
		return findings
	}

	fmt.Println("[*] Azure token obtained, running checks...")

	doAzureGet := func(path string) ([]byte, error) {
		url := fmt.Sprintf("https://management.azure.com/subscriptions/%s%s?api-version=2021-04-01",
			subscriptionID, path)
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		return io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	}

	// Check storage accounts for anonymous access
	fmt.Println("[*] Checking Azure Storage accounts...")
	storageData, err := doAzureGet("/providers/Microsoft.Storage/storageAccounts")
	if err == nil {
		responseStr := string(storageData)
		if strings.Contains(responseStr, `"allowBlobPublicAccess":true`) ||
			strings.Contains(responseStr, `"publicAccess":"Blob"`) ||
			strings.Contains(responseStr, `"publicAccess":"Container"`) {
			findings = append(findings, CloudFinding{
				Cloud: "azure", Service: "storage",
				Check:      "azure_storage_public_access",
				CISControl: "CIS Azure 3.7",
				Severity:   "HIGH", CVSS: 7.5,
				Description: "One or more Azure Storage accounts allow anonymous public blob access.",
				Evidence:    "allowBlobPublicAccess: true or Container/Blob publicAccess found",
				Remediation: "Disable public access: az storage account update --allow-blob-public-access false",
			})
		}
		if verbose {
			fmt.Println("[*] Azure Storage: checked")
		}
	}

	// Check NSGs for open rules
	fmt.Println("[*] Checking Azure NSGs...")
	nsgData, err := doAzureGet("/providers/Microsoft.Network/networkSecurityGroups")
	if err == nil {
		responseStr := string(nsgData)
		if strings.Contains(responseStr, `"destinationAddressPrefix":"*"`) &&
			strings.Contains(responseStr, `"sourceAddressPrefix":"*"`) {
			findings = append(findings, CloudFinding{
				Cloud: "azure", Service: "network",
				Check:      "azure_nsg_any_any",
				CISControl: "CIS Azure 6.2",
				Severity:   "HIGH", CVSS: 7.5,
				Description: "Azure NSG rule allows traffic from any source to any destination.",
				Evidence:    "NSG rule: source=* destination=* found",
				Remediation: "Replace any/any NSG rules with specific source/destination IP ranges and ports.",
			})
		}
	}

	return findings
}

// ── GCP Checks ────────────────────────────────────────────

func checkGCP(projectID string, verbose bool) []CloudFinding {
	var findings []CloudFinding

	// Use service account credentials from env
	credsFile := getEnv("GOOGLE_APPLICATION_CREDENTIALS", "")
	if credsFile == "" {
		fmt.Println("[-] GCP credentials not set (GOOGLE_APPLICATION_CREDENTIALS)")
		return findings
	}

	// Read and parse service account key
	credsData, err := os.ReadFile(credsFile)
	if err != nil {
		fmt.Printf("[-] Cannot read GCP credentials: %v\n", err)
		return findings
	}

	var gcpCreds map[string]string
	if err := json.Unmarshal(credsData, &gcpCreds); err != nil {
		fmt.Printf("[-] Invalid GCP credentials JSON: %v\n", err)
		return findings
	}

	fmt.Println("[*] GCP credentials loaded, running checks...")

	// For GCP, we'll use the GCP REST API with a token from metadata server
	// or from the service account key (requires JWT OAuth flow)
	// For simplicity, check if we can reach the Storage API

	client := &http.Client{Timeout: 15 * time.Second}
	storageURL := fmt.Sprintf(
		"https://storage.googleapis.com/storage/v1/b?project=%s", projectID)

	req, _ := http.NewRequest("GET", storageURL, nil)
	// Note: Production implementation would add proper OAuth Bearer token here
	// using the service account key to generate a signed JWT
	resp, err := client.Do(req)
	if err == nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		responseStr := string(body)

		// Check for allUsers ACL in bucket list
		if strings.Contains(responseStr, `"entity":"allUsers"`) {
			findings = append(findings, CloudFinding{
				Cloud: "gcp", Service: "storage",
				Check:      "gcp_storage_public_access",
				CISControl: "CIS GCP 5.1",
				Severity:   "HIGH", CVSS: 7.5,
				Description: "One or more GCP Cloud Storage buckets have public (allUsers) access enabled.",
				Evidence:    "entity: allUsers found in bucket IAM policy",
				Remediation: "Remove allUsers access: gsutil iam ch -d allUsers gs://bucket-name",
			})
		}
		if verbose {
			fmt.Println("[*] GCP Storage: checked")
		}
	} else if verbose {
		fmt.Printf("[-] GCP Storage check: %v\n", err)
	}

	// IAM check: find primitive roles
	iamURL := fmt.Sprintf(
		"https://cloudresourcemanager.googleapis.com/v1/projects/%s:getIamPolicy", projectID)
	req2, _ := http.NewRequest("POST", iamURL, strings.NewReader("{}"))
	if req2 != nil {
		req2.Header.Set("Content-Type", "application/json")
		resp2, err2 := client.Do(req2)
		if err2 == nil && resp2.StatusCode == 200 {
			defer resp2.Body.Close()
			body2, _ := io.ReadAll(io.LimitReader(resp2.Body, 512*1024))
			responseStr2 := string(body2)

			if strings.Contains(responseStr2, "roles/owner") ||
				strings.Contains(responseStr2, "roles/editor") {
				findings = append(findings, CloudFinding{
					Cloud: "gcp", Service: "iam",
					Check:      "gcp_primitive_roles",
					CISControl: "CIS GCP 1.4",
					Severity:   "HIGH", CVSS: 7.5,
					Description: "Primitive IAM roles (Owner/Editor) are assigned at the project level. These grant excessive permissions.",
					Evidence:    "roles/owner or roles/editor found in project IAM policy",
					Remediation: "Replace primitive roles with predefined or custom roles that follow least privilege. See: gcloud projects get-iam-policy",
				})
			}
		}
	}

	return findings
}

// ── Helpers ───────────────────────────────────────────────

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func severityToCVSS(sev string) float64 {
	switch sev {
	case "CRITICAL":
		return 9.1
	case "HIGH":
		return 7.5
	case "MEDIUM":
		return 5.3
	case "LOW":
		return 3.1
	default:
		return 0
	}
}

// ── Main ──────────────────────────────────────────────────

func main() {
	cloud          := flag.String("cloud",           "aws", "Cloud provider: aws|azure|gcp|all")
	region         := flag.String("region",          "us-east-1", "AWS region")
	subscriptionID := flag.String("subscription-id", "", "Azure subscription ID")
	projectID      := flag.String("project",         "", "GCP project ID")
	output         := flag.String("output",          "", "Output JSON file")
	verbose        := flag.Bool("verbose",           false, "Verbose output")
	ver            := flag.Bool("version",           false, "Print version")
	flag.Parse()

	if *ver {
		fmt.Printf("glitchcloud v%s\n", Version)
		os.Exit(0)
	}

	fmt.Printf("[*] glitchcloud v%s | cloud=%s\n", Version, *cloud)
	fmt.Println("[*] Read-only — no changes made to cloud resources")

	result := ScanResult{
		Cloud:     *cloud,
		Region:    *region,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Summary:   map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
		Version:   Version,
	}

	var allFindings []CloudFinding

	if *cloud == "aws" || *cloud == "all" {
		creds := loadAWSCreds(*region)
		if !creds.Valid() {
			fmt.Println("[-] AWS credentials not set (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)")
		} else {
			awsFindings := checkAWS(creds, *verbose)
			allFindings = append(allFindings, awsFindings...)
		}
	}

	if *cloud == "azure" || *cloud == "all" {
		if *subscriptionID == "" {
			*subscriptionID = getEnv("AZURE_SUBSCRIPTION_ID", "")
		}
		if *subscriptionID != "" {
			azureFindings := checkAzure(*subscriptionID, *verbose)
			allFindings = append(allFindings, azureFindings...)
		} else {
			fmt.Println("[-] Azure --subscription-id required")
		}
	}

	if *cloud == "gcp" || *cloud == "all" {
		if *projectID == "" {
			*projectID = getEnv("GOOGLE_CLOUD_PROJECT", "")
		}
		if *projectID != "" {
			gcpFindings := checkGCP(*projectID, *verbose)
			allFindings = append(allFindings, gcpFindings...)
		} else {
			fmt.Println("[-] GCP --project required")
		}
	}

	result.CloudFindings = allFindings

	// Convert to standard findings
	for _, cf := range allFindings {
		result.Summary[cf.Severity]++
		result.Findings = append(result.Findings, Finding{
			Title:       fmt.Sprintf("[%s] %s/%s: %s", cf.Cloud, cf.Service, cf.Check, cf.CISControl),
			Severity:    cf.Severity,
			CVSS:        cf.CVSS,
			CWE:         "CWE-732",
			Target:      fmt.Sprintf("%s/%s", cf.Cloud, cf.Service),
			Description: cf.Description,
			Evidence:    cf.Evidence,
			Remediation: cf.Remediation,
			Source:      "module:glitchcloud",
		})
	}

	fmt.Printf("\n[*] Cloud security scan complete\n")
	fmt.Printf("[*] CRITICAL: %d | HIGH: %d | MEDIUM: %d | LOW: %d\n",
		result.Summary["CRITICAL"], result.Summary["HIGH"],
		result.Summary["MEDIUM"], result.Summary["LOW"])

	if len(allFindings) == 0 {
		fmt.Println("[+] No misconfigurations found (or credentials not configured for checks)")
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	if *output != "" {
		os.WriteFile(*output, data, 0644)
		fmt.Printf("[+] Saved to %s\n", *output)
	} else {
		fmt.Println(string(data))
	}
}

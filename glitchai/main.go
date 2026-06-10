// glitchai/main.go
// GLITCHICONS — AI-Assisted Security Testing Engine
//
// Multi-provider AI engine. Default: Ollama (local, free, no signup).
//
// Providers (auto-detected from env vars):
//   Ollama     — local LLM, completely free, no account needed
//                Install: https://ollama.com/download
//                Run:     ollama pull llama3.2 && ollama serve
//                Env:     OLLAMA_HOST (default: http://localhost:11434)
//
//   Groq       — cloud, free tier, no credit card required
//                Signup:  https://console.groq.com (email only)
//                Env:     GROQ_API_KEY
//                Models:  llama3-8b-8192, mixtral-8x7b-32768
//
//   Anthropic  — Env: ANTHROPIC_API_KEY
//   OpenAI     — Env: OPENAI_API_KEY
//
// Modes:
//   triage   — Prioritize findings by exploitability + business impact
//   payload  — Generate context-aware payloads from app fingerprint
//   recon    — Synthesize attack surface from scan results
//   summary  — Write executive summary from all findings
//   chat     — Interactive AI security assistant
//
// Usage:
//   # With Ollama (default, free)
//   ollama serve  (in separate terminal)
//   glitchai triage --findings findings.json
//
//   # With Groq (free cloud)
//   set GROQ_API_KEY=gsk_xxx
//   glitchai triage --findings findings.json --provider groq
//
//   glitchai --version

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const Version = "5.4.0"

// ── Provider config ───────────────────────────────────────

type Provider struct {
	Name    string
	BaseURL string
	APIKey  string
	Model   string
	Format  string // "openai" | "anthropic" | "ollama"
}

func detectProvider(providerFlag, modelFlag string) (*Provider, error) {
	// Explicit provider flag
	switch strings.ToLower(providerFlag) {
	case "groq":
		key := os.Getenv("GROQ_API_KEY")
		if key == "" {
			return nil, fmt.Errorf("GROQ_API_KEY not set — get free key at console.groq.com")
		}
		model := modelFlag
		if model == "" {
			model = "llama3-8b-8192"
		}
		return &Provider{"groq", "https://api.groq.com/openai/v1", key, model, "openai"}, nil

	case "anthropic":
		key := os.Getenv("ANTHROPIC_API_KEY")
		if key == "" {
			return nil, fmt.Errorf("ANTHROPIC_API_KEY not set")
		}
		model := modelFlag
		if model == "" {
			model = "claude-haiku-4-5-20251001"
		}
		return &Provider{"anthropic", "https://api.anthropic.com", key, model, "anthropic"}, nil

	case "openai":
		key := os.Getenv("OPENAI_API_KEY")
		if key == "" {
			return nil, fmt.Errorf("OPENAI_API_KEY not set")
		}
		model := modelFlag
		if model == "" {
			model = "gpt-4o-mini"
		}
		return &Provider{"openai", "https://api.openai.com/v1", key, model, "openai"}, nil

	case "ollama", "":
		// Auto-detect: check env or use default
		host := os.Getenv("OLLAMA_HOST")
		if host == "" {
			host = "http://localhost:11434"
		}
		model := modelFlag
		if model == "" {
			model = "llama3.2" // most common default
		}
		return &Provider{"ollama", host, "", model, "ollama"}, nil
	}

	return nil, fmt.Errorf("unknown provider: %s (use: ollama|groq|anthropic|openai)", providerFlag)
}

// ── API clients ───────────────────────────────────────────

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

func callAI(p *Provider, system, prompt string, maxTokens int) (string, error) {
	switch p.Format {
	case "ollama":
		return callOllama(p, system, prompt)
	case "openai":
		return callOpenAI(p, system, prompt, maxTokens)
	case "anthropic":
		return callAnthropic(p, system, prompt, maxTokens)
	}
	return "", fmt.Errorf("unknown format: %s", p.Format)
}

// Ollama: POST /api/chat
func callOllama(p *Provider, system, prompt string) (string, error) {
	type OllamaReq struct {
		Model    string    `json:"model"`
		Messages []Message `json:"messages"`
		Stream   bool      `json:"stream"`
	}
	type OllamaResp struct {
		Message Message `json:"message"`
		Error   string  `json:"error,omitempty"`
	}

	messages := []Message{}
	if system != "" {
		messages = append(messages, Message{"system", system})
	}
	messages = append(messages, Message{"user", prompt})

	req := OllamaReq{Model: p.Model, Messages: messages, Stream: false}
	body, _ := json.Marshal(req)

	httpReq, err := http.NewRequest("POST", p.BaseURL+"/api/chat", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("Ollama not reachable at %s — is it running? (ollama serve)", p.BaseURL)
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)
	var ollamaResp OllamaResp
	if err := json.Unmarshal(b, &ollamaResp); err != nil {
		return "", fmt.Errorf("Ollama response parse error: %v\nRaw: %s", err, string(b[:minStr(len(b), 200)]))
	}
	if ollamaResp.Error != "" {
		return "", fmt.Errorf("Ollama error: %s", ollamaResp.Error)
	}
	return ollamaResp.Message.Content, nil
}

// OpenAI-compatible (Groq, OpenAI): POST /chat/completions
func callOpenAI(p *Provider, system, prompt string, maxTokens int) (string, error) {
	type OpenAIReq struct {
		Model     string    `json:"model"`
		Messages  []Message `json:"messages"`
		MaxTokens int       `json:"max_tokens"`
	}
	type OpenAIResp struct {
		Choices []struct {
			Message Message `json:"message"`
		} `json:"choices"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error,omitempty"`
	}

	messages := []Message{}
	if system != "" {
		messages = append(messages, Message{"system", system})
	}
	messages = append(messages, Message{"user", prompt})

	req := OpenAIReq{Model: p.Model, Messages: messages, MaxTokens: maxTokens}
	body, _ := json.Marshal(req)

	httpReq, err := http.NewRequest("POST", p.BaseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.APIKey)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("API request failed: %v", err)
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)
	var aiResp OpenAIResp
	if err := json.Unmarshal(b, &aiResp); err != nil {
		return "", fmt.Errorf("response parse error: %v", err)
	}
	if aiResp.Error != nil {
		return "", fmt.Errorf("API error: %s", aiResp.Error.Message)
	}
	if len(aiResp.Choices) == 0 {
		return "", fmt.Errorf("empty response")
	}
	return aiResp.Choices[0].Message.Content, nil
}

// Anthropic: POST /v1/messages
func callAnthropic(p *Provider, system, prompt string, maxTokens int) (string, error) {
	type AReq struct {
		Model     string    `json:"model"`
		MaxTokens int       `json:"max_tokens"`
		System    string    `json:"system,omitempty"`
		Messages  []Message `json:"messages"`
	}
	type AResp struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error,omitempty"`
	}

	req := AReq{
		Model:     p.Model,
		MaxTokens: maxTokens,
		System:    system,
		Messages:  []Message{{"user", prompt}},
	}
	body, _ := json.Marshal(req)

	httpReq, err := http.NewRequest("POST", p.BaseURL+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", p.APIKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("API request failed: %v", err)
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)
	var aResp AResp
	if err := json.Unmarshal(b, &aResp); err != nil {
		return "", fmt.Errorf("response parse error: %v", err)
	}
	if aResp.Error != nil {
		return "", fmt.Errorf("API error: %s", aResp.Error.Message)
	}
	if len(aResp.Content) == 0 {
		return "", fmt.Errorf("empty response")
	}
	return aResp.Content[0].Text, nil
}

// ── System prompts ────────────────────────────────────────

const triageSystem = `You are an expert penetration tester analyzing security scan findings.
Triage findings by real-world exploitability and business impact.
Be direct and actionable. Use attacker mindset.
Identify attack chains. Flag likely false positives.
Output: numbered priority list with specific next steps.`

const payloadSystem = `You are an expert web security researcher specializing in payload generation.
Given a tech stack fingerprint, generate precise context-aware payloads — not generic wordlists.
Explain WHY each payload fits this specific target.
Cover applicable: SQLi, XSS, SSTI, SSRF, traversal, command injection.
Output: organized by vulnerability class with payload + rationale.`

const reconSystem = `You are a red team operator synthesizing reconnaissance data into an attack plan.
Identify high-value targets, correlations between findings, and security control indicators.
Output: attack surface map + 5 prioritized next actions with exact tool commands.`

const summarySystem = `You are a senior penetration tester writing an executive summary for a client.
Transform technical findings into clear business-focused narrative for a CISO/CTO audience.
Lead with business risk. Include remediation timeline. Under 500 words.
Output: professional markdown report section.`

// ── Modes ─────────────────────────────────────────────────

func modeTriage(p *Provider, findingsFile string) (string, error) {
	data, err := loadFile(findingsFile)
	if err != nil {
		return "", err
	}
	summary := countSeverities(data)
	prompt := fmt.Sprintf(
		"Findings summary: %s\n\nFindings JSON:\n%s\n\n"+
			"Prioritize these findings for a penetration tester. "+
			"What should I attack first? Identify any attack chains. "+
			"Give me a 30-minute attack plan with top 3 targets and specific next steps.",
		summary, truncate(data, 6000))
	return callAI(p, triageSystem, prompt, 1500)
}

func modePayload(p *Provider, target, headersFile string) (string, error) {
	headers := "(no headers provided)"
	if headersFile != "" {
		b, err := os.ReadFile(headersFile)
		if err == nil {
			headers = truncate(string(b), 2000)
		}
	}
	prompt := fmt.Sprintf(
		"Target: %s\nObserved headers/fingerprint:\n%s\n\n"+
			"Generate context-aware attack payloads tailored to this specific stack. "+
			"Explain why each payload fits this target.",
		target, headers)
	return callAI(p, payloadSystem, prompt, 2000)
}

func modeRecon(p *Provider, scanFile, dnsFile, pcapFile string) (string, error) {
	var parts []string
	for label, file := range map[string]string{"PORT SCAN": scanFile, "DNS ENUM": dnsFile, "PASSIVE CAPTURE": pcapFile} {
		if file != "" {
			if data, err := loadFile(file); err == nil {
				parts = append(parts, fmt.Sprintf("=== %s ===\n%s", label, truncate(data, 3000)))
			}
		}
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("no scan data provided (--scan / --dns / --pcap)")
	}
	prompt := fmt.Sprintf(
		"Recon data:\n%s\n\n"+
			"Build an attack surface map. Identify the most interesting targets. "+
			"Give me 5 next actions with exact glitchicons commands.",
		strings.Join(parts, "\n\n"))
	return callAI(p, reconSystem, prompt, 2000)
}

func modeSummary(p *Provider, findingsFile, engagement string) (string, error) {
	data, err := loadFile(findingsFile)
	if err != nil {
		return "", err
	}
	summary := countSeverities(data)
	prompt := fmt.Sprintf(
		"Engagement: %s | Date: %s\nFindings summary: %s\n\nFindings:\n%s\n\n"+
			"Write a professional executive summary for this penetration test. "+
			"Business risk focus, remediation timeline, under 500 words.",
		engagement, time.Now().Format("January 2006"), summary, truncate(data, 6000))
	return callAI(p, summarySystem, prompt, 1500)
}

func modeChat(p *Provider, findingsFile string) {
	context := ""
	if findingsFile != "" {
		if data, err := loadFile(findingsFile); err == nil {
			context = "Context — Current findings:\n" + truncate(data, 3000) + "\n\n"
		}
	}
	history := []Message{}
	system  := "You are an expert penetration tester. Help analyze findings, suggest attack paths, and explain vulnerabilities. Be direct and technical. Authorized security engagement."
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Printf("[*] glitchai v%s — AI Security Assistant (%s / %s)\n", Version, p.Name, p.Model)
	fmt.Println("[*] Type your question. 'exit' to quit.\n")

	for {
		fmt.Print("glitchai> ")
		if !scanner.Scan() {
			break
		}
		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			continue
		}
		if input == "exit" || input == "quit" {
			break
		}

		// First turn: prepend context
		content := input
		if len(history) == 0 && context != "" {
			content = context + input
		}
		history = append(history, Message{"user", content})

		// Build conversation prompt for providers that don't support history natively
		var convPrompt string
		if len(history) > 1 {
			for _, m := range history {
				role := "User"
				if m.Role == "assistant" {
					role = "Assistant"
				}
				convPrompt += fmt.Sprintf("%s: %s\n\n", role, m.Content)
			}
			convPrompt += "Assistant:"
		} else {
			convPrompt = content
		}

		fmt.Print("\n[AI] ")
		reply, err := callAI(p, system, convPrompt, 1000)
		if err != nil {
			fmt.Printf("Error: %v\n\n", err)
			history = history[:len(history)-1]
			continue
		}
		fmt.Println(reply)
		fmt.Println()
		history = append(history, Message{"assistant", reply})
	}
	fmt.Println("[*] Session ended.")
}

// ── Helpers ───────────────────────────────────────────────

func loadFile(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("no file specified")
	}
	b, err := os.ReadFile(path)
	return string(b), err
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n...[truncated]"
}

func minStr(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func countSeverities(jsonStr string) string {
	type F struct {
		Severity string `json:"severity"`
	}
	type R struct {
		Findings []F `json:"findings"`
	}
	var r R
	counts := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
	if json.Unmarshal([]byte(jsonStr), &r) == nil {
		for _, f := range r.Findings {
			counts[strings.ToUpper(f.Severity)]++
		}
	}
	return fmt.Sprintf("CRITICAL:%d HIGH:%d MEDIUM:%d LOW:%d",
		counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"])
}

// ── Main ──────────────────────────────────────────────────

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}
	if os.Args[1] == "--version" {
		fmt.Printf("glitchai v%s\n", Version)
		os.Exit(0)
	}

	mode := os.Args[1]
	fs   := flag.NewFlagSet(mode, flag.ExitOnError)

	providerF  := fs.String("provider",   "", "Provider: ollama|groq|anthropic|openai (default: ollama)")
	modelF     := fs.String("model",      "", "Model override (default: auto per provider)")
	findings   := fs.String("findings",   "", "Findings JSON file")
	target     := fs.String("target",     "", "Target URL (payload mode)")
	headersF   := fs.String("headers",    "", "Headers/fingerprint file (payload mode)")
	scanF      := fs.String("scan",       "", "Port scan JSON (recon mode)")
	dnsF       := fs.String("dns",        "", "DNS enum JSON (recon mode)")
	pcapF      := fs.String("pcap",       "", "Passive capture JSON (recon mode)")
	engagement := fs.String("engagement", "Penetration Test", "Engagement name (summary mode)")
	outputF    := fs.String("output",     "", "Save output to file")
	fs.Parse(os.Args[2:])

	p, err := detectProvider(*providerF, *modelF)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Provider error: %v\n", err)
		fmt.Fprintln(os.Stderr, "\nFree options:")
		fmt.Fprintln(os.Stderr, "  Ollama (local): ollama.com/download → ollama pull llama3.2 → ollama serve")
		fmt.Fprintln(os.Stderr, "  Groq (cloud):   console.groq.com (email only) → set GROQ_API_KEY=gsk_xxx")
		os.Exit(1)
	}

	fmt.Printf("[*] glitchai v%s | mode=%s | provider=%s | model=%s\n",
		Version, mode, p.Name, p.Model)

	var result string

	switch mode {
	case "triage":
		if *findings == "" {
			fmt.Fprintln(os.Stderr, "[-] --findings required"); os.Exit(1)
		}
		fmt.Println("[*] Triaging findings with AI...")
		result, err = modeTriage(p, *findings)

	case "payload":
		if *target == "" {
			fmt.Fprintln(os.Stderr, "[-] --target required"); os.Exit(1)
		}
		fmt.Printf("[*] Generating context-aware payloads for %s...\n", *target)
		result, err = modePayload(p, *target, *headersF)

	case "recon":
		fmt.Println("[*] Synthesizing recon into attack surface map...")
		result, err = modeRecon(p, *scanF, *dnsF, *pcapF)

	case "summary":
		if *findings == "" {
			fmt.Fprintln(os.Stderr, "[-] --findings required"); os.Exit(1)
		}
		fmt.Printf("[*] Writing executive summary for: %s\n", *engagement)
		result, err = modeSummary(p, *findings, *engagement)

	case "chat":
		modeChat(p, *findings)
		return

	default:
		fmt.Fprintf(os.Stderr, "Unknown mode: %s\n", mode)
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n" + strings.Repeat("─", 60))
	fmt.Println(result)
	fmt.Println(strings.Repeat("─", 60))

	if *outputF != "" {
		out := map[string]interface{}{
			"mode": mode, "provider": p.Name, "model": p.Model,
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"result": result, "scanner_version": Version,
		}
		data, _ := json.MarshalIndent(out, "", "  ")
		os.WriteFile(*outputF, data, 0644)
		fmt.Printf("[+] Saved to %s\n", *outputF)
	}
}

func printUsage() {
	fmt.Printf(`glitchai v%s — AI-Assisted Security Testing Engine

FREE OPTIONS (no credit card):
  Ollama (local):  ollama.com/download → ollama pull llama3.2 → ollama serve
  Groq (cloud):    console.groq.com (email signup) → set GROQ_API_KEY=gsk_xxx

Modes:
  triage   — Prioritize findings by exploitability
  payload  — Context-aware payloads from app fingerprint
  recon    — Attack surface map from scan results
  summary  — Executive summary for client report
  chat     — Interactive AI security assistant

Provider flags:
  --provider ollama      (default, local, free)
  --provider groq        (GROQ_API_KEY, free cloud)
  --provider anthropic   (ANTHROPIC_API_KEY)
  --provider openai      (OPENAI_API_KEY)
  --model <name>         override model

Examples:
  # Ollama (local, free):
  ollama serve
  glitchai triage --findings glitchexploit.json
  glitchai chat   --findings findings.json

  # Groq (free cloud):
  set GROQ_API_KEY=gsk_xxx
  glitchai triage  --findings findings.json --provider groq
  glitchai summary --findings findings.json --engagement "Corp Q4 2025" --provider groq

  # Payload generation:
  glitchai payload --target https://app.corp.com --headers headers.txt

  # Recon synthesis:
  glitchai recon --scan glitchscan.json --dns glitchdns.json
`, Version)
}

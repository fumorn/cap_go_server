package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/samwafgo/cap_go_server"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	// Initialize the cap server
	config := &capserver.CapConfig{
		TokensStorePath: "./example_tokens.json",
		EnableFSState:   true, // Opt in to file-based storage
		Logger:          log.Printf,
	}

	capServer := capserver.New(config)

	// Set up HTTP routes
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/challenge", handleChallenge(capServer))
	http.HandleFunc("/redeem", handleVerify(capServer))
	http.HandleFunc("/validate", handleValidate(capServer))

	// Start the server
	port := ":8080"
	log.Printf("Starting server on http://localhost%s", port)
	log.Printf("Make sure the static files are in the ./static/ directory")
	log.Fatal(http.ListenAndServe(port, nil))
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	// Serve static files from the static directory
	staticDir := "./static/"
	if r.URL.Path == "/" {
		http.ServeFile(w, r, filepath.Join(staticDir, "index.html"))
		return
	}

	// Handle other static files
	filePath := filepath.Join(staticDir, r.URL.Path[1:])
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		http.NotFound(w, r)
		return
	}

	http.ServeFile(w, r, filePath)
}

// handleChallenge creates a new challenge
func handleChallenge(capServer *capserver.Cap) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		config := &capserver.ChallengeConfig{
			ChallengeCount:      50,
			ChallengeSize:       32,
			ChallengeDifficulty: 4,
			ExpiresMs:           300000,
			Store:               true,
		}

		challenge, err := capServer.CreateChallenge(config)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to create challenge: %v", err), http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(challenge)
	}
}

// handleVerify solves a challenge and returns a verification token
func handleVerify(capServer *capserver.Cap) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		var req struct {
			Token     string          `json:"token"`
			Solutions [][]interface{} `json:"solutions"` // Array of [salt, target, solution] tuples
		}

		/*if 1 == 1 {
			http.Error(w, "TestError", http.StatusBadRequest)
			return
		}*/

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		if req.Token == "" {
			http.Error(w, "Token is required", http.StatusBadRequest)
			return
		}

		if len(req.Solutions) == 0 {
			http.Error(w, "Solution is required", http.StatusBadRequest)
			return
		}

		// Create solution structure with [salt, target, solution] format
		solution := &capserver.Solution{
			Token:     req.Token,
			Solutions: req.Solutions,
		}

		result, err := capServer.RedeemChallenge(solution)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to redeem challenge: %v", err), http.StatusInternalServerError)
			return
		}

		response := map[string]interface{}{
			"success": result.Success,
		}

		if result.Success && result.Token != "" {
			response["token"] = result.Token
		}
		if result.Success && result.Expires > 0 {
			response["expires"] = result.Expires
		}

		json.NewEncoder(w).Encode(response)
	}
}

// handleValidate validates a verification token
func handleValidate(capServer *capserver.Cap) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		var req struct {
			Token string `json:"token"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		if req.Token == "" {
			http.Error(w, "Token is required", http.StatusBadRequest)
			return
		}

		result, err := capServer.ValidateToken(req.Token, nil)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to validate token: %v", err), http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": result.Success,
			"message": "1",
		})
	}
}

// findSolution finds a nonce that produces a hash with the required prefix
// This is a simplified brute-force approach for demonstration
func findSolution(salt, target string) int {
	for nonce := 0; nonce < 1000000; nonce++ {
		if checkSolution(salt, target, nonce) {
			return nonce
		}
	}
	return -1 // No solution found
}

// checkSolution verifies if a given nonce produces a hash with the required prefix
func checkSolution(salt, target string, nonce int) bool {
	input := fmt.Sprintf("%s%d", salt, nonce)
	hash := sha256.Sum256([]byte(input))
	hashHex := hex.EncodeToString(hash[:])
	return strings.HasPrefix(hashHex, target)
}

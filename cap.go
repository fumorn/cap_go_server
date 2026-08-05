package capserver

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ChallengeTuple represents a single challenge consisting of salt and target
type ChallengeTuple [2]string

// ChallengeData contains the complete challenge information
type ChallengeData struct {
	Challenge []ChallengeTuple `json:"challenge"`
	Expires   int64            `json:"expires"`
	Token     string           `json:"token"`
}

// ChallengeState represents the internal state of challenges and tokens
type ChallengeState struct {
	ChallengesList map[string]*ChallengeData `json:"challengesList"`
	TokensList     map[string]int64          `json:"tokensList"`
}

// ChallengeConfig contains configuration options for challenge generation
type ChallengeConfig struct {
	ChallengeCount      int  `json:"challengeCount,omitempty"`      // Number of challenges to generate (default: 50)
	ChallengeSize       int  `json:"challengeSize,omitempty"`       // Size of each challenge in bytes (default: 32)
	ChallengeDifficulty int  `json:"challengeDifficulty,omitempty"` // Difficulty level (default: 4)
	ExpiresMs           int  `json:"expiresMs,omitempty"`           // Expiration time in milliseconds (default: 600000)
	Store               bool `json:"store,omitempty"`               // Whether to store the challenge in memory (default: true)
}

// TokenConfig contains configuration options for token validation
type TokenConfig struct {
	KeepToken bool `json:"keepToken,omitempty"` // Whether to keep the token after validation
}

// Solution represents a solution to a challenge
type Solution struct {
	Token     string          `json:"token"`
	Solutions [][]interface{} `json:"solutions"` // Array of [salt, target, solution] tuples
}

// CapConfig contains the main configuration for the Cap instance
type CapConfig struct {
	TokensStorePath string          `json:"tokensStorePath,omitempty"` // Path to store tokens file, absolute path recommended
	State           *ChallengeState `json:"state,omitempty"`           // State configuration

	// EnableFSState turns on file-based token persistence (default: false).
	// Since v1.0.1 persistence is opt-in: unless this is set, Cap never touches
	// the filesystem, so no directory or file is created on New().
	EnableFSState bool `json:"enableFSState,omitempty"`

	// Deprecated: kept for backward compatibility only. Setting it to true still
	// force-disables persistence; setting it to false no longer enables it.
	// Use EnableFSState instead.
	NoFSState bool `json:"noFSState,omitempty"`

	// SaveThrottleMs is the minimum interval between two disk writes, in
	// milliseconds. 0 uses DefaultSaveThrottleMs, a negative value writes on
	// every change. Pending changes are flushed by Flush() or Cleanup().
	SaveThrottleMs int `json:"saveThrottleMs,omitempty"`

	// Logger receives diagnostic messages. When nil, Cap stays completely
	// silent instead of writing to stdout.
	Logger func(format string, args ...interface{}) `json:"-"`
}

// ChallengeResponse represents the response from CreateChallenge
type ChallengeResponse struct {
	Challenge []ChallengeTuple `json:"challenge"`
	Token     string           `json:"token,omitempty"`
	Expires   int64            `json:"expires"`
}

// RedeemResponse represents the response from RedeemChallenge
type RedeemResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Token   string `json:"token,omitempty"`
	Expires int64  `json:"expires,omitempty"`
}

// ValidationResponse represents the response from ValidateToken
type ValidationResponse struct {
	Success bool `json:"success"`
}

// Cap represents the main Cap instance
type Cap struct {
	config *CapConfig
	mu     sync.RWMutex

	fsEnabled bool          // whether token state is persisted to disk
	throttle  time.Duration // minimum interval between two disk writes
	lastSave  time.Time     // when the last successful write happened
	dirty     bool          // there are in-memory changes not yet written
}

const (
	// Version is the released version of this library.
	Version = "1.0.1"

	DefaultTokensStore         = ".data/tokensList.json"
	DefaultChallengeCount      = 50
	DefaultChallengeSize       = 32
	DefaultChallengeDifficulty = 4
	DefaultExpiresMs           = 600000  // 10 minutes
	DefaultTokenExpiresMs      = 1200000 // 20 minutes
	DefaultSaveThrottleMs      = 2000    // coalesce disk writes within 2 seconds
)

// New creates a new Cap instance with the given configuration.
//
// File persistence is opt-in: without CapConfig.EnableFSState, New touches no
// file or directory at all and all state is kept in memory.
func New(configObj *CapConfig) *Cap {
	config := &CapConfig{
		TokensStorePath: DefaultTokensStore,
		State: &ChallengeState{
			ChallengesList: make(map[string]*ChallengeData),
			TokensList:     make(map[string]int64),
		},
	}

	if configObj != nil {
		if configObj.TokensStorePath != "" {
			config.TokensStorePath = configObj.TokensStorePath
		}
		config.EnableFSState = configObj.EnableFSState
		config.NoFSState = configObj.NoFSState
		config.SaveThrottleMs = configObj.SaveThrottleMs
		config.Logger = configObj.Logger
		if configObj.State != nil {
			config.State = configObj.State
		}
	}

	// A caller-supplied State may carry nil maps, guard against writing to them.
	if config.State.ChallengesList == nil {
		config.State.ChallengesList = make(map[string]*ChallengeData)
	}
	if config.State.TokensList == nil {
		config.State.TokensList = make(map[string]int64)
	}

	cap := &Cap{
		config:    config,
		fsEnabled: config.EnableFSState && !config.NoFSState,
	}

	switch {
	case config.SaveThrottleMs < 0:
		cap.throttle = 0
	case config.SaveThrottleMs == 0:
		cap.throttle = DefaultSaveThrottleMs * time.Millisecond
	default:
		cap.throttle = time.Duration(config.SaveThrottleMs) * time.Millisecond
	}

	if cap.fsEnabled {
		cap.loadTokens()
	}

	return cap
}

// CreateChallenge generates a new challenge with the specified configuration
func (c *Cap) CreateChallenge(conf *ChallengeConfig) (*ChallengeResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cleanExpiredTokens()

	// Set default values
	challengeCount := DefaultChallengeCount
	challengeSize := DefaultChallengeSize
	challengeDifficulty := DefaultChallengeDifficulty
	expiresMs := DefaultExpiresMs
	store := true

	if conf != nil {
		if conf.ChallengeCount > 0 {
			challengeCount = conf.ChallengeCount
		}
		if conf.ChallengeSize > 0 {
			challengeSize = conf.ChallengeSize
		}
		if conf.ChallengeDifficulty > 0 {
			challengeDifficulty = conf.ChallengeDifficulty
		}
		if conf.ExpiresMs > 0 {
			expiresMs = conf.ExpiresMs
		}
		store = conf.Store
	}

	// Generate challenges
	challenges := make([]ChallengeTuple, challengeCount)
	for i := 0; i < challengeCount; i++ {
		salt, err := generateRandomHex(challengeSize)
		if err != nil {
			return nil, fmt.Errorf("failed to generate salt: %w", err)
		}

		target, err := generateRandomHex(challengeDifficulty)
		if err != nil {
			return nil, fmt.Errorf("failed to generate target: %w", err)
		}

		challenges[i] = ChallengeTuple{salt, target}
	}

	token, err := generateRandomHex(50) // 25 bytes = 50 hex chars
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	expires := time.Now().UnixMilli() + int64(expiresMs)

	if !store {
		return &ChallengeResponse{
			Challenge: challenges,
			Expires:   expires,
		}, nil
	}

	c.config.State.ChallengesList[token] = &ChallengeData{
		Challenge: challenges,
		Expires:   expires,
		Token:     token,
	}

	return &ChallengeResponse{
		Challenge: challenges,
		Token:     token,
		Expires:   expires,
	}, nil
}

// RedeemChallenge validates a challenge solution and returns a verification token
func (c *Cap) RedeemChallenge(solution *Solution) (*RedeemResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if solution == nil || solution.Token == "" || solution.Solutions == nil {
		return &RedeemResponse{
			Success: false,
			Message: "Invalid body",
		}, nil
	}

	c.cleanExpiredTokens()

	challengeData, exists := c.config.State.ChallengesList[solution.Token]
	if !exists || challengeData.Expires < time.Now().UnixMilli() {
		delete(c.config.State.ChallengesList, solution.Token)
		return &RedeemResponse{
			Success: false,
			Message: "Challenge expired",
		}, nil
	}

	delete(c.config.State.ChallengesList, solution.Token)

	// Validate all challenges
	for _, challenge := range challengeData.Challenge {
		salt, target := challenge[0], challenge[1]
		found := false

		for _, sol := range solution.Solutions {
			if len(sol) != 3 {
				continue
			}

			solSalt, ok1 := sol[0].(string)
			solTarget, ok2 := sol[1].(string)
			solValue := sol[2]

			if !ok1 || !ok2 || solSalt != salt || solTarget != target {
				continue
			}

			// Convert solution value to string
			var solStr string
			switch v := solValue.(type) {
			case string:
				solStr = v
			case float64:
				solStr = fmt.Sprintf("%.0f", v)
			case int:
				solStr = fmt.Sprintf("%d", v)
			default:
				solStr = fmt.Sprintf("%v", v)
			}

			// Verify the solution
			hash := sha256.Sum256([]byte(salt + solStr))
			hashHex := hex.EncodeToString(hash[:])

			if strings.HasPrefix(hashHex, target) {
				found = true
				break
			}
		}

		if !found {
			return &RedeemResponse{
				Success: false,
				Message: "Invalid solution",
			}, nil
		}
	}

	// Generate verification token
	vertoken, err := generateRandomHex(30) // 15 bytes = 30 hex chars
	if err != nil {
		return nil, fmt.Errorf("failed to generate verification token: %w", err)
	}

	expires := time.Now().UnixMilli() + DefaultTokenExpiresMs
	hash := sha256.Sum256([]byte(vertoken))
	hashHex := hex.EncodeToString(hash[:])

	id, err := generateRandomHex(16) // 8 bytes = 16 hex chars
	if err != nil {
		return nil, fmt.Errorf("failed to generate token ID: %w", err)
	}

	key := fmt.Sprintf("%s:%s", id, hashHex)
	c.config.State.TokensList[key] = expires

	c.persist()

	return &RedeemResponse{
		Success: true,
		Token:   fmt.Sprintf("%s:%s", id, vertoken),
		Expires: expires,
	}, nil
}

// ValidateToken validates a verification token
func (c *Cap) ValidateToken(token string, conf *TokenConfig) (*ValidationResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cleanExpiredTokens()

	parts := strings.Split(token, ":")
	if len(parts) != 2 {
		return &ValidationResponse{Success: false}, nil
	}

	id, vertoken := parts[0], parts[1]
	hash := sha256.Sum256([]byte(vertoken))
	hashHex := hex.EncodeToString(hash[:])
	key := fmt.Sprintf("%s:%s", id, hashHex)

	if _, exists := c.config.State.TokensList[key]; exists {
		if conf == nil || !conf.KeepToken {
			delete(c.config.State.TokensList, key)
			c.persist()
		}

		return &ValidationResponse{Success: true}, nil
	}

	return &ValidationResponse{Success: false}, nil
}

// Cleanup cleans up expired tokens and syncs state to disk
func (c *Cap) Cleanup() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cleanExpiredTokens() {
		c.dirty = true
	}

	if !c.fsEnabled || !c.dirty {
		return nil
	}

	return c.saveTokens()
}

// Flush writes any pending token changes to disk right away, ignoring the
// throttle interval. It is a no-op when persistence is disabled or when there
// is nothing to write. Call it before shutting down so throttled changes are
// not lost.
func (c *Cap) Flush() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.fsEnabled || !c.dirty {
		return nil
	}

	return c.saveTokens()
}

// logf reports a diagnostic message through the injected logger. Without a
// logger the library stays silent rather than writing to stdout.
func (c *Cap) logf(format string, args ...interface{}) {
	if c.config.Logger != nil {
		c.config.Logger(format, args...)
	}
}

// loadTokens loads tokens from the storage file. A missing file is not an
// error: the state stays empty and the file is created on the first write.
func (c *Cap) loadTokens() {
	data, err := os.ReadFile(c.config.TokensStorePath)
	if err != nil {
		if !os.IsNotExist(err) {
			c.logf("cap: couldn't read tokens file %s: %v", c.config.TokensStorePath, err)
		}
		return
	}

	var tokensList map[string]int64
	if err := json.Unmarshal(data, &tokensList); err != nil {
		c.logf("cap: couldn't parse tokens file %s, using empty state: %v", c.config.TokensStorePath, err)
		return
	}
	if tokensList == nil { // file contained "null"
		return
	}

	c.config.State.TokensList = tokensList
	c.cleanExpiredTokens()
}

// persist records a state change and writes it out, unless another write
// happened within the throttle window. Callers must hold the lock.
func (c *Cap) persist() {
	if !c.fsEnabled {
		return
	}

	c.dirty = true
	if c.throttle > 0 && time.Since(c.lastSave) < c.throttle {
		return // coalesced, Flush() or a later change writes it out
	}

	if err := c.saveTokens(); err != nil {
		c.logf("cap: failed to save tokens: %v", err)
	}
}

// saveTokens atomically writes the tokens to the storage file. The file is
// written to a temporary sibling first and then renamed, so a crash can never
// leave a half-written file behind. Callers must hold the lock.
func (c *Cap) saveTokens() error {
	data, err := json.Marshal(c.config.State.TokensList)
	if err != nil {
		return fmt.Errorf("failed to marshal tokens: %w", err)
	}

	storePath := c.config.TokensStorePath
	if dirPath := filepath.Dir(storePath); dirPath != "." && dirPath != "" {
		if err := os.MkdirAll(dirPath, 0700); err != nil {
			return fmt.Errorf("failed to create tokens directory: %w", err)
		}
	}

	tmpPath := storePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write tokens file: %w", err)
	}

	if err := os.Rename(tmpPath, storePath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to replace tokens file: %w", err)
	}

	c.lastSave = time.Now()
	c.dirty = false
	return nil
}

// cleanExpiredTokens removes expired tokens and challenges from memory
func (c *Cap) cleanExpiredTokens() bool {
	now := time.Now().UnixMilli()
	tokensChanged := false

	// Clean expired challenges
	for k, v := range c.config.State.ChallengesList {
		if v.Expires < now {
			delete(c.config.State.ChallengesList, k)
		}
	}

	// Clean expired tokens
	for k, v := range c.config.State.TokensList {
		if v < now {
			delete(c.config.State.TokensList, k)
			tokensChanged = true
		}
	}

	return tokensChanged
}

// generateRandomHex generates a random hex string of the specified length
func generateRandomHex(length int) (string, error) {
	bytes := make([]byte, (length+1)/2)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes)[:length], nil
}

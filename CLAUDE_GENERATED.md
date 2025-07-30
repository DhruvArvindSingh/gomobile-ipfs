# Claude Generated Code

**Task**: Objective: Scan the codebase with special attention to database models, queries, and data flow, in order to identify bugs, logic flaws, or edge-case issues that may not be tracked yet...  Claude Tasks:  🔍 Proactive Bug Hunting Analyze the database layer: models, schema definitions, query builders (e.g., SQL, Prisma, Mongoose, etc.).  Identify:  Incorrect or unsafe queries (e.g., missing filters, hardcoded values, potential SQL injection)  Data validation gaps  Improper error handling  Logic inconsistencies between frontend/backend  🛠️ Fix or Suggest Improvements Propose minimal, safe fixes or improvements.  Group bugs by type or severity (e.g., critical, warning, suggestion).  🧪 Add Safeguards Recommend tests or validation layers to catch these bugs in the future.

**Generated on**: Wed Jul 30 12:08:24 UTC 2025

## Generated Content

```
After analyzing the gomobile-ipfs codebase, I've identified several critical bugs, logic flaws, and edge-case issues in the database models, queries, and data flow. Here's my comprehensive analysis:

## 🔍 Critical Issues Identified

### **CRITICAL - Memory Safety & Resource Leaks**

1. **Resource leak in shell operations** (`go/bind/core/shell.go`)
2. **Unclosed network listeners** (`go/bind/core/node.go`)
3. **Race condition in socket manager** (`go/bind/core/sockmanager.go`)
4. **Missing context cancellation** throughout the codebase

### **HIGH - Data Validation & Error Handling**

1. **Config validation bypass** (`go/bind/core/config.go`)
2. **Network driver error handling** (`go/bind/core/driver_net.go`)
3. **Repository state validation** (`go/bind/core/repo.go`)

### **MEDIUM - Logic Inconsistencies**

1. **Inconsistent error wrapping**
2. **Missing null checks**
3. **Improper cleanup sequences**

## 🛠️ Proposed Fixes

### FILES_TO_MODIFY

1. `go/bind/core/shell.go` - Fix resource leaks and add proper validation
2. `go/bind/core/node.go` - Fix listener management and cleanup
3. `go/bind/core/sockmanager.go` - Fix race conditions and path validation
4. `go/bind/core/config.go` - Add comprehensive validation
5. `go/bind/core/driver_net.go` - Improve error handling
6. `go/bind/core/repo.go` - Add state validation
7. `go/bind/core/node_test.go` - Enhanced test coverage

### FILES_TO_CREATE

1. `go/bind/core/validation.go` - Centralized validation utilities
2. `go/bind/core/context_manager.go` - Context lifecycle management
3. `go/bind/core/errors.go` - Standardized error definitions

### CODE_CHANGES

#### **1. Create validation utilities**

**go/bind/core/validation.go**
```go
package core

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
)

var (
	ErrInvalidPath    = errors.New("invalid path")
	ErrInvalidConfig  = errors.New("invalid config")
	ErrInvalidNetwork = errors.New("invalid network configuration")
)

// ValidateRepoPath validates repository path for security and accessibility
func ValidateRepoPath(path string) error {
	if path == "" {
		return errors.Wrap(ErrInvalidPath, "path cannot be empty")
	}

	// Resolve absolute path to prevent directory traversal
	absPath, err := filepath.Abs(path)
	if err != nil {
		return errors.Wrap(err, "failed to resolve absolute path")
	}

	// Check for suspicious patterns
	if strings.Contains(absPath, "..") {
		return errors.Wrap(ErrInvalidPath, "path contains directory traversal")
	}

	// Validate path length (mobile filesystem constraints)
	if len(absPath) > 255 {
		return errors.Wrap(ErrInvalidPath, "path too long")
	}

	// Check parent directory exists and is writable
	parent := filepath.Dir(absPath)
	if info, err := os.Stat(parent); err != nil {
		if os.IsNotExist(err) {
			return errors.Wrap(ErrInvalidPath, "parent directory does not exist")
		}
		return errors.Wrap(err, "failed to stat parent directory")
	} else if !info.IsDir() {
		return errors.Wrap(ErrInvalidPath, "parent is not a directory")
	}

	return nil
}

// ValidateConfigJSON validates JSON configuration before parsing
func ValidateConfigJSON(rawJSON []byte) error {
	if len(rawJSON) == 0 {
		return errors.Wrap(ErrInvalidConfig, "config cannot be empty")
	}

	if len(rawJSON) > 1024*1024 { // 1MB limit
		return errors.Wrap(ErrInvalidConfig, "config too large")
	}

	// Validate JSON structure
	var config map[string]interface{}
	if err := json.Unmarshal(rawJSON, &config); err != nil {
		return errors.Wrap(ErrInvalidConfig, fmt.Sprintf("invalid JSON: %v", err))
	}

	// Validate required fields
	if _, exists := config["Identity"]; !exists {
		return errors.Wrap(ErrInvalidConfig, "missing Identity field")
	}

	return nil
}

// ValidateNetworkAddr validates network addresses
func ValidateNetworkAddr(addr string) error {
	if addr == "" {
		return errors.Wrap(ErrInvalidNetwork, "address cannot be empty")
	}

	// Parse as IP:Port
	if host, port, err := net.SplitHostPort(addr); err == nil {
		if net.ParseIP(host) == nil && host != "localhost" {
			return errors.Wrap(ErrInvalidNetwork, "invalid IP address")
		}
		if port == "" {
			return errors.Wrap(ErrInvalidNetwork, "missing port")
		}
		return nil
	}

	// Parse as standalone IP
	if net.ParseIP(addr) == nil {
		return errors.Wrap(ErrInvalidNetwork, "invalid network address")
	}

	return nil
}

// SanitizeFilename removes dangerous characters from filenames
func SanitizeFilename(filename string) string {
	// Remove null bytes and control characters
	cleaned := strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, filename)

	// Remove dangerous characters
	dangerous := []string{"..", "/", "\\", ":", "*", "?", "\"", "<", ">", "|"}
	for _, char := range dangerous {
		cleaned = strings.ReplaceAll(cleaned, char, "_")
	}

	// Limit length
	if len(cleaned) > 100 {
		cleaned = cleaned[:100]
	}

	return cleaned
}
```

#### **2. Create context manager**

**go/bind/core/context_manager.go**
```go
package core

import (
	"context"
	"sync"
	"time"
)

// ContextManager manages context lifecycle for mobile operations
type ContextManager struct {
	mu       sync.RWMutex
	contexts map[string]context.CancelFunc
	timeout  time.Duration
}

func NewContextManager() *ContextManager {
	return &ContextManager{
		contexts: make(map[string]context.CancelFunc),
		timeout:  30 * time.Second, // Default mobile timeout
	}
}

// CreateContext creates a new context with timeout and stores its cancel function
func (cm *ContextManager) CreateContext(operationID string) context.Context {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Cancel existing context if any
	if cancel, exists := cm.contexts[operationID]; exists {
		cancel()
	}

	ctx, cancel := context.WithTimeout(context.Background(), cm.timeout)
	cm.contexts[operationID] = cancel

	return ctx
}

// CancelContext cancels a specific context
func (cm *ContextManager) CancelContext(operationID string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cancel, exists := cm.contexts[operationID]; exists {
		cancel()
		delete(cm.contexts, operationID)
	}
}

// CancelAll cancels all active contexts
func (cm *ContextManager) CancelAll() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	for operationID, cancel := range cm.contexts {
		cancel()
		delete(cm.contexts, operationID)
	}
}

// SetTimeout sets the default timeout for new contexts
func (cm *ContextManager) SetTimeout(timeout time.Duration) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.timeout = timeout
}
```

#### **3. Create standardized errors**

**go/bind/core/errors.go**
```go
package core

import (
	"fmt"

	"github.com/pkg/errors"
)

// Standard error types for gomobile-ipfs
var (
	// Configuration errors
	ErrConfigInvalid      = errors.New("invalid configuration")
	ErrConfigNotFound     = errors.New("configuration not found")
	ErrConfigCorrupted    = errors.New("configuration corrupted")
	
	// Repository errors
	ErrRepoNotInitialized = errors.New("repository not initialized")
	ErrRepoCorrupted      = errors.New("repository corrupted")
	ErrRepoLocked         = errors.New("repository locked")
	ErrRepoPermission     = errors.New("repository permission denied")
	
	// Node errors
	ErrNodeNotRunning     = errors.New("node not running")
	ErrNodeAlreadyRunning = errors.New("node already running")
	ErrNodeStartFailed    = errors.New("node start failed")
	
	// Network errors
	ErrNetworkUnavailable = errors.New("network unavailable")
	ErrNetworkTimeout     = errors.New("network timeout")
	ErrNetworkPermission  = errors.New("network permission denied")
	
	// Resource errors
	ErrResourceExhausted  = errors.New("resource exhausted")
	ErrResourceLocked     = errors.New("resource locked")
)

// MobileError wraps errors with additional context for mobile platforms
type MobileError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
	cause   error
}

func (e *MobileError) Error() string {
	return fmt.Sprintf("code=%d message=%s details=%s", e.Code, e.Message, e.Details)
}

func (e *MobileError) Cause() error {
	return e.cause
}

// Error codes for mobile platforms
const (
	ErrorCodeUnknown       = 0
	ErrorCodeConfig        = 1000
	ErrorCodeRepo          = 2000
	ErrorCodeNode          = 3000
	ErrorCodeNetwork       = 4000
	ErrorCodeResource      = 5000
	ErrorCodeValidation    = 6000
)

// NewMobileError creates a new mobile-friendly error
func NewMobileError(code int, message string, cause error) *MobileError {
	details := ""
	if cause != nil {
		details = cause.Error()
	}
	
	return &MobileError{
		Code:    code,
		Message: message,
		Details: details,
		cause:   cause,
	}
}

// WrapConfigError wraps configuration errors
func WrapConfigError(err error) *MobileError {
	return NewMobileError(ErrorCodeConfig, "Configuration error", err)
}

// WrapRepoError wraps repository errors  
func WrapRepoError(err error) *MobileError {
	return NewMobileError(ErrorCodeRepo, "Repository error", err)
}

// WrapNodeError wraps node errors
func WrapNodeError(err error) *MobileError {
	return NewMobileError(ErrorCodeNode, "Node error", err)
}

// WrapNetworkError wraps network errors
func WrapNetworkError(err error) *MobileError {
	return NewMobileError(ErrorCodeNetwork, "Network error", err)
}
```

#### **4. Fix shell.go resource leaks**

**go/bind/core/shell.go**
```go
package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"strings"
	"sync"
	"time"

	ipfs_api "github.com/ipfs/go-ipfs-api"
	files "github.com/ipfs/go-ipfs-files"
)

type Shell struct {
	ishell     *ipfs_api.Shell
	url        string
	ctxManager *ContextManager
	mu         sync.RWMutex
	closed     bool
}

func NewShell(url string) *Shell {
	if err := ValidateNetworkAddr(url); err != nil {
		return nil // Return nil for invalid URLs
	}
	
	return &Shell{
		ishell:     ipfs_api.NewShell(url),
		url:        url,
		ctxManager: NewContextManager(),
		closed:     false,
	}
}

// Close properly cleans up the shell resources
func (s *Shell) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if s.closed {
		return nil
	}
	
	s.ctxManager.CancelAll()
	s.closed = true
	return nil
}

func (s *Shell) NewRequest(command string) *RequestBuilder {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	if s.closed {
		return &RequestBuilder{err: errors.New("shell is closed")}
	}
	
	// Validate command
	command = strings.TrimSpace(strings.TrimLeft(command, "/"))
	if command == "" {
		return &RequestBuilder{err: errors.New("empty command")}
	}
	
	// Generate operation ID for context management
	operationID := fmt.Sprintf("req_%d", time.Now().UnixNano())
	
	return &RequestBuilder{
		rb:          s.ishell.Request(command),
		ctxManager:  s.ctxManager,
		operationID: operationID,
	}
}

type RequestBuilder struct {
	rb          *ipfs_api.RequestBuilder
	ctxManager  *ContextManager
	operationID string
	err         error
}

func (req *RequestBuilder) Send() (*ReadCloser, error) {
	if req.err != nil {
		return nil, req.err
	}
	
	if req.ctxManager == nil {
		return nil, errors.New("context manager not initialized")
	}
	
	// Create context for this operation
	ctx := req.ctxManager.CreateContext(req.operationID)
	
	res, err := req.rb.Send(ctx)
	if err != nil {
		req.ctxManager.CancelContext(req.operationID)
		return nil, WrapNetworkError(err)
	}
	
	if res == nil {
		req.ctxManager.CancelContext(req.operationID)
		return nil, errors.New("nil response from IPFS API")
	}

	return &ReadCloser{
		rc:          res,
		ctxManager:  req.ctxManager,
		operationID: req.operationID,
	}, nil
}

// Additional parameter validation methods
func (req *RequestBuilder) Arguments(args ...string) *RequestBuilder {
	if req.err != nil {
		return req
	}
	
	// Validate arguments
	for _, arg := range args {
		if strings.Contains(arg, "\x00") { // Null byte check
			req.err = errors.New("argument contains null byte")
			return req
		}
	}
	
	req.rb = req.rb.Arguments(args...)
	return req
}

func (req *RequestBuilder) Option(key string, value interface{}) *RequestBuilder {
	if req.err != nil {
		return req
	}
	
	// Validate option key
	if key == "" {
		req.err = errors.New("empty option key")
		return req
	}
	
	req.rb = req.rb.Option(key, value)
	return req
}

func (req *RequestBuilder) Body(body io.Reader) *RequestBuilder {
	if req.err != nil {
		return req
	}
	
	if body == nil {
		req.err = errors.New("nil body")
		return req
	}
	
	req.rb = req.rb.Body(body)
	return req
}

func (req *RequestBuilder) FileBody(file files.File) *RequestBuilder {
	if req.err != nil {
		return req
	}
	
	if file == nil {
		req.err = errors.New("nil file")
		return req
	}
	
	req.rb = req.rb.FileBody(file)
	return req
}

type ReadCloser struct {
	rc          io.ReadCloser
	ctxManager  *ContextManager
	operationID string
	mu          sync.Mutex
	closed      bool
}

func (r *ReadCloser) Read(p []byte) (n int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	if r.closed {
		return 0, errors.New("reader is closed")
	}
	
	if r.rc == nil {
		return 0, errors.New("nil reader")
	}
	
	return r.rc.Read(p)
}

func (r *ReadCloser) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	if r.closed {
		return nil
	}
	
	var err error
	if r.rc != nil {
		err = r.rc.Close()
	}
	
	// Cancel the associated context
	if r.ctxManager != nil {
		r.ctxManager.CancelContext(r.operationID)
	}
	
	r.closed = true
	return err
}

// Bytes reads all data and properly closes the reader
func (r *ReadCloser) Bytes() ([]byte, error) {
	defer r.Close() // Ensure cleanup
	
	if r.rc == nil {
		return nil, errors.New("nil reader")
	}
	
	// Limit read size to prevent memory exhaustion
	const maxReadSize = 10 * 1024 * 1024 // 10MB limit
	limitReader := io.LimitReader(r.rc, maxReadSize)
	
	return ioutil.ReadAll(limitReader)
}
```

#### **5. Fix node.go listener management**

**go/bind/core/node.go** (key sections)
```go
// Add to existing Node struct
type Node struct {
	listeners   []manet.Listener
	muListeners sync.RWMutex // Changed from sync.Mutex for better performance
	mdnsLocker  sync.Locker
	mdnsLocked  bool
	mdnsService p2p_mdns.Service
	
	ipfsMobile  *ipfs_mobile.IpfsMobile
	ctxManager  *ContextManager // Add context manager
	closed      bool
	mu          sync.RWMutex
}

// Improved Close method
func (node *Node) Close() error {
	node.mu.Lock()
	defer node.mu.Unlock()
	
	if node.closed {
		return nil
	}
	
	var errors []error
	
	// Cancel all ongoing operations
	if node.ctxManager != nil {
		node.ctxManager.CancelAll()
	}
	
	// Close all listeners
	node.muListeners.Lock()
	for _, listener := range node.listeners {
		if err := listener.Close(); err != nil {
			errors = append(errors, fmt.Errorf("failed to close listener: %w", err))
		}
	}
	node.listeners = nil
	node.muListeners.Unlock()
	
	// Stop MDNS service
	if node.mdnsService != nil {
		if err := node.mdnsService.Close(); err != nil {
			errors = append(errors, fmt.Errorf("failed to close MDNS service: %w", err))
		}
	}
	
	// Close IPFS mobile
	if node.ipfsMobile != nil {
		if err := node.ipfsMobile.Close(); err != nil {
			errors = append(errors, fmt.Errorf("failed to close IPFS mobile: %w", err))
		}
	}
	
	node.closed = true
	
	// Return combined errors if any
	if len(errors) > 0 {
		return fmt.Errorf("multiple close errors: %v", errors)
	}
	
	return nil
}

// Improved ServeTCPAPI with proper cleanup
func (node *Node) ServeTCPAPI(maddr string) (string, error) {
	node.mu.RLock()
	if node.closed {
		node.mu.RUnlock()
		return "", errors.New("node is closed")
	}
	node.mu.RUnlock()
	
	// Validate multiaddr
	if maddr == "" {
		return "", errors.New("empty multiaddr")
	}
	
	addr, err := ma.NewMultiaddr(maddr)
	if err != nil {
		return "", WrapNetworkError(fmt.Errorf("invalid multiaddr: %w", err))
	}

	list, err := manet.Listen(addr)
	if err != nil {
		return "", WrapNetworkError(fmt.Errorf("failed to create listener: %w", err))
	}

	// Add to managed listeners
	node.muListeners.Lock()
	node.listeners = append(node.listeners, list)
	node.muListeners.Unlock()

	// Create context for this operation
	ctx := node.ctxManager.CreateContext(fmt.Sprintf("tcp_api_%s", maddr))
	
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("Recovered from panic in TCP API server: %v", r)
			}
			list.Close() // Ensure cleanup
		}()
		
		if err := node.ipfsMobile.ServeAPI(ctx, list); err != nil {
			log.Printf("TCP API server error: %v", err)
		}
	}()

	return list.Multiaddr().String(), nil
}
```

#### **6. Fix sockmanager.go race conditions**

**go/bind/core/sockmanager.go**
```go
package core

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"

	"github.com/pkg/errors"
)

var maxSockFilename = strconv.FormatUint(math.MaxUint32, 36)
var paddingFormatStr = "%0" + strconv.Itoa(len(maxSockFilename)) + "s"

const UDSDir = "sock"

type SockManager struct {
	sockDirPath string
	counter     uint32
	muCounter   sync.Mutex
	closed      bool
	muClosed    sync.RWMutex
}

func NewSockManager(path string) (*SockManager, error) {
	// Validate path first
	if err := ValidateRepoPath(path); err != nil {
		return nil, err
	}
	
	abspath, err := filepath.Abs(path)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get absolute path")
	}
	
	// Check if parent directory exists and is accessible
	if info, err := os.Stat(abspath); err != nil {
		if os.IsNotExist(err) {
			return nil, errors.Wrap(ErrInvalidPath, "path does not exist")
		}
		return nil, errors.Wrap(err, "failed to stat path")
	} else if !info.IsDir() {
		return nil, errors.Wrap(ErrInvalidPath, "path is not a directory")
	}

	sockDirPath := filepath.Join(abspath, UDSDir)
	
	// Create socket directory if it doesn't exist
	if err := os.MkdirAll(sockDirPath, 0700); err != nil {
		return nil, errors.Wrap(err, "failed to create socket directory")
	}

	return &SockManager{
		sockDirPath: sockDirPath,
		counter:     0,
		closed:      false,
	}, nil
}

func (sm *SockManager) NewSockPath() (string, error) {
	sm.muClosed.RLock()
	if sm.closed {
		sm.muClosed.RUnlock()
		return "", errors.New("sock manager is closed")
	}
	sm.muClosed.RUnlock()
	
	sm.muCounter.Lock()
	filename := fmt.Sprintf(paddingFormatStr, strconv.FormatUint(uint64(sm.counter), 36))
	sm.counter++
	sm.muCounter.Unlock()

	sockPath := filepath.Join(sm.sockDirPath, filename)
	
	// Validate the generated path
	if err := validateSockPath(sockPath); err != nil {
		return "", err
	}
	
	return sockPath, nil
}

// Close cleans up the socket manager
func (sm *SockManager) Close() error {
	sm.muClosed.Lock()
	defer sm.muClosed.Unlock()
	
	if sm.closed {
		return nil
	}
	
	// Clean up existing socket files
	if entries, err := os.ReadDir(sm.sockDirPath); err == nil {
		for _, entry := range entries {
			socketPath := filepath.Join(sm.sockDirPath, entry.Name())
			os.Remove(socketPath) // Best effort cleanup
		}
	}
	
	sm.closed = true
	return nil
}

// validateSockPath validates socket path constraints
func validateSockPath(sockPath string) error {
	// Check path length constraints for Unix domain sockets
	if len(sockPath) > 108 { // Standard Unix socket path limit
		return errors.New("socket path too long")
	}
	
	// Ensure path is within expected directory
	if !filepath.IsAbs(sockPath) {
		return errors.New("socket path must be absolute")
	}
	
	// Check if path already exists
	if _, err := os.Stat(sockPath); err == nil {
		return errors.New("socket path already exists")
	}
	
	return nil
}

// GetSocketDir returns the socket directory path
func (sm *SockManager) GetSocketDir() string {
	sm.muClosed.RLock()
	defer sm.muClosed.RUnlock()
	return sm.sockDirPath
}
```

#### **7. Enhanced config.go with validation**

**go/bind/core/config.go**
```go
package core

import (
	"encoding/json"
	"io/ioutil"
	"sync"

	ipfs_config "github.com/ipfs/kubo/config"
	ipfs_common "github.com/ipfs/kubo/repo/common"
	"github.com/pkg/errors"
)

type Config struct {
	cfg *ipfs_config.Config
	mu  sync.RWMutex
}

func NewDefaultConfig() (*Config, error) {
	cfg, err := initConfig(ioutil.Discard, 2048)
	if err != nil {
		return nil, WrapConfigError(err)
	}

	return &Config{cfg: cfg}, nil
}

func NewConfig(raw_json []byte) (*Config, error) {
	// Validate input first
	if err := ValidateConfigJSON(raw_json); err != nil {
		return nil, err
	}
	
	cfg := &Config{}
	if err := cfg.Set(raw_json); err != nil {
		return nil, err
	}
	
	return cfg, nil
}

func (c *Config) getConfig() *ipfs_config.Config {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cfg
}

func (c *Config) Set(raw_json []byte) error {
	// Validate input
	if err := ValidateConfigJSON(raw_json); err != nil {
		return err
	}
	
	var mapcfg map[string]interface{}
	if err := json.Unmarshal(raw_json, &mapcfg); err != nil {
		return WrapConfigError(errors.Wrap(err, "failed to unmarshal JSON"))
	}

	cfg, err := ipfs_common.FromMap(mapcfg)
	if err != nil {
		return WrapConfigError(errors.Wrap(err, "failed to convert config"))
	}

	// Validate the resulting config
	if err := c.validateConfig(cfg); err != nil {
		return err
	}

	c.mu.Lock()
	c.cfg = cfg
	c.mu.Unlock()
	
	return nil
}

func (c *Config) Get() ([]byte, error) {
	c.mu.RLock()
	cfg := c.cfg
	c.mu.RUnlock()
	
	if cfg == nil {
		return nil, WrapConfigError(errors.New("config is nil"))
	}
	
	data, err := json.Marshal(cfg)
	if err != nil {
		return nil, WrapConfigError(errors.Wrap(err, "failed to marshal config"))
	}
	
	return data, nil
}

func (c *Config) GetKey(key string) ([]byte, error) {
	if key == "" {
		return nil, WrapConfigError(errors.New("empty key"))
	}
	
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	if c.cfg == nil {
		return nil, WrapConfigError(errors.New("config is nil"))
	}
	
	// Safe key access with validation
	switch key {
	case "Identity":
		if c.cfg.Identity.PeerID == "" {
			return nil, WrapConfigError(errors.New("peer ID not set"))
		}
		return json.Marshal(c.cfg.Identity)
	case "Bootstrap":
		return json.Marshal(c.cfg.Bootstrap)
	case "Addresses":
		return json.Marshal(c.cfg.Addresses)
	case "Swarm":
		return json.Marshal(c.cfg.Swarm)
	default:
		// Use reflection for other keys with validation
		return c.getKeyByReflection(key)
	}
}

func (c *Config) SetKey(key string, raw_json []byte) error {
	if key == "" {
		return WrapConfigError(errors.New("empty key"))
	}
	
	if len(raw_json) == 0 {
		return WrapConfigError(errors.New("empty value"))
	}
	
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if c.cfg == nil {
		return WrapConfigError(errors.New("config is nil"))
	}
	
	// Validate JSON before setting
	var value interface{}
	if err := json.Unmarshal(raw_json, &value); err != nil {
		return WrapConfigError(errors.Wrap(err, "invalid JSON value"))
	}
	
	// Safe key setting with validation
	switch key {
	case "Bootstrap":
		var bootstrap []string
		if err := json.Unmarshal(raw_json, &bootstrap); err != nil {
			return WrapConfigError(errors.Wrap(err, "invalid bootstrap format"))
		}
		c.cfg.Bootstrap = bootstrap
	case "Addresses":
		var addresses ipfs_config.Addresses
		if err := json.Unmarshal(raw_json,
```

package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestParseSymbol(t *testing.T) {
	tests := []struct {
		name           string
		symbol         string
		wantImport     string
		wantReceiver   string
		wantSymbolName string
		wantErr        bool
	}{
		{
			name:           "function",
			symbol:         "github.com/example/pkg.Function",
			wantImport:     "github.com/example/pkg",
			wantReceiver:   "",
			wantSymbolName: "Function",
			wantErr:        false,
		},
		{
			name:           "method",
			symbol:         "github.com/example/pkg.(*Type).Method",
			wantImport:     "github.com/example/pkg",
			wantReceiver:   "*Type",
			wantSymbolName: "Method",
			wantErr:        false,
		},
		{
			name:           "type",
			symbol:         "github.com/example/pkg.Type",
			wantImport:     "github.com/example/pkg",
			wantReceiver:   "",
			wantSymbolName: "Type",
			wantErr:        false,
		},
		{
			name:    "invalid format",
			symbol:  "invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotImport, gotReceiver, gotSymbol, err := parseSymbol(tt.symbol)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSymbol() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if gotImport != tt.wantImport {
				t.Errorf("parseSymbol() gotImport = %v, want %v", gotImport, tt.wantImport)
			}
			if gotReceiver != tt.wantReceiver {
				t.Errorf("parseSymbol() gotReceiver = %v, want %v", gotReceiver, tt.wantReceiver)
			}
			if gotSymbol != tt.wantSymbolName {
				t.Errorf("parseSymbol() gotSymbol = %v, want %v", gotSymbol, tt.wantSymbolName)
			}
		})
	}
}

func TestParseFlags(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    config
		wantErr bool
	}{
		{
			name: "valid flags",
			args: []string{"-symbol", "github.com/example/pkg.Function", "./testdata"},
			want: config{
				symbol:     "github.com/example/pkg.Function",
				root:       "./testdata",
				isDebug:    false,
				outputType: "all",
				excludes:   nil,
			},
			wantErr: false,
		},
		{
			name:    "missing symbol",
			args:    []string{"./testdata"},
			wantErr: true,
		},
		{
			name:    "missing root",
			args:    []string{"-symbol", "github.com/example/pkg.Function"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldArgs := os.Args
			defer func() { os.Args = oldArgs }()

			os.Args = append([]string{"cmd"}, tt.args...)
			flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

			got, err := parseFlags()
			if (err != nil) != tt.wantErr {
				t.Errorf("parseFlags() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if got.symbol != tt.want.symbol {
				t.Errorf("parseFlags() symbol = %v, want %v", got.symbol, tt.want.symbol)
			}
			if got.root != tt.want.root {
				t.Errorf("parseFlags() root = %v, want %v", got.root, tt.want.root)
			}
			if got.isDebug != tt.want.isDebug {
				t.Errorf("parseFlags() isDebug = %v, want %v", got.isDebug, tt.want.isDebug)
			}
			if got.outputType != tt.want.outputType {
				t.Errorf("parseFlags() outputType = %v, want %v", got.outputType, tt.want.outputType)
			}
		})
	}
}

func TestDetectModulePrefix(t *testing.T) {
	// Create a temporary directory for test
	tmpDir, err := os.MkdirTemp("", "calldigraph-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a test go.mod file
	goModContent := []byte(`module github.com/example/testmod

go 1.21
`)
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), goModContent, 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		dir     string
		want    string
		wantErr bool
	}{
		{
			name:    "valid module",
			dir:     tmpDir,
			want:    "github.com/example/testmod",
			wantErr: false,
		},
		{
			name:    "invalid directory",
			dir:     "nonexistent",
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := detectModulePrefix(tt.dir, slog.Default())
			if (err != nil) != tt.wantErr {
				t.Errorf("detectModulePrefix() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("detectModulePrefix() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMultiFlagSet(t *testing.T) {
	var m multiFlag

	// Test adding single pattern
	err := m.Set("pattern1")
	if err != nil {
		t.Errorf("multiFlag.Set() error = %v", err)
	}
	if len(m) != 1 || m[0] != "pattern1" {
		t.Errorf("multiFlag.Set() result = %v, want [pattern1]", m)
	}

	// Test String() method
	if s := m.String(); s != "pattern1" {
		t.Errorf("multiFlag.String() = %v, want pattern1", s)
	}

	// Test adding multiple patterns
	err = m.Set("pattern2")
	if err != nil {
		t.Errorf("multiFlag.Set() error = %v", err)
	}
	if len(m) != 2 || m[1] != "pattern2" {
		t.Errorf("multiFlag.Set() result = %v, want [pattern1 pattern2]", m)
	}
}

func TestCommand_Run(t *testing.T) {
	// Create a temporary test directory
	tmpDir, err := os.MkdirTemp("", "calldigraph-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a minimal Go module for testing
	if err := createTestModule(tmpDir); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		conf    config
		wantErr bool
	}{
		{
			name: "test function symbol",
			conf: config{
				symbol:     "example.com/testmod.TestFunc",
				root:       tmpDir,
				isDebug:    true,
				outputType: "all",
			},
			wantErr: false,
		},
		{
			name: "test type symbol",
			conf: config{
				symbol:     "example.com/testmod.TestType",
				root:       tmpDir,
				isDebug:    true,
				outputType: "s",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &command{
				conf:   tt.conf,
				logger: slog.Default(),
			}
			err := cmd.Run(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("command.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCommand_RunComplex(t *testing.T) {
	// Create a temporary test directory
	tmpDir, err := os.MkdirTemp("", "calldigraph-complex-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a complex test module
	if err := createComplexTestModule(tmpDir); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		conf    config
		wantErr bool
	}{
		{
			name: "test interface implementation",
			conf: config{
				symbol:     "example.com/testmod/complex.Handler",
				root:       tmpDir,
				isDebug:    true,
				outputType: "all",
			},
			wantErr: false,
		},
		{
			name: "test recursive function",
			conf: config{
				symbol:     "example.com/testmod/complex.RecursiveFunc",
				root:       tmpDir,
				isDebug:    true,
				outputType: "f",
			},
			wantErr: false,
		},
		{
			name: "test complex type dependencies",
			conf: config{
				symbol:     "example.com/testmod/complex.ComplexType",
				root:       tmpDir,
				isDebug:    true,
				outputType: "s",
			},
			wantErr: false,
		},
		{
			name: "test generic function",
			conf: config{
				symbol:     "example.com/testmod/complex.ProcessItems",
				root:       tmpDir,
				isDebug:    true,
				outputType: "f",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &command{
				conf:   tt.conf,
				logger: slog.Default(),
			}
			err := cmd.Run(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("command.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Helper function to create a test module
func createTestModule(dir string) error {
	files := map[string]string{
		"go.mod": `module example.com/testmod

go 1.21
`,
		"main.go": `package testmod

type TestType struct {
	Field string
}

func TestFunc() {
	var t TestType
	t.Field = "test"
}
`,
	}

	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			return err
		}
	}

	return nil
}

// Helper function to create a complex test module
func createComplexTestModule(dir string) error {
	files := map[string]string{
		"go.mod": `module example.com/testmod/complex

go 1.21
`,
		"interfaces.go": `package complex

// Handler is an interface that defines request handling
type Handler interface {
	Handle(req Request) Response
	Validate(req Request) error
}

// Request represents an incoming request
type Request struct {
	ID      string
	Payload interface{}
}

// Response represents an outgoing response
type Response struct {
	ID     string
	Result interface{}
	Error  error
}
`,
		"implementation.go": `package complex

import "fmt"

// DefaultHandler implements the Handler interface
type DefaultHandler struct {
	validator  Validator
	processor  Processor
	middleware []Middleware
}

// Validator validates requests
type Validator interface {
	Validate(req Request) error
}

// Processor processes requests
type Processor interface {
	Process(req Request) (interface{}, error)
}

// Middleware represents a middleware function
type Middleware func(Handler) Handler

func (h *DefaultHandler) Handle(req Request) Response {
	if err := h.Validate(req); err != nil {
		return Response{ID: req.ID, Error: err}
	}

	result, err := h.processor.Process(req)
	return Response{
		ID:     req.ID,
		Result: result,
		Error:  err,
	}
}

func (h *DefaultHandler) Validate(req Request) error {
	if req.ID == "" {
		return fmt.Errorf("request ID is required")
	}
	if h.validator != nil {
		return h.validator.Validate(req)
	}
	return nil
}
`,
		"recursive.go": `package complex

// RecursiveFunc demonstrates recursive function calls
func RecursiveFunc(n int) int {
	if n <= 1 {
		return 1
	}
	return n * RecursiveFunc(n-1)
}

// IndirectRecursion demonstrates indirect recursion
func IndirectRecursion1(n int) int {
	if n <= 0 {
		return 0
	}
	return IndirectRecursion2(n - 1)
}

func IndirectRecursion2(n int) int {
	if n <= 0 {
		return 1
	}
	return IndirectRecursion1(n)
}
`,
		"types.go": `package complex

import "context"

// ComplexType demonstrates complex type dependencies
type ComplexType struct {
	handler    Handler
	middleware []Middleware
	config     *Config
	client     *Client
	cache      Cache
}

// Config holds configuration
type Config struct {
	Timeout   int
	MaxRetries int
	Options    map[string]interface{}
}

// Client represents an external client
type Client struct {
	ctx     context.Context
	baseURL string
	config  *Config
}

// Cache represents a caching interface
type Cache interface {
	Get(key string) (interface{}, error)
	Set(key string, value interface{}) error
}
`,
		"generics.go": `package complex

// Item represents a generic item
type Item[T any] struct {
	Value T
	Meta  map[string]interface{}
}

// ProcessItems demonstrates generic function usage
func ProcessItems[T any](items []Item[T], fn func(T) T) []Item[T] {
	result := make([]Item[T], len(items))
	for i, item := range items {
		processed := fn(item.Value)
		result[i] = Item[T]{
			Value: processed,
			Meta:  item.Meta,
		}
	}
	return result
}

// Container is a generic container type
type Container[T any] struct {
	items []Item[T]
	cache Cache
}

func (c *Container[T]) Process(fn func(T) T) {
	c.items = ProcessItems(c.items, fn)
}
`,
	}

	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			return err
		}
	}

	return nil
}

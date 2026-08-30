// witshield-helper is the narrow privileged boundary for WitShield. It accepts
// typed playbook requests over a local Unix socket and never accepts a command
// line, executable path, or shell fragment from a client.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/witkitlab/witshield/internal/action"
	"github.com/witkitlab/witshield/internal/observation"
)

const (
	maxRequestBytes       = 1 << 20
	maxConcurrentRequests = 32
	packagePlanBase       = "/var/lib/witshield-helper/package-plans"
)

var version = "dev"
var commit = "unknown"
var buildDate = "unknown"

var attemptIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

type stringFlags []string

func (values *stringFlags) String() string { return strings.Join(*values, ",") }
func (values *stringFlags) Set(value string) error {
	*values = append(*values, value)
	return nil
}

type helperRequest struct {
	Token           string           `json:"token,omitempty"`
	Kind            string           `json:"kind,omitempty"`
	AttemptID       string           `json:"attemptId"`
	ActionID        string           `json:"actionId"`
	Type            action.Type      `json:"type"`
	Operation       action.Operation `json:"operation,omitempty"`
	Parameters      json.RawMessage  `json:"parameters"`
	State           json.RawMessage  `json:"state,omitempty"`
	RollbackPayload json.RawMessage  `json:"rollbackPayload,omitempty"`
}

type helperResponse struct {
	OK               bool                  `json:"ok"`
	Result           *action.Result        `json:"result,omitempty"`
	RollbackPayload  json.RawMessage       `json:"rollbackPayload,omitempty"`
	AuditReceipt     *action.Receipt       `json:"auditReceipt,omitempty"`
	Error            string                `json:"error,omitempty"`
	Processes        []observation.Process `json:"processes,omitempty"`
	ProcessObserved  int                   `json:"processObserved,omitempty"`
	ProcessTruncated bool                  `json:"processTruncated,omitempty"`
}

type server struct {
	engine           *action.Engine
	receipts         *receiptCache
	token            []byte
	slots            chan struct{}
	wg               sync.WaitGroup
	actionMu         sync.Mutex
	observeProcesses func(context.Context) (observation.ProcessSnapshot, error)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "apt-plan-guard" {
		if len(os.Args) != 3 || os.Geteuid() != 0 {
			fmt.Fprintln(os.Stderr, "witshield apt plan guard requires one transaction directory and root")
			os.Exit(2)
		}
		if err := action.RunPackagePlanGuard(os.Stdin, os.Args[2], packagePlanBase); err != nil {
			fmt.Fprintf(os.Stderr, "witshield rejected the locked APT plan: %v\n", err)
			os.Exit(1)
		}
		return
	}
	versionFlag := flag.Bool("version", false, "print version and exit")
	var protectedPrefixes, adminIPs stringFlags
	socketPath := flag.String("socket", "/run/witshield/helper.sock", "Unix socket path")
	tokenPath := flag.String("token-file", "/etc/witshield/helper.token", "strong local authentication token")
	stateKeyPath := flag.String("state-key-file", "/var/lib/witshield-helper/state.key", "root-only rollback-state signing key")
	groupName := flag.String("group", "", "optional local group allowed to read the token and connect")
	journalDir := flag.String("journal-dir", "/var/lib/witshield-helper/ssh-rollbacks", "durable SSH rollback journal directory")
	processJournalDir := flag.String("process-journal-dir", "/var/lib/witshield-helper/process-resumes", "durable temporary-process resume journal directory")
	receiptDir := flag.String("receipt-dir", "/var/lib/witshield-helper/receipts", "durable successful action receipt cache")
	flag.Var(&protectedPrefixes, "protected-prefix", "additional IP prefix which temporary bans must never target (repeatable)")
	flag.Var(&adminIPs, "admin-ip", "administrator IP which temporary bans must never target (repeatable)")
	flag.Parse()
	if *versionFlag {
		fmt.Printf("witshield-helper %s (commit %s, built %s)\n", version, commit, buildDate)
		return
	}

	if os.Geteuid() != 0 {
		log.Fatal("witshield-helper must run as root")
	}
	groupID, err := resolveGroup(*groupName)
	if err != nil {
		log.Fatal(err)
	}
	token, err := loadOrCreateToken(*tokenPath, groupID)
	if err != nil {
		log.Fatalf("token setup failed: %v", err)
	}
	stateKey, err := loadOrCreateToken(*stateKeyPath, -1)
	if err != nil {
		log.Fatalf("rollback-state key setup failed: %v", err)
	}
	engine, err := buildEngine(*journalDir, *processJournalDir, protectedPrefixes, adminIPs, groupID, stateKey)
	if err != nil {
		log.Fatalf("action engine setup failed: %v", err)
	}
	receipts, err := newReceiptCache(*receiptDir)
	if err != nil {
		log.Fatalf("receipt cache setup failed: %v", err)
	}
	listener, err := listenUnix(*socketPath, groupID)
	if err != nil {
		log.Fatalf("socket setup failed: %v", err)
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(*socketPath)
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	log.Printf("witshield-helper listening on %s with %d typed playbooks", *socketPath, len(engine.Types()))
	if err := (&server{engine: engine, receipts: receipts, token: token, observeProcesses: func(ctx context.Context) (observation.ProcessSnapshot, error) {
		return observation.SuspiciousProcesses(ctx, "/")
	}}).serve(ctx, listener); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Fatalf("helper server failed: %v", err)
	}
}

func buildEngine(journalDir, processJournalDir string, protectedPrefixValues, adminIPValues []string, groupID int, stateKey []byte) (*action.Engine, error) {
	const (
		aptGetPath    = "/usr/bin/apt-get"
		dpkgQueryPath = "/usr/bin/dpkg-query"
		sshdPath      = "/usr/sbin/sshd"
		systemctlPath = "/usr/bin/systemctl"
		nftPath       = "/usr/sbin/nft"
	)
	runner := action.NewExecRunner(aptGetPath, dpkgQueryPath, sshdPath, systemctlPath, nftPath)
	hookPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve helper executable for APT plan guard: %w", err)
	}
	packagePlaybook, err := action.NewPackageSecurityUpgradePlaybook(runner, aptGetPath, dpkgQueryPath, hookPath, packagePlanBase)
	if err != nil {
		return nil, fmt.Errorf("configure package upgrade plan guard: %w", err)
	}
	sshPlaybook, err := action.NewSSHPasswordHardeningPlaybook(action.SSHHardeningConfig{
		Runner: runner, SSHDPath: sshdPath, SystemctlPath: systemctlPath,
		ConfigPath: "/etc/ssh/sshd_config", ServiceName: "ssh", JournalDir: journalDir,
		DefaultRollbackDelay: 2 * time.Minute,
	})
	if err != nil {
		return nil, err
	}
	protected, err := parseProtectedPrefixes(protectedPrefixValues)
	if err != nil {
		return nil, err
	}
	protected = append(protected, localAddressPrefixes()...)
	currentAdmins, err := parseAddresses(adminIPValues)
	if err != nil {
		return nil, err
	}
	banPlaybook, err := action.NewTemporaryIPBanPlaybook(action.IPBanConfig{
		Runner: runner, NFTPath: nftPath, Protected: protected, CurrentAdminIPs: currentAdmins,
	})
	if err != nil {
		return nil, err
	}
	prepareContext, cancelPrepare := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancelPrepare()
	if err := banPlaybook.Prepare(prepareContext); err != nil {
		return nil, fmt.Errorf("prepare temporary-ban nftables infrastructure: %w", err)
	}
	permissionPlaybook, err := action.NewFilePermissionRepairPlaybook(defaultApprovedPaths(groupID))
	if err != nil {
		return nil, err
	}
	processPlaybook, err := action.NewTemporaryProcessSuspendPlaybook(action.NewSystemProcessController(), processJournalDir)
	if err != nil {
		return nil, err
	}
	return action.NewEngineWithStateKey(stateKey, packagePlaybook, sshPlaybook, banPlaybook, permissionPlaybook, processPlaybook)
}

func defaultApprovedPaths(groupID int) []action.ApprovedPath {
	rules := make([]action.ApprovedPath, 0, 5)
	addIfExists := func(rule action.ApprovedPath) {
		if _, err := os.Stat(rule.Path); err == nil {
			rules = append(rules, rule)
		}
	}
	addIfExists(action.ApprovedPath{
		Path: action.DefaultPermissionRepairSSHPath, FileModes: []fs.FileMode{0600, 0640, 0644}, UIDs: []int{0}, GIDs: []int{0},
	})
	for _, root := range action.DefaultPermissionRepairRoots() {
		addIfExists(action.ApprovedPath{
			Path: root, Descendants: true,
			FileModes: []fs.FileMode{0600, 0640}, DirectoryModes: []fs.FileMode{0700, 0750},
		})
	}
	return rules
}

func resolveGroup(name string) (int, error) {
	if name == "" {
		return -1, nil
	}
	group, err := user.LookupGroup(name)
	if err != nil {
		return -1, fmt.Errorf("look up helper group %q: %w", name, err)
	}
	groupID, err := strconv.Atoi(group.Gid)
	if err != nil || groupID < 0 {
		return -1, fmt.Errorf("helper group %q has an invalid numeric ID", name)
	}
	return groupID, nil
}

func loadOrCreateToken(path string, groupID int) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("token path must be absolute")
	}
	mode := fs.FileMode(0600)
	directoryMode := fs.FileMode(0700)
	if groupID >= 0 {
		mode = 0640
		directoryMode = 0750
	}
	if err := prepareOwnedDirectory(filepath.Dir(path), directoryMode, groupID); err != nil {
		return nil, err
	}

	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		random := make([]byte, 32)
		if _, err := rand.Read(random); err != nil {
			return nil, err
		}
		encoded := []byte(hex.EncodeToString(random))
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			return nil, err
		}
		created := false
		defer func() {
			if !created {
				_ = os.Remove(path)
			}
		}()
		if groupID >= 0 {
			if err := file.Chown(0, groupID); err != nil {
				file.Close()
				return nil, err
			}
		}
		if err := file.Chmod(mode); err != nil {
			file.Close()
			return nil, err
		}
		if _, err := file.Write(append(encoded, '\n')); err != nil {
			file.Close()
			return nil, err
		}
		if err := file.Sync(); err != nil {
			file.Close()
			return nil, err
		}
		if err := file.Close(); err != nil {
			return nil, err
		}
		directory, err := os.Open(filepath.Dir(path))
		if err != nil {
			return nil, err
		}
		if err := directory.Sync(); err != nil {
			directory.Close()
			return nil, err
		}
		if err := directory.Close(); err != nil {
			return nil, err
		}
		created = true
		return encoded, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("token file must be a regular non-symlink file")
	}
	expectedMode := mode.Perm()
	if info.Mode().Perm() != expectedMode {
		return nil, fmt.Errorf("token file must have mode %04o", expectedMode)
	}
	uid, gid, err := fileOwner(info)
	if err != nil {
		return nil, err
	}
	if uid != os.Geteuid() || (groupID >= 0 && gid != groupID) {
		return nil, errors.New("token file has an unexpected owner or group")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(encoded) == 65 && encoded[64] == '\n' {
		encoded = encoded[:64]
	} else if len(encoded) != 64 {
		return nil, errors.New("token file must contain exactly 64 hexadecimal characters and an optional final newline")
	}
	decoded, err := hex.DecodeString(string(encoded))
	if err != nil || len(decoded) != 32 || len(encoded) != 64 {
		return nil, errors.New("token file must contain exactly 256 bits encoded as lowercase hexadecimal")
	}
	if string(encoded) != strings.ToLower(string(encoded)) {
		return nil, errors.New("token file must use lowercase hexadecimal")
	}
	// Decode above only to validate entropy length. The wire token is always the
	// same 64-byte lowercase hexadecimal representation returned on creation;
	// returning decoded here would break authentication after a helper restart.
	return append([]byte(nil), encoded...), nil
}

func validateOwnedDirectory(path string, mode fs.FileMode, groupID int) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != mode.Perm() {
		return fmt.Errorf("directory %q has an unsafe type or mode", path)
	}
	uid, gid, err := fileOwner(info)
	if err != nil {
		return err
	}
	expectedUID := os.Geteuid()
	if groupID >= 0 {
		expectedUID = 0
	}
	if uid != expectedUID || (groupID >= 0 && gid != groupID) {
		return fmt.Errorf("directory %q has an unexpected owner or group", path)
	}
	return nil
}

func prepareOwnedDirectory(path string, mode fs.FileMode, groupID int) error {
	info, err := os.Lstat(path)
	if err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("directory %q must be a non-symlink directory", path)
		}
		uid, _, ownerErr := fileOwner(info)
		expectedUID := os.Geteuid()
		if groupID >= 0 {
			expectedUID = 0
		}
		if ownerErr != nil || uid != expectedUID {
			return fmt.Errorf("directory %q has an unexpected owner", path)
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(path, mode); err != nil {
			return err
		}
	} else {
		return err
	}
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	if groupID >= 0 {
		if err := os.Chown(path, 0, groupID); err != nil {
			return err
		}
	}
	return validateOwnedDirectory(path, mode, groupID)
}

func fileOwner(info fs.FileInfo) (int, int, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, errors.New("file ownership unavailable")
	}
	return int(stat.Uid), int(stat.Gid), nil
}

func listenUnix(path string, groupID int) (*net.UnixListener, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("socket path must be absolute")
	}
	directory := filepath.Dir(path)
	mode := fs.FileMode(0700)
	socketMode := fs.FileMode(0600)
	if groupID >= 0 {
		mode = 0750
		socketMode = 0660
	}
	if err := prepareOwnedDirectory(directory, mode, groupID); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil {
		uid, _, ownerErr := fileOwner(info)
		if info.Mode()&os.ModeSocket == 0 || ownerErr != nil || uid != os.Geteuid() {
			return nil, errors.New("refusing to replace a non-socket or foreign-owned socket path")
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, socketMode); err != nil {
		listener.Close()
		return nil, err
	}
	if groupID >= 0 {
		if err := os.Chown(path, 0, groupID); err != nil {
			listener.Close()
			return nil, err
		}
	}
	return listener, nil
}

func (s *server) serve(ctx context.Context, listener *net.UnixListener) error {
	defer s.wg.Wait()
	if s.slots == nil {
		s.slots = make(chan struct{}, maxConcurrentRequests)
	}
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case s.slots <- struct{}{}:
			s.wg.Add(1)
			go func() {
				defer func() {
					<-s.slots
					s.wg.Done()
				}()
				s.handle(ctx, connection)
			}()
		default:
			_ = connection.SetWriteDeadline(time.Now().Add(time.Second))
			s.writeResponse(connection, helperResponse{Error: "helper is busy"})
			_ = connection.Close()
		}
	}
}

func (s *server) handle(serverContext context.Context, connection *net.UnixConn) {
	defer connection.Close()
	stopDeadlineUpdate := context.AfterFunc(serverContext, func() {
		_ = connection.SetDeadline(time.Now())
	})
	defer stopDeadlineUpdate()
	_ = connection.SetReadDeadline(time.Now().Add(30 * time.Second))
	reader := bufio.NewReaderSize(connection, maxRequestBytes+1)
	line, err := reader.ReadSlice('\n')
	if err != nil {
		if errors.Is(err, bufio.ErrBufferFull) {
			s.writeResponse(connection, helperResponse{Error: "request exceeds size limit"})
		}
		return
	}
	if len(line) > maxRequestBytes {
		s.writeResponse(connection, helperResponse{Error: "request exceeds size limit"})
		return
	}
	var request helperRequest
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		s.writeResponse(connection, helperResponse{Error: "invalid request"})
		return
	}
	if err := ensureJSONEOF(decoder); err != nil {
		_ = s.writeResponse(connection, helperResponse{Error: "invalid request"})
		return
	}
	// The read deadline only protects the unauthenticated request phase. Valid
	// playbooks may legitimately run for up to ten minutes; keep the response
	// channel alive slightly longer than that budget.
	_ = connection.SetReadDeadline(time.Time{})
	_ = connection.SetWriteDeadline(time.Now().Add(11 * time.Minute))
	actor, authenticated := s.authenticate(connection, request.Token)
	if !authenticated {
		s.writeResponse(connection, helperResponse{Error: "authentication failed"})
		return
	}
	request.Token = ""
	if request.Kind != "" {
		s.handleObservation(serverContext, connection, request)
		return
	}
	if !attemptIDPattern.MatchString(request.AttemptID) {
		s.writeResponse(connection, helperResponse{Error: "invalid attempt identity"})
		return
	}
	if len(request.State) > 0 && len(request.RollbackPayload) > 0 {
		s.writeResponse(connection, helperResponse{Error: "state and rollbackPayload are mutually exclusive"})
		return
	}
	if request.Operation == "" {
		if len(request.RollbackPayload) > 0 {
			request.Operation = action.OperationRollback
		} else {
			request.Operation = action.OperationExecute
		}
	}
	state := request.State
	if len(request.RollbackPayload) > 0 {
		state = request.RollbackPayload
	}
	if (request.Operation == action.OperationPrecheck || request.Operation == action.OperationPreview ||
		request.Operation == action.OperationApply || request.Operation == action.OperationExecute) && len(state) > 0 {
		s.writeResponse(connection, helperResponse{Error: "rollback state is not accepted for this operation"})
		return
	}
	requestContext, cancel := context.WithTimeout(serverContext, action.PrivilegedExecutionTimeout)
	defer cancel()
	cacheable := request.Operation == action.OperationExecute || request.Operation == action.OperationRollback || request.Operation == action.OperationConfirm
	if cacheable {
		s.actionMu.Lock()
		defer s.actionMu.Unlock()
	}
	if s.receipts != nil && cacheable {
		if cached, found, cacheErr := s.receipts.load(request.AttemptID, request.ActionID, request.Type, request.Operation, request.Parameters, state); cacheErr != nil {
			s.writeResponse(connection, helperResponse{Error: "receipt cache validation failed"})
			return
		} else if found {
			s.writeResponse(connection, cached)
			return
		}
		if err := s.receipts.begin(request.AttemptID, request.ActionID, request.Type, request.Operation, request.Parameters, state); err != nil {
			s.writeResponse(connection, helperResponse{Error: "failed to persist action execution intent"})
			return
		}
	}
	receipt := s.engine.Run(requestContext, action.Request{
		ActionID: request.ActionID, Actor: actor, Type: request.Type,
		Operation: request.Operation, Parameters: request.Parameters, State: state,
	})
	response := helperResponse{
		OK: receipt.Success, RollbackPayload: receipt.State, AuditReceipt: &receipt, Error: receipt.Error,
	}
	for index := len(receipt.Steps) - 1; index >= 0; index-- {
		if receipt.Steps[index].Result != nil {
			response.Result = receipt.Steps[index].Result
			break
		}
	}
	if s.receipts != nil && cacheable {
		if err := s.receipts.save(request.AttemptID, request.ActionID, request.Type, request.Operation, request.Parameters, state, response); err != nil {
			response.OK = false
			if receipt.Success {
				response.Error = action.ReceiptPersistenceFailureMessage
			} else {
				response.Error = "action did not reach a verified state and durable receipt persistence also failed: " + receipt.Error
			}
		}
	}
	if err := s.writeResponse(connection, response); err != nil {
		log.Printf("failed to return durable helper receipt for action %q: %v", request.ActionID, err)
	}
}

func (s *server) handleObservation(serverContext context.Context, connection *net.UnixConn, request helperRequest) {
	if request.Kind != observation.ProcessQueryKind || request.AttemptID != "" || request.ActionID != "" || request.Type != "" || request.Operation != "" ||
		len(request.Parameters) != 0 || len(request.State) != 0 || len(request.RollbackPayload) != 0 || s.observeProcesses == nil {
		s.writeResponse(connection, helperResponse{Error: "invalid observation request"})
		return
	}
	ctx, cancel := context.WithTimeout(serverContext, 10*time.Second)
	defer cancel()
	snapshot, err := s.observeProcesses(ctx)
	if err != nil {
		s.writeResponse(connection, helperResponse{Error: "process observation failed"})
		return
	}
	if len(snapshot.Processes) > 256 || snapshot.Observed < len(snapshot.Processes) {
		s.writeResponse(connection, helperResponse{Error: "process observation exceeded safe capacity"})
		return
	}
	s.writeResponse(connection, helperResponse{OK: true, Processes: snapshot.Processes, ProcessObserved: snapshot.Observed, ProcessTruncated: snapshot.Truncated})
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("multiple JSON values")
	}
	return err
}

func (s *server) authenticate(connection *net.UnixConn, candidate string) (string, bool) {
	uid, peerErr := peerUID(connection)
	if peerErr == nil && uid == 0 {
		return "local-uid:0", true
	}
	if !tokenMatches(candidate, s.token) {
		return "", false
	}
	if peerErr == nil {
		return fmt.Sprintf("local-uid:%d", uid), true
	}
	return "local-token-client", true
}

func tokenMatches(candidate string, expected []byte) bool {
	provided := []byte(candidate)
	return len(provided) == len(expected) && subtle.ConstantTimeCompare(provided, expected) == 1
}

func (s *server) writeResponse(connection net.Conn, response helperResponse) error {
	encoded, err := json.Marshal(response)
	if err != nil {
		encoded = []byte(`{"ok":false,"error":"response encoding failed"}`)
	}
	_, err = connection.Write(append(encoded, '\n'))
	return err
}

func parseProtectedPrefixes(values []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("invalid protected prefix %q", value)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}

func parseAddresses(values []string) ([]netip.Addr, error) {
	addresses := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		address, err := netip.ParseAddr(value)
		if err != nil || address.Zone() != "" {
			return nil, fmt.Errorf("invalid administrator IP %q", value)
		}
		addresses = append(addresses, address.Unmap())
	}
	return addresses, nil
}

func localAddressPrefixes() []netip.Prefix {
	interfaceAddresses, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	prefixes := make([]netip.Prefix, 0, len(interfaceAddresses))
	for _, interfaceAddress := range interfaceAddresses {
		prefix, err := netip.ParsePrefix(interfaceAddress.String())
		if err != nil {
			continue
		}
		address := prefix.Addr().Unmap()
		bits := 128
		if address.Is4() {
			bits = 32
		}
		prefixes = append(prefixes, netip.PrefixFrom(address, bits))
	}
	return prefixes
}

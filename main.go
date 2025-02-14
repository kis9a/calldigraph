package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"go/types"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

type config struct {
	symbol     string
	root       string
	isDebug    bool
	outputType string
	excludes   []string
}

type command struct {
	conf   config
	logger *slog.Logger
}

func main() {
	conf, err := parseFlags()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	var logger *slog.Logger
	if conf.isDebug {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	} else {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}

	cmd := &command{
		conf:   conf,
		logger: logger,
	}

	if err := cmd.Run(context.Background()); err != nil {
		logger.Error("Command error", "error", err)
		os.Exit(1)
	}
}

type multiFlag []string

func (m *multiFlag) String() string {
	return strings.Join(*m, ",")
}

func (m *multiFlag) Set(value string) error {
	if fi, err := os.Stat(value); err == nil && !fi.IsDir() {
		f, err := os.Open(value)
		if err != nil {
			return fmt.Errorf("failed to open exclude file %q: %w", value, err)
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			*m = append(*m, line)
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("failed to read exclude file %q: %w", value, err)
		}
	} else {
		*m = append(*m, value)
	}
	return nil
}

func parseFlags() (config, error) {
	symbolFlag := flag.String("symbol", "", "Fully qualified symbol, e.g. github.com/xxx.(*Service).Method or github.com/xxx.TypeName")
	debugFlag := flag.Bool("debug", false, "Enable debug logging")
	typeFlag := flag.String("type", "all", "Output type: f=func calls, s=struct references, all=both")
	var excludePatterns multiFlag
	flag.Var(&excludePatterns, "exclude", "Exclude symbol patterns (or file containing them). May be repeated.")

	flag.Parse()

	if *symbolFlag == "" {
		return config{}, fmt.Errorf("symbol flag is required")
	}
	if flag.NArg() < 1 {
		return config{}, fmt.Errorf("module root directory must be specified")
	}
	moduleRoot := flag.Arg(0)

	return config{
		symbol:     *symbolFlag,
		root:       moduleRoot,
		isDebug:    *debugFlag,
		outputType: *typeFlag,
		excludes:   excludePatterns,
	}, nil
}

func (a *command) Run(ctx context.Context) error {
	absRoot, err := filepath.Abs(a.conf.root)
	if err != nil {
		return fmt.Errorf("failed to resolve module root: %w", err)
	}
	a.logger.Debug("Resolved module root", "absRoot", absRoot)

	modulePrefix, err := detectModulePrefix(absRoot, a.logger)
	if err != nil {
		return fmt.Errorf("failed to detect module prefix: %w", err)
	}
	if modulePrefix == "" {
		return fmt.Errorf("module prefix could not be detected")
	}
	a.logger.Debug("Detected module prefix", "modulePrefix", modulePrefix)

	importPath, receiver, symbolName, err := parseSymbol(a.conf.symbol)
	if err != nil {
		return fmt.Errorf("failed to parse symbol: %w", err)
	}
	a.logger.Debug("Parsed symbol", "importPath", importPath, "receiver", receiver, "symbolName", symbolName)

	shouldSkipPackage := func(pkgPath string) bool {
		for _, pattern := range a.conf.excludes {
			matched, err := path.Match(pattern, pkgPath)
			if err == nil && matched {
				return true
			}
		}
		return false
	}

	shouldExcludeSymbol := func(fullName string) bool {
		for _, pattern := range a.conf.excludes {
			matched, err := path.Match(pattern, fullName)
			if err == nil && matched {
				return true
			}
		}
		return false
	}

	pkgs, err := loadPackagesRecursively(absRoot, importPath, a.logger, shouldSkipPackage)
	if err != nil {
		return fmt.Errorf("loadPackagesRecursively: %w", err)
	}
	a.logger.Debug("Loaded packages", "count", len(pkgs))

	prog, ssaPkgs := ssautil.AllPackages(pkgs, ssa.InstantiateGenerics)
	prog.Build()

	isFuncRoot := true
	var rootFunc *ssa.Function
	var rootNamed *types.Named

	if receiver == "" {
		rootFunc = findFunction(ssaPkgs, importPath, symbolName)
	} else {
		rootFunc = findMethodFunction(prog, ssaPkgs, importPath, receiver, symbolName)
	}
	if rootFunc == nil {
		rootNamed = findNamedType(ssaPkgs, importPath, symbolName)
		if rootNamed == nil {
			return fmt.Errorf("root function/type not found: %s.%s", importPath, symbolName)
		}
		isFuncRoot = false
	}

	implIndex := buildImplementerIndex(prog, modulePrefix, shouldSkipPackage, shouldExcludeSymbol)

	if isFuncRoot {
		a.logger.Debug("Found root function", "func", rootFunc.String())
		cg, reachableFns := buildCallGraph(prog, rootFunc, modulePrefix, shouldSkipPackage, shouldExcludeSymbol, implIndex)

		structEdges := buildStructEdgesFromPackages(pkgs, shouldSkipPackage)

		funcToTypeEdges := [][2]string{}
		reachableTypes := make(map[*types.Named]bool)

		for fn := range reachableFns {
			if shouldExcludeSymbol(fn.String()) {
				continue
			}
			usedTypes := collectFunctionUsedTypes(fn)
			for _, nt := range usedTypes {
				if nt == nil {
					continue
				}
				if shouldSkipPackage(namedTypePackagePath(nt)) {
					continue
				}
				if shouldExcludeSymbol(namedTypeString(nt)) {
					continue
				}
				if !strings.HasPrefix(namedTypePackagePath(nt), modulePrefix) {
					continue
				}
				funcToTypeEdges = append(funcToTypeEdges, [2]string{fn.String(), namedTypeString(nt)})
				reachableTypes[nt] = true
			}
		}

		visitedType := make(map[*types.Named]bool)
		typeEdges := [][2]string{}

		var walkTypes func(*types.Named)
		walkTypes = func(t *types.Named) {
			if visitedType[t] {
				return
			}
			visitedType[t] = true

			children := structEdges[t]
			for _, child := range children {
				if shouldSkipPackage(namedTypePackagePath(child)) {
					continue
				}
				if shouldExcludeSymbol(namedTypeString(child)) {
					continue
				}
				if !strings.HasPrefix(namedTypePackagePath(child), modulePrefix) {
					continue
				}
				typeEdges = append(typeEdges, [2]string{namedTypeString(t), namedTypeString(child)})
				if !visitedType[child] {
					reachableTypes[child] = true
					walkTypes(child)
				}
			}
		}
		for t := range reachableTypes {
			walkTypes(t)
		}

		var funcEdges [][2]string
		for fn, node := range cg.Nodes {
			if fn == nil || fn.Pkg == nil || node == nil {
				continue
			}
			pkgPath := fn.Package().Pkg.Path()
			if shouldSkipPackage(pkgPath) {
				continue
			}
			if shouldExcludeSymbol(fn.String()) {
				continue
			}
			if !strings.HasPrefix(pkgPath, modulePrefix) {
				continue
			}
			for _, out := range node.Out {
				callee := out.Callee.Func
				if callee == nil || callee.Pkg == nil {
					continue
				}
				calleePath := callee.Pkg.Pkg.Path()
				if shouldSkipPackage(calleePath) {
					continue
				}
				if shouldExcludeSymbol(callee.String()) {
					continue
				}
				if !strings.HasPrefix(calleePath, modulePrefix) {
					continue
				}
				funcEdges = append(funcEdges, [2]string{fn.String(), callee.String()})
			}
		}

		switch a.conf.outputType {
		case "f":
			for _, e := range funcEdges {
				fmt.Printf("%q -> %q\n", e[0], e[1])
			}
		case "s":
			for _, e := range funcToTypeEdges {
				fmt.Printf("%q -> %q\n", e[0], e[1])
			}
			for _, e := range typeEdges {
				fmt.Printf("%q -> %q\n", e[0], e[1])
			}
		default:
			for _, e := range funcEdges {
				fmt.Printf("%q -> %q\n", e[0], e[1])
			}
			for _, e := range funcToTypeEdges {
				fmt.Printf("%q -> %q\n", e[0], e[1])
			}
			for _, e := range typeEdges {
				fmt.Printf("%q -> %q\n", e[0], e[1])
			}

		}
	} else {
		a.logger.Debug("Found root type", "type", namedTypeString(rootNamed))

		structEdges := buildStructEdgesFromPackages(pkgs, shouldSkipPackage)
		visitedType := make(map[*types.Named]bool)
		typeEdges := [][2]string{}

		var walkTypes func(*types.Named)
		walkTypes = func(t *types.Named) {
			if visitedType[t] {
				return
			}
			visitedType[t] = true
			for _, child := range structEdges[t] {
				if shouldSkipPackage(namedTypePackagePath(child)) {
					continue
				}
				if shouldExcludeSymbol(namedTypeString(child)) {
					continue
				}
				typeEdges = append(typeEdges, [2]string{
					namedTypeString(t),
					namedTypeString(child),
				})
				walkTypes(child)
			}
		}

		if !shouldSkipPackage(namedTypePackagePath(rootNamed)) &&
			!shouldExcludeSymbol(namedTypeString(rootNamed)) {
			walkTypes(rootNamed)
		}

		switch a.conf.outputType {
		case "s", "all":
			for _, e := range typeEdges {
				fmt.Printf("%q -> %q\n", e[0], e[1])
			}
		case "f":
			return fmt.Errorf("symbol %s is a type; function call graph requested", a.conf.symbol)
		}
	}

	return nil
}

func detectModulePrefix(dir string, logger *slog.Logger) (string, error) {
	goModPath := filepath.Join(dir, "go.mod")
	data, err := os.ReadFile(goModPath)
	if err != nil {
		logger.Debug("Failed to read go.mod", "error", err)
		return "", fmt.Errorf("failed to read go.mod: %w", err)
	}
	mf, err := modfile.Parse(goModPath, data, nil)
	if err != nil {
		return "", fmt.Errorf("failed to parse go.mod: %w", err)
	}
	if mf.Module == nil || mf.Module.Mod.Path == "" {
		return "", fmt.Errorf("module path not found in go.mod")
	}
	return mf.Module.Mod.Path, nil
}

func parseSymbol(symbol string) (importPath, receiver, symbolName string, err error) {
	lastDot := strings.LastIndex(symbol, ".")
	if lastDot == -1 || lastDot == len(symbol)-1 {
		return "", "", "", fmt.Errorf("invalid symbol format: %q", symbol)
	}
	importPathPart := symbol[:lastDot]
	symbolName = symbol[lastDot+1:]
	receiverStart := strings.Index(importPathPart, "(")
	if receiverStart != -1 && strings.Contains(importPathPart[receiverStart:], ")") {
		receiverEnd := strings.Index(importPathPart[receiverStart:], ")")
		if receiverEnd == -1 {
			return "", "", "", fmt.Errorf("closing ')' not found in %q", importPathPart)
		}
		receiverEnd += receiverStart
		receiver = importPathPart[receiverStart+1 : receiverEnd]
		if receiverStart >= 1 {
			importPath = strings.TrimSuffix(importPathPart[:receiverStart], ".")
		} else {
			importPath = importPathPart
		}
	} else {
		importPath = importPathPart
	}
	return importPath, receiver, symbolName, nil
}

func loadPackagesRecursively(
	dir, initialPattern string,
	logger *slog.Logger,
	skipPackage func(string) bool,
) ([]*packages.Package, error) {

	conf := &packages.Config{
		Mode: packages.NeedName |
			packages.NeedTypes |
			packages.NeedTypesInfo |
			packages.NeedImports |
			packages.NeedDeps |
			packages.NeedSyntax |
			packages.NeedCompiledGoFiles,
		Dir:   dir,
		Tests: false,
	}
	loadedMap := make(map[string]*packages.Package)

	var addPkg func(pkg *packages.Package)
	addPkg = func(pkg *packages.Package) {
		if pkg == nil || pkg.PkgPath == "" {
			return
		}
		if skipPackage(pkg.PkgPath) {
			logger.Debug("Skipping package", "pkgPath", pkg.PkgPath)
			return
		}
		if _, ok := loadedMap[pkg.PkgPath]; ok {
			return
		}
		loadedMap[pkg.PkgPath] = pkg
		for _, imp := range pkg.Imports {
			addPkg(imp)
		}
	}

	initialPkgs, err := packages.Load(conf, initialPattern)
	if err != nil {
		return nil, fmt.Errorf("packages.Load error: %w", err)
	}
	if packages.PrintErrors(initialPkgs) > 0 {
		return nil, fmt.Errorf("errors encountered in initial package loading")
	}

	for _, pkg := range initialPkgs {
		addPkg(pkg)
	}

	for {
		allPkgs := make([]*packages.Package, 0, len(loadedMap))
		for _, p := range loadedMap {
			allPkgs = append(allPkgs, p)
		}
		prog, _ := ssautil.AllPackages(allPkgs, ssa.InstantiateGenerics)
		prog.Build()

		missing := make(map[string]struct{})
		for _, ssaPkg := range prog.AllPackages() {
			if ssaPkg.Pkg == nil {
				continue
			}
			if skipPackage(ssaPkg.Pkg.Path()) {
				continue
			}
			if _, ok := loadedMap[ssaPkg.Pkg.Path()]; !ok {
				missing[ssaPkg.Pkg.Path()] = struct{}{}
			}
		}
		if len(missing) == 0 {
			break
		}
		missingSlice := make([]string, 0, len(missing))
		for pkgPath := range missing {
			missingSlice = append(missingSlice, pkgPath)
		}
		logger.Debug("Loading missing packages", "count", len(missingSlice), "packages", missingSlice)

		newPkgs, err := packages.Load(conf, missingSlice...)
		if err != nil {
			return nil, fmt.Errorf("packages.Load missing error: %w", err)
		}
		if packages.PrintErrors(newPkgs) > 0 {
			return nil, fmt.Errorf("errors encountered in missing package loading")
		}
		for _, p := range newPkgs {
			addPkg(p)
		}
	}

	result := make([]*packages.Package, 0, len(loadedMap))
	for _, p := range loadedMap {
		result = append(result, p)
	}
	return result, nil
}

func findFunction(ssaPkgs []*ssa.Package, importPath, function string) *ssa.Function {
	for _, pkg := range ssaPkgs {
		if pkg.Pkg.Path() == importPath {
			if fn := pkg.Func(function); fn != nil {
				return fn
			}
		}
	}
	return nil
}

func findMethodFunction(
	prog *ssa.Program,
	ssapkgs []*ssa.Package,
	importPath, receiver, function string,
) *ssa.Function {
	for _, pkg := range ssapkgs {
		if pkg.Pkg.Path() != importPath {
			continue
		}
		for _, member := range pkg.Members {
			t, ok := member.(*ssa.Type)
			if !ok {
				continue
			}
			if t.Name() == receiver || "*"+t.Name() == receiver {
				var T types.Type = t.Type()
				if strings.HasPrefix(receiver, "*") {
					T = types.NewPointer(t.Type())
				}
				ms := prog.MethodSets.MethodSet(T)
				for i := 0; i < ms.Len(); i++ {
					sel := ms.At(i)
					if sel.Obj().Name() == function {
						return prog.MethodValue(sel)
					}
				}
			}
		}
	}
	return nil
}

func findNamedType(ssaPkgs []*ssa.Package, importPath, typeName string) *types.Named {
	for _, pkg := range ssaPkgs {
		if pkg.Pkg.Path() != importPath {
			continue
		}
		for _, member := range pkg.Members {
			if t, ok := member.(*ssa.Type); ok {
				if t.Name() == typeName {
					if named, ok := t.Type().(*types.Named); ok {
						return named
					}
				}
			}
		}
	}
	return nil
}

type implementerIndex struct {
	Type  types.Type
	Funcs map[string]*ssa.Function
}

func buildImplementerIndex(
	prog *ssa.Program,
	modulePrefix string,
	skipPkg func(string) bool,
	skipSym func(string) bool,
) []implementerIndex {

	var index []implementerIndex

	for _, ssaPkg := range prog.AllPackages() {
		if ssaPkg.Pkg == nil {
			continue
		}
		pkgPath := ssaPkg.Pkg.Path()
		if !strings.HasPrefix(pkgPath, modulePrefix) {
			continue
		}
		if skipPkg(pkgPath) {
			continue
		}
		for _, mem := range ssaPkg.Members {
			t, ok := mem.(*ssa.Type)
			if !ok {
				continue
			}
			if _, isIface := t.Type().Underlying().(*types.Interface); isIface {
				continue
			}
			fullTypeName := pkgPath + "." + t.Name()
			if skipSym(fullTypeName) {
				continue
			}

			msVal := make(map[string]*ssa.Function)
			var TT types.Type = t.Type()

			ms := prog.MethodSets.MethodSet(TT)
			for i := 0; i < ms.Len(); i++ {
				sel := ms.At(i)
				mName := sel.Obj().Name()
				fn := prog.MethodValue(sel)
				if fn != nil {
					if !skipSym(fn.String()) {
						msVal[mName] = fn
					}
				}
			}

			ptrT := types.NewPointer(TT)
			msPtr := prog.MethodSets.MethodSet(ptrT)
			for i := 0; i < msPtr.Len(); i++ {
				sel := msPtr.At(i)
				mName := sel.Obj().Name()
				fn := prog.MethodValue(sel)
				if fn != nil {
					if !skipSym(fn.String()) {
						msVal[mName] = fn
					}
				}
			}

			if len(msVal) > 0 {
				index = append(index, implementerIndex{
					Type:  TT,
					Funcs: msVal,
				})
			}
		}
	}
	return index
}

func buildCallGraph(
	prog *ssa.Program,
	root *ssa.Function,
	modulePrefix string,
	skipPkg func(string) bool,
	skipSym func(string) bool,
	implIndex []implementerIndex,
) (*callgraph.Graph, map[*ssa.Function]bool) {

	cg := callgraph.New(root)
	visited := make(map[*ssa.Function]bool)

	var dfs func(fn *ssa.Function)
	dfs = func(fn *ssa.Function) {
		if fn == nil || fn.Pkg == nil {
			return
		}
		if visited[fn] {
			return
		}
		pkgPath := fn.Package().Pkg.Path()
		if skipPkg(pkgPath) {
			return
		}
		if !strings.HasPrefix(pkgPath, modulePrefix) {
			return
		}
		if skipSym(fn.String()) {
			return
		}
		visited[fn] = true

		for _, block := range fn.Blocks {
			for _, instr := range block.Instrs {
				callInstr, ok := instr.(ssa.CallInstruction)
				if !ok {
					continue
				}
				callCommon := callInstr.Common()
				callee := callCommon.StaticCallee()
				if callee != nil {
					if !skipSym(callee.String()) {
						from := cg.CreateNode(fn)
						to := cg.CreateNode(callee)
						callgraph.AddEdge(from, callInstr, to)
						dfs(callee)
					}
					continue
				}
				if callCommon.Value != nil {
					t := callCommon.Value.Type()
					if t == nil {
						continue
					}
					iface, ok := t.Underlying().(*types.Interface)
					if !ok {
						continue
					}
					mName := callCommon.Method.Name()

					for _, idx := range implIndex {
						if !types.Implements(idx.Type, iface) &&
							!types.Implements(types.NewPointer(idx.Type), iface) {
							continue
						}
						cfn := idx.Funcs[mName]
						if cfn == nil {
							continue
						}
						if skipSym(cfn.String()) {
							continue
						}
						from := cg.CreateNode(fn)
						to := cg.CreateNode(cfn)
						callgraph.AddEdge(from, callInstr, to)
						dfs(cfn)
					}
				}
			}
		}
	}

	dfs(root)
	return cg, visited
}

func buildStructEdgesFromPackages(
	pkgs []*packages.Package,
	skipPackage func(string) bool,
) map[*types.Named][]*types.Named {

	edges := make(map[*types.Named][]*types.Named)
	visited := make(map[*types.Named]bool)

	var collectFields func(n *types.Named)
	collectFields = func(n *types.Named) {
		if visited[n] {
			return
		}
		visited[n] = true

		st, ok := n.Underlying().(*types.Struct)
		if !ok {
			return
		}
		for i := 0; i < st.NumFields(); i++ {
			ft := st.Field(i).Type()
			child := extractNamed(ft)
			if child != nil {
				edges[n] = append(edges[n], child)
				collectFields(child)
			}
		}
	}

	for _, pkg := range pkgs {
		if pkg.Types == nil || pkg.Types.Scope() == nil {
			continue
		}
		if skipPackage(pkg.PkgPath) {
			continue
		}

		scope := pkg.Types.Scope()
		for _, name := range scope.Names() {
			obj := scope.Lookup(name)
			if obj == nil {
				continue
			}
			tn, ok := obj.(*types.TypeName)
			if !ok {
				continue
			}
			named, ok := tn.Type().(*types.Named)
			if !ok {
				continue
			}
			collectFields(named)
		}
	}

	return edges
}

func collectFunctionUsedTypes(fn *ssa.Function) []*types.Named {
	found := make(map[*types.Named]bool)

	var collect func(types.Type)
	collect = func(tt types.Type) {
		named := extractNamed(tt)
		if named != nil {
			found[named] = true
		}
		switch u := tt.Underlying().(type) {
		case *types.Pointer:
			collect(u.Elem())
		case *types.Slice:
			collect(u.Elem())
		case *types.Array:
			collect(u.Elem())
		case *types.Map:
			collect(u.Key())
			collect(u.Elem())
		case *types.Chan:
			collect(u.Elem())
		case *types.Signature:
			for i := 0; i < u.Params().Len(); i++ {
				collect(u.Params().At(i).Type())
			}
			for i := 0; i < u.Results().Len(); i++ {
				collect(u.Results().At(i).Type())
			}
		}
	}

	if fn.Signature != nil {
		for i := 0; i < fn.Signature.Params().Len(); i++ {
			collect(fn.Signature.Params().At(i).Type())
		}
		for i := 0; i < fn.Signature.Results().Len(); i++ {
			collect(fn.Signature.Results().At(i).Type())
		}
	}

	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			if val, ok := instr.(ssa.Value); ok {
				collect(val.Type())
			}
			var ops []*ssa.Value
			ops = instr.Operands(ops)
			for _, op := range ops {
				if op == nil {
					continue
				}
				if *op != nil {
					collect((*op).Type())
				}
			}
		}
	}

	result := make([]*types.Named, 0, len(found))
	for nt := range found {
		result = append(result, nt)
	}
	return result
}

func extractNamed(t types.Type) *types.Named {
	for {
		switch u := t.(type) {
		case *types.Named:
			return u
		case *types.Pointer:
			t = u.Elem()
		default:
			return nil
		}
	}
}

func namedTypeString(nt *types.Named) string {
	obj := nt.Obj()
	if obj == nil || obj.Pkg() == nil {
		return nt.String()
	}
	return obj.Pkg().Path() + "." + obj.Name()
}

func namedTypePackagePath(nt *types.Named) string {
	if nt == nil || nt.Obj() == nil || nt.Obj().Pkg() == nil {
		return ""
	}
	return nt.Obj().Pkg().Path()
}

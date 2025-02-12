package main

import (
	"context"
	"flag"
	"fmt"
	"go/types"
	"log/slog"
	"os"
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

func parseFlags() (config, error) {
	symbolFlag := flag.String("symbol", "", "The fully qualified symbol (function/method or type, e.g., github.com/xxx.(*Service).Method or github.com/xxx.TypeName)")
	debugFlag := flag.Bool("debug", false, "Enable debug logging")
	typeFlag := flag.String("type", "all", "Output type: f for function calls, s for struct references, all for both (default)")

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
	}, nil
}

func (a *command) Run(ctx context.Context) error {
	absRoot, err := filepath.Abs(a.conf.root)
	if err != nil {
		return fmt.Errorf("failed to resolve module root path: %w", err)
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
		return fmt.Errorf("failed to parse symbol flag: %w", err)
	}
	a.logger.Debug("Parsed symbol", "importPath", importPath, "receiver", receiver, "symbolName", symbolName)

	pkgs, err := loadPackagesRecursively(absRoot, importPath, a.logger)
	if err != nil {
		return fmt.Errorf("failed to load packages recursively: %w", err)
	}
	a.logger.Debug("Packages loaded (recursively)", "packageCount", len(pkgs))

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

	if isFuncRoot {
		a.logger.Debug("Found root function", "rootFunc", rootFunc.String())

		cg, reachableFuncs := buildCallGraph(prog, rootFunc, modulePrefix, a.logger)

		structEdgesMap := buildStructEdgesFromPackages(pkgs)

		funcToTypeEdges := make([][2]string, 0)
		reachableTypes := make(map[*types.Named]bool)

		for fn := range reachableFuncs {
			usedTypes := collectFunctionUsedTypes(fn)
			for _, nt := range usedTypes {
				if !strings.HasPrefix(namedTypePackagePath(nt), modulePrefix) {
					continue
				}
				funcToTypeEdges = append(funcToTypeEdges, [2]string{
					fn.String(),
					namedTypeString(nt),
				})
				reachableTypes[nt] = true
			}
		}

		typeEdges := make([][2]string, 0)
		visitedType := make(map[*types.Named]bool)

		var walkTypes func(t *types.Named)
		walkTypes = func(t *types.Named) {
			if visitedType[t] {
				return
			}
			visitedType[t] = true

			for _, child := range structEdgesMap[t] {
				if !strings.HasPrefix(namedTypePackagePath(child), modulePrefix) {
					continue
				}
				typeEdges = append(typeEdges, [2]string{
					namedTypeString(t),
					namedTypeString(child),
				})
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
			if fn == nil || fn.Pkg == nil {
				continue
			}
			if !strings.HasPrefix(fn.Package().Pkg.Path(), modulePrefix) {
				continue
			}
			if node == nil {
				continue
			}
			for _, edge := range node.Out {
				calleeFn := edge.Callee.Func
				if calleeFn == nil || calleeFn.Pkg == nil {
					continue
				}
				if !strings.HasPrefix(calleeFn.Package().Pkg.Path(), modulePrefix) {
					continue
				}
				funcEdges = append(funcEdges, [2]string{
					fn.String(),
					calleeFn.String(),
				})
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
		a.logger.Debug("Found root type", "rootType", namedTypeString(rootNamed))
		structEdgesMap := buildStructEdgesFromPackages(pkgs)
		typeEdges := make([][2]string, 0)
		visitedType := make(map[*types.Named]bool)

		var walkTypes func(t *types.Named)
		walkTypes = func(t *types.Named) {
			if visitedType[t] {
				return
			}
			visitedType[t] = true

			for _, child := range structEdgesMap[t] {
				if !strings.HasPrefix(namedTypePackagePath(child), modulePrefix) {
					continue
				}
				typeEdges = append(typeEdges, [2]string{
					namedTypeString(t),
					namedTypeString(child),
				})
				walkTypes(child)
			}
		}
		walkTypes(rootNamed)

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

func loadPackagesRecursively(dir, initialPattern string, logger *slog.Logger) ([]*packages.Package, error) {
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
		if _, exists := loadedMap[pkg.PkgPath]; exists {
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
		return nil, fmt.Errorf("errors encountered during initial package loading")
	}
	for _, pkg := range initialPkgs {
		addPkg(pkg)
	}

	for {
		allPkgs := make([]*packages.Package, 0, len(loadedMap))
		for _, pkg := range loadedMap {
			allPkgs = append(allPkgs, pkg)
		}
		prog, _ := ssautil.AllPackages(allPkgs, ssa.InstantiateGenerics)
		prog.Build()

		missingSet := make(map[string]struct{})
		for _, ssaPkg := range prog.AllPackages() {
			if ssaPkg.Pkg == nil {
				continue
			}
			pkgPath := ssaPkg.Pkg.Path()
			if _, ok := loadedMap[pkgPath]; !ok {
				missingSet[pkgPath] = struct{}{}
			}
		}

		if len(missingSet) == 0 {
			break
		}

		missingSlice := make([]string, 0, len(missingSet))
		for pkgPath := range missingSet {
			missingSlice = append(missingSlice, pkgPath)
		}
		logger.Debug("Loading missing packages", "packages", missingSlice)
		newPkgs, err := packages.Load(conf, missingSlice...)
		if err != nil {
			return nil, fmt.Errorf("packages.Load error (missing packages): %w", err)
		}
		if packages.PrintErrors(newPkgs) > 0 {
			return nil, fmt.Errorf("errors encountered during missing package loading")
		}
		for _, pkg := range newPkgs {
			addPkg(pkg)
		}
	}

	result := make([]*packages.Package, 0, len(loadedMap))
	for _, pkg := range loadedMap {
		result = append(result, pkg)
	}
	return result, nil
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
		return "", "", "", fmt.Errorf("invalid format: missing '.' in symbol (%q)", symbol)
	}
	importPathPart := symbol[:lastDot]
	symbolName = symbol[lastDot+1:]
	receiverStart := strings.Index(importPathPart, "(")
	if receiverStart != -1 && strings.Contains(importPathPart[receiverStart:], ")") {
		receiverEnd := strings.Index(importPathPart[receiverStart:], ")")
		if receiverEnd == -1 {
			return "", "", "", fmt.Errorf("closing ')' not found for receiver in %q", importPathPart)
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

func findFunction(pkgs []*ssa.Package, importPath, function string) *ssa.Function {
	for _, pkg := range pkgs {
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
	pkgs []*ssa.Package,
	importPath, receiver, function string,
) *ssa.Function {
	for _, pkg := range pkgs {
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

func buildCallGraph(
	prog *ssa.Program,
	root *ssa.Function,
	modulePrefix string,
	logger *slog.Logger,
) (*callgraph.Graph, map[*ssa.Function]bool) {

	cg := callgraph.New(root)
	visited := make(map[*ssa.Function]bool)

	var dfs func(fn *ssa.Function)
	dfs = func(fn *ssa.Function) {
		if fn == nil || fn.Pkg == nil {
			return
		}
		if !strings.HasPrefix(fn.Package().Pkg.Path(), modulePrefix) {
			return
		}
		if visited[fn] {
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
					from := cg.CreateNode(fn)
					to := cg.CreateNode(callee)
					callgraph.AddEdge(from, callInstr, to)
					dfs(callee)
					continue
				}
				if callCommon.Value != nil {
					t := callCommon.Value.Type()
					if t != nil {
						iface, ok := t.Underlying().(*types.Interface)
						if ok {
							mname := callCommon.Method.Name()
							for _, pkg := range prog.AllPackages() {
								if pkg.Pkg == nil {
									continue
								}
								if !strings.HasPrefix(pkg.Pkg.Path(), modulePrefix) {
									continue
								}
								for _, mem := range pkg.Members {
									ssaType, ok := mem.(*ssa.Type)
									if !ok {
										continue
									}
									if _, isIface := ssaType.Type().Underlying().(*types.Interface); isIface {
										continue
									}
									concrete := ssaType.Type()
									if !types.Implements(concrete, iface) &&
										!types.Implements(types.NewPointer(concrete), iface) {
										continue
									}
									m := lookupMethodSafe(prog, concrete, mname)
									if m == nil {
										m = lookupMethodSafe(prog, types.NewPointer(concrete), mname)
									}
									if m == nil {
										continue
									}
									from := cg.CreateNode(fn)
									to := cg.CreateNode(m)
									callgraph.AddEdge(from, callInstr, to)
									dfs(m)
								}
							}
						}
					}
				}
			}
		}
	}

	dfs(root)
	return cg, visited
}

func lookupMethodSafe(prog *ssa.Program, T types.Type, mname string) *ssa.Function {
	ms := prog.MethodSets.MethodSet(T)
	for i := 0; i < ms.Len(); i++ {
		sel := ms.At(i)
		if sel.Obj().Name() == mname {
			return prog.MethodValue(sel)
		}
	}
	return nil
}

func buildStructEdgesFromPackages(pkgs []*packages.Package) map[*types.Named][]*types.Named {
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
			named := extractNamed(ft)
			if named != nil {
				edges[n] = append(edges[n], named)
				collectFields(named)
			}
		}
	}

	for _, pkg := range pkgs {
		if pkg.Types == nil || pkg.Types.Scope() == nil {
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

	var collect func(t types.Type)
	collect = func(t types.Type) {
		named := extractNamed(t)
		if named != nil {
			found[named] = true
		}
		switch u := t.Underlying().(type) {
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
		sig := fn.Signature
		for i := 0; i < sig.Params().Len(); i++ {
			collect(sig.Params().At(i).Type())
		}
		for i := 0; i < sig.Results().Len(); i++ {
			collect(sig.Results().At(i).Type())
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
				val := *op
				if val == nil {
					continue
				}
				collect(val.Type())
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

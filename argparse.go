package aarvion

import (
	"strings"
	"unicode"
)

type argExit struct {
	code   int
	stdout string
	stderr string
}

type parsedArgs struct {
	cmd    string
	values map[string]string
}

const mainUsage = "usage: aarvion [-h] {init,whoami,check,status} ...\n"

const mainHelp = mainUsage + "\n" +
	"Aarvion developer data plane\n" +
	"\n" +
	"positional arguments:\n" +
	"  {init,whoami,check,status}\n" +
	"    init                connect an agent and write local config\n" +
	"    whoami              show the resolved local config\n" +
	"    check               evaluate one request against the policy (CI gate)\n" +
	"    status              show bundle/provenance state\n" +
	"\n" +
	"options:\n" +
	"  -h, --help            show this help message and exit\n"

type subParser struct {
	name     string
	options  []string
	required []string
	usage    string
	help     string
}

var initUsage = "usage: aarvion init [-h] [--api-key API_KEY] [--agent AGENT]\n" +
	"                    [--api-url API_URL]\n"

var checkUsage = "usage: aarvion check [-h] [--method METHOD] --host HOST [--path PATH]\n" +
	"                     [--body BODY]\n"

var subParsers = map[string]subParser{
	"init": {"init", []string{"--api-key", "--agent", "--api-url"}, nil, initUsage, initUsage +
		"\n" +
		"options:\n" +
		"  -h, --help         show this help message and exit\n" +
		"  --api-key API_KEY  org dev key (or set AARVION_API_KEY)\n" +
		"  --agent AGENT      agent name (default: project directory name)\n" +
		"  --api-url API_URL  backend base URL\n"},
	"whoami": {"whoami", nil, nil, "usage: aarvion whoami [-h]\n", "usage: aarvion whoami [-h]\n" +
		"\n" +
		"options:\n" +
		"  -h, --help  show this help message and exit\n"},
	"check": {"check", []string{"--method", "--host", "--path", "--body"}, []string{"--host"}, checkUsage, checkUsage +
		"\n" +
		"options:\n" +
		"  -h, --help       show this help message and exit\n" +
		"  --method METHOD\n" +
		"  --host HOST\n" +
		"  --path PATH\n" +
		"  --body BODY      request body, or @file\n"},
	"status": {"status", []string{"--state-dir"}, nil, "usage: aarvion status [-h] [--state-dir STATE_DIR]\n",
		"usage: aarvion status [-h] [--state-dir STATE_DIR]\n" +
			"\n" +
			"options:\n" +
			"  -h, --help            show this help message and exit\n" +
			"  --state-dir STATE_DIR\n" +
			"                        override the SDK state directory\n"},
}

func argError(usage, prog, msg string) *argExit {
	return &argExit{code: 2, stderr: usage + prog + ": error: " + msg + "\n"}
}

type argOpt struct {
	option    string
	explicit  *string
	shortForm bool
	unknown   bool
}

func allDigits(s string) bool {
	for _, r := range s {
		if !unicode.Is(unicode.Nd, r) && !isPyDigit(r) {
			return false
		}
	}
	return true
}

func isNegativeNumber(s string) bool {
	if len(s) < 2 || s[0] != '-' {
		return false
	}
	rest := s[1:]
	a, b, found := strings.Cut(rest, ".")
	if !found {
		return rest != "" && allDigits(rest)
	}
	return allDigits(a) && allDigits(b) && b != ""
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func strp(s string) *string { return &s }

func classifyArg(arg string, options []string, usage, prog string) (*argOpt, *argExit) {
	if arg == "" || arg[0] != '-' {
		return nil, nil
	}
	if contains(options, arg) {
		return &argOpt{option: arg}, nil
	}
	if len(arg) == 1 {
		return nil, nil
	}
	if eq := strings.IndexByte(arg, '='); eq >= 0 && contains(options, arg[:eq]) {
		return &argOpt{option: arg[:eq], explicit: strp(arg[eq+1:])}, nil
	}
	var tuples []argOpt
	if strings.HasPrefix(arg, "--") {
		prefix := arg
		var explicit *string
		if eq := strings.IndexByte(arg, '='); eq >= 0 {
			prefix = arg[:eq]
			explicit = strp(arg[eq+1:])
		}
		for _, o := range options {
			if strings.HasPrefix(o, prefix) {
				tuples = append(tuples, argOpt{option: o, explicit: explicit})
			}
		}
	} else {
		shortPrefix := arg[:2]
		shortExplicit := arg[2:]
		for _, o := range options {
			if o == shortPrefix {
				tuples = append(tuples, argOpt{option: o, explicit: strp(shortExplicit), shortForm: true})
			} else if strings.HasPrefix(o, arg) {
				tuples = append(tuples, argOpt{option: o})
			}
		}
	}
	if len(tuples) > 1 {
		names := make([]string, len(tuples))
		for i, t := range tuples {
			names[i] = t.option
		}
		return nil, argError(usage, prog, "ambiguous option: "+arg+" could match "+strings.Join(names, ", "))
	}
	if len(tuples) == 1 {
		return &tuples[0], nil
	}
	if isNegativeNumber(arg) {
		return nil, nil
	}
	if strings.Contains(arg, " ") {
		return nil, nil
	}
	return &argOpt{unknown: true}, nil
}

func ignoredExplicit(o *argOpt) bool {
	return o.explicit != nil && !(o.shortForm && *o.explicit != "")
}

func parseCLIArgs(argv []string) (*parsedArgs, *argExit) {
	mainOptions := []string{"-h", "--help"}
	var extras []string
	parsed := &parsedArgs{values: map[string]string{}}
	dashdash := false
	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		if !dashdash && arg == "--" {
			dashdash = true
			continue
		}
		if !dashdash {
			o, ex := classifyArg(arg, mainOptions, mainUsage, "aarvion")
			if ex != nil {
				return nil, ex
			}
			if o != nil {
				if o.unknown {
					extras = append(extras, arg)
					continue
				}
				if ignoredExplicit(o) {
					return nil, argError(mainUsage, "aarvion", "argument -h/--help: ignored explicit argument "+pyRepr(*o.explicit))
				}
				return nil, &argExit{code: 0, stdout: mainHelp}
			}
		}
		sub, ok := subParsers[arg]
		if !ok {
			return nil, argError(mainUsage, "aarvion", "argument cmd: invalid choice: "+pyRepr(arg)+
				" (choose from 'init', 'whoami', 'check', 'status')")
		}
		parsed.cmd = arg
		more, ex := parseSubArgs(sub, argv[i+1:], parsed)
		if ex != nil {
			return nil, ex
		}
		extras = append(extras, more...)
		break
	}
	if parsed.cmd == "" {
		return nil, argError(mainUsage, "aarvion", "the following arguments are required: cmd")
	}
	if len(extras) > 0 {
		return nil, argError(mainUsage, "aarvion", "unrecognized arguments: "+strings.Join(extras, " "))
	}
	return parsed, nil
}

func parseSubArgs(sub subParser, args []string, parsed *parsedArgs) ([]string, *argExit) {
	options := append([]string{"-h", "--help"}, sub.options...)
	prog := "aarvion " + sub.name
	var extras []string
	kinds := make([]*argOpt, len(args))
	firstDashdash := len(args)
	for i, a := range args {
		if a == "--" {
			firstDashdash = i
			break
		}
		o, ex := classifyArg(a, options, sub.usage, prog)
		if ex != nil {
			return nil, ex
		}
		kinds[i] = o
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if i >= firstDashdash {
			extras = append(extras, arg)
			continue
		}
		o := kinds[i]
		if o == nil || o.unknown {
			extras = append(extras, arg)
			continue
		}
		if o.option == "-h" || o.option == "--help" {
			if ignoredExplicit(o) {
				return nil, argError(sub.usage, prog, "argument -h/--help: ignored explicit argument "+pyRepr(*o.explicit))
			}
			return nil, &argExit{code: 0, stdout: sub.help}
		}
		var value string
		if o.explicit != nil {
			value = *o.explicit
		} else {
			if !(i+1 < firstDashdash && kinds[i+1] == nil) {
				return nil, argError(sub.usage, prog, "argument "+o.option+": expected one argument")
			}
			i++
			value = args[i]
		}
		parsed.values[o.option] = value
	}
	var missing []string
	for _, r := range sub.required {
		if _, ok := parsed.values[r]; !ok {
			missing = append(missing, r)
		}
	}
	if len(missing) > 0 {
		return nil, argError(sub.usage, prog, "the following arguments are required: "+strings.Join(missing, ", "))
	}
	return extras, nil
}

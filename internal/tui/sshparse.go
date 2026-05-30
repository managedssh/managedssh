package tui

import (
	"fmt"
	"strconv"
	"strings"
)

type parsedSSH struct {
	Hostname string
	User     string
	Port     int
	KeyPath  string
}

// parseSSHCommand parses a subset of the ssh(1) command line.
// Recognised forms (flags may appear in any order before the destination):
//
//	ssh [user@]host
//	ssh -p port [user@]host
//	ssh -i keypath [user@]host
//	ssh -l user host
//
// Unknown flags and everything after the destination are silently ignored.
func parseSSHCommand(input string) (parsedSSH, error) {
	tokens, err := tokenizeSSH(input)
	if err != nil {
		return parsedSSH{}, err
	}
	if len(tokens) == 0 {
		return parsedSSH{}, fmt.Errorf("empty SSH command")
	}
	if tokens[0] == "ssh" {
		tokens = tokens[1:]
	}

	// Flags that consume the next token as their argument.
	argFlags := map[string]bool{
		"-b": true, "-c": true, "-D": true, "-e": true, "-E": true,
		"-F": true, "-i": true, "-J": true, "-L": true, "-l": true,
		"-m": true, "-o": true, "-p": true, "-Q": true, "-R": true,
		"-S": true, "-w": true,
	}

	var result parsedSSH
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]

		if tok == "--" {
			// destination follows
			i++
			if i < len(tokens) {
				result.Hostname, result.User = splitDestination(tokens[i])
			}
			break
		}

		if strings.HasPrefix(tok, "-") && len(tok) >= 2 {
			flag := tok[:2]
			var val string
			if len(tok) > 2 {
				// value attached: -p2222 or -i/path/key
				val = tok[2:]
			} else if argFlags[flag] {
				i++
				if i >= len(tokens) {
					return parsedSSH{}, fmt.Errorf("flag %s requires an argument", flag)
				}
				val = tokens[i]
			}

			switch flag {
			case "-i":
				result.KeyPath = val
			case "-p":
				p, err := strconv.Atoi(val)
				if err != nil || p < 1 || p > 65535 {
					return parsedSSH{}, fmt.Errorf("invalid port %q", val)
				}
				result.Port = p
			case "-l":
				result.User = val
			}
			continue
		}

		// First non-flag token is the destination; the rest is the remote command.
		h, u := splitDestination(tok)
		result.Hostname = h
		if u != "" {
			result.User = u
		}
		break
	}

	if result.Hostname == "" {
		return parsedSSH{}, fmt.Errorf("no hostname found in SSH command")
	}
	return result, nil
}

// splitDestination splits a "[user@]host" token into its parts.
func splitDestination(tok string) (host, user string) {
	if idx := strings.LastIndex(tok, "@"); idx >= 0 {
		return tok[idx+1:], tok[:idx]
	}
	return tok, ""
}

// tokenizeSSH splits a shell-style string into tokens, honouring single
// quotes, double quotes, and backslash escapes.
func tokenizeSSH(s string) ([]string, error) {
	var tokens []string
	var cur strings.Builder
	inSingle, inDouble := false, false

	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '\'' && !inDouble:
			inSingle = !inSingle
		case ch == '"' && !inSingle:
			inDouble = !inDouble
		case ch == '\\' && !inSingle && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
		case (ch == ' ' || ch == '\t') && !inSingle && !inDouble:
			if cur.Len() > 0 {
				tokens = append(tokens, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(ch)
		}
	}

	if inSingle || inDouble {
		return nil, fmt.Errorf("unterminated quote in SSH command")
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}
	return tokens, nil
}

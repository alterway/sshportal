// Splitting command-line strings into words like a Posix shell would do
// Vendored from https://github.com/buildkite/shellwords/tree/v1.0.1
// but only with SplitPosix support

package utils

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// This is a recursive descent parser for our basic shellword grammar.

const (
	eof               = -1
	posixSpecialChars = "!\"#$&'()*,;<=>?[]\\^`{}|~"
	posixEscape       = '\\'
)

// Parser takes a string and parses out a tree of structs that represent text and Expansions
type parser struct {
	// Input is the string to parse
	Input string

	// Characters to use for quoted strings
	QuoteChars []rune

	// The character used for escaping
	EscapeChar rune

	// The characters used for escaping quotes in quoted strings
	QuoteEscapeChars []rune

	// Field seperators are used for splitting words
	FieldSeperators []rune

	// The current internal position
	pos int
}

func (p *parser) parse() ([]string, error) {
	var word strings.Builder

	words := []string{}
	token := false // Used to force token emission, even if empty

	for {
		// Read until we encounter a delimiter character
		scanned := p.scanUntil(func(r rune) bool {
			return r == p.EscapeChar || p.isQuote(r) || p.isFieldSeperator(r)
		})

		if len(scanned) > 0 {
			word.WriteString(scanned)
		}

		// Read the character that caused the scan to stop
		r := p.nextRune()
		if r == eof {
			break
		}

		switch {
		// Handle quotes
		case p.isQuote(r):
			quote, err := p.scanQuote(r)
			if err != nil {
				return nil, err
			}

			token = true // Ensure a token will be emitted, even if empty (e.g. "")

			// Write to the buffer
			word.WriteString(quote)

		// Handle escaped characters
		case r == p.EscapeChar:
			if escaped := p.nextRune(); escaped != eof {
				word.WriteRune(escaped)
			}
			continue

		// Handle field seperators
		case p.isFieldSeperator(r):
			if word.Len() > 0 || token {
				words = append(words, word.String())
				word.Reset()
				token = false
			}

		default:
			return nil, fmt.Errorf("unhandled character %c at pos %d", r, p.pos)
		}
	}

	if word.Len() > 0 || token {
		words = append(words, word.String())
		word.Reset()
	}

	return words, nil
}

func (p *parser) scanQuote(delim rune) (string, error) {
	var quote strings.Builder

	for {
		r := p.nextRune()
		if r == eof {
			return "", fmt.Errorf("expected closing quote %c at offset %d, got EOF", delim, p.pos-1)
		}
		// Check for escaped characters
		if escapeChar, escaped := p.isQuoteEscape(r); escaped {
			// Handle the case where our escape char is our delimiter (e.g "")
			if escapeChar != delim || p.peekRune() == delim {
				if escaped := p.nextRune(); escaped != eof {
					quote.WriteRune(escaped)
				}
				continue
			}
		}
		if r == delim {
			break
		}
		quote.WriteRune(r)
	}

	return quote.String(), nil
}

func (p *parser) isQuote(r rune) bool {
	for _, qr := range p.QuoteChars {
		if qr == r {
			return true
		}
	}
	return false
}

func (p *parser) isQuoteEscape(r rune) (rune, bool) {
	for _, qr := range p.QuoteEscapeChars {
		if qr == r {
			return qr, true
		}
	}
	return r, false
}

func (p *parser) isFieldSeperator(r rune) bool {
	for _, qr := range p.FieldSeperators {
		if qr == r {
			return true
		}
	}
	return false
}

func (p *parser) scanUntil(f func(rune) bool) string {
	start := p.pos
	for p.pos < len(p.Input) {
		c, size := utf8.DecodeRuneInString(p.Input[p.pos:])
		if c == utf8.RuneError || f(c) {
			break
		}
		p.pos += size
	}
	return p.Input[start:p.pos]
}

func (p *parser) nextRune() rune {
	if p.pos >= len(p.Input) {
		return eof
	}
	c, size := utf8.DecodeRuneInString(p.Input[p.pos:])
	p.pos += size
	return c
}

func (p *parser) peekRune() rune {
	if p.pos >= len(p.Input) {
		return eof
	}
	c, _ := utf8.DecodeRuneInString(p.Input[p.pos:])
	return c
}

// SplitPosix splits a command string into words like a posix shell would
func SplitPosix(line string) ([]string, error) {
	p := parser{
		Input:            line,
		QuoteChars:       []rune{'\'', '"'},
		EscapeChar:       posixEscape,
		QuoteEscapeChars: []rune{posixEscape},
		FieldSeperators:  []rune{'\n', '\t', ' '},
	}
	return p.parse()
}

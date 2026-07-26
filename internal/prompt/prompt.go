package prompt

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/term"
)

type Prompter interface {
	String(label, defaultValue string) (string, error)
	Password(label string) (string, error)
	Confirm(label string, defaultValue bool) (bool, error)
}

type Terminal struct {
	in       *bufio.Reader
	out      io.Writer
	password func(int) ([]byte, error)
	fd       func() (int, bool)
}

// Interactive reports whether the prompt is attached to an interactive terminal.
func (t *Terminal) Interactive() bool {
	fd, ok := t.fd()
	return ok && term.IsTerminal(fd)
}

func New(in io.Reader, out io.Writer) *Terminal {
	t := &Terminal{in: bufio.NewReader(in), out: out, password: term.ReadPassword}
	if file, ok := in.(interface{ Fd() uintptr }); ok {
		t.fd = func() (int, bool) { return int(file.Fd()), true }
	} else {
		t.fd = func() (int, bool) { return 0, false }
	}
	return t
}

func (t *Terminal) String(label, defaultValue string) (string, error) {
	if defaultValue == "" {
		fmt.Fprintf(t.out, "%s: ", label)
	} else {
		fmt.Fprintf(t.out, "%s [%s]: ", label, defaultValue)
	}
	value, err := t.readLine()
	if err != nil {
		return "", err
	}
	if value == "" {
		return defaultValue, nil
	}
	return value, nil
}

func (t *Terminal) Password(label string) (string, error) {
	fd, ok := t.fd()
	if !ok || !term.IsTerminal(fd) {
		return "", errors.New("password prompt requires an interactive terminal")
	}
	fmt.Fprintf(t.out, "%s: ", label)
	value, err := t.password(fd)
	fmt.Fprintln(t.out)
	if err != nil {
		return "", err
	}
	return string(value), nil
}

func (t *Terminal) Confirm(label string, defaultValue bool) (bool, error) {
	defaultText := "y/N"
	if defaultValue {
		defaultText = "Y/n"
	}
	fmt.Fprintf(t.out, "%s [%s]: ", label, defaultText)
	value, err := t.readLine()
	if err != nil {
		return false, err
	}
	if value == "" {
		return defaultValue, nil
	}
	switch strings.ToLower(value) {
	case "y", "yes":
		return true, nil
	case "n", "no":
		return false, nil
	default:
		return false, errors.New("please answer yes or no")
	}
}

func (t *Terminal) readLine() (string, error) {
	value, err := t.in.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if errors.Is(err, io.EOF) && value == "" {
		return "", io.EOF
	}
	return strings.TrimSpace(value), nil
}

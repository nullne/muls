package muls

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"text/scanner"
	// "log"
)

const (
	PS1PATTERN = `<\|(\d+)\|>`
	//regexp for weird characters
	CTRLSEQPATTERN     = `\x1b[ #%()*+\-.\/].|\r|(?:\x1b\[|\x9b)[ -?]*[@-~]|(?:\x1b\]|\x9d).*?(?:\x1b\\|[\a\x9c])|(?:\x1b[P^_]|[\x90\x9e\x9f]).*?(?:\x1b\\|\x9c)|\x1b.|[\x80-\x9f]`
	NOBACKSPACEPATTERN = `[^\x08][\x08]`
)

var (
	rePS1, reCtrlseq, reNobackspace *regexp.Regexp
	PS1                             command
)

// init compiles regexp pattern
func init() {
	rePS1 = regexp.MustCompile(PS1PATTERN)
	PS1 = command{Command{"export PS1='<|$?|>'", map[string]string{"readonly variable": "exit"}}, map[*regexp.Regexp]string{}}
	reCtrlseq = regexp.MustCompile(CTRLSEQPATTERN)
	reNobackspace = regexp.MustCompile(NOBACKSPACEPATTERN)
}

// pseudoShell simulates a interactive shell
func pseudoShell(so, se io.Reader, si io.Writer, done chan struct{}) (in chan command, out chan CommandResult, errch chan error) {

	in = make(chan command, 1)
	out = make(chan CommandResult)
	errch = make(chan error, 2)
	ch := make(chan bool)
	initch := make(chan struct{})

	cur := PS1
	in <- PS1

	// stdin
	go func() {
		// fmt.Println("[DEBUG] STDIN Start")
		defer close(out)
		defer func() {
			// fmt.Println("[DEBUG] STDIN Exit")
			_, err := si.Write([]byte(fmt.Sprintf("exit\n")))
			if err != nil {
				errch <- err
			}
		}()
		select {
		case <-initch:
		case <-done:
			return
		}
		// defer fmt.Println("[DEBUG] STDIN EXIT")
		for cmd := range in {
			cur = cmd
			// fmt.Println("[DEBUG] STDIN Write:", cmd.Cmd)
			_, err := si.Write([]byte(fmt.Sprintf("%s\n", cmd.Cmd)))
			if err != nil {
				errch <- err
				return
			}

			select {
			case <-done:
				return
			case _, ok := <-ch:
				if !ok {
					return
				}
			}
		}
	}()

	// stdout
	go func() {
		defer close(ch)
		// fmt.Println("[DEBUG] STDOUT Start")
		// defer fmt.Println("[DEBUG] STDOUT Exit")
		var (
			total, prebuf []byte
			buf           []byte = make([]byte, 1024*1024)
			init          bool   = false
			pn         int
		)

		for {
			n, err := so.Read(buf[0:])
			if err != nil {
				if err != io.EOF {
					errch <- err
				}
				return
			}
			if n == 0 {
				continue
			}
			if !init {
				close(initch)
				init = true
			}
			// fmt.Println("[DEBUG]OUTPUT:", string(buf[:n]))
			total = append(total, buf[:n]...)
			tmp, code, err := handle(prebuf[:pn], buf[:n], cur, si)
			pn = len(tmp)
			prebuf = make([]byte, pn)
			copy(prebuf, tmp)
			pn = len(prebuf)
			if code != -1 {
				if cur.Cmd != PS1.Cmd {
					select {
					case <-done:
						return
					case out <- cur.result(removeCommandAndPS1(total, cur.Cmd), code):
					}
				}
				total = total[:0]
				prebuf = prebuf[:0]
				pn=0
				ch <- true
			}
		}
	}()

	// stderr
	go func() {
		// fmt.Println("[DEBUG] STDERR Start")
		// defer fmt.Println("[DEBUG] STDERR EXIT")
		var s scanner.Scanner
		s.Init(se)
		var tok rune
		for tok != scanner.EOF {
			tok = s.Scan()
			// fmt.Println("At position", s.Pos(), ":", s.TokenText())
		}
	}()
	return
}

func handle(pre, buf []byte, cmd command, si io.Writer) ([]byte, int, error) {
	origin := append(pre, buf...)
	// fmt.Printf("origin: %s\n", origin)
	restbuf, err := cmd.interact(origin, si)
	if err != nil {
		return restbuf, -1, err
	}
	res := rePS1.FindAllSubmatch(restbuf, -1)
	if len(res) == 0 {
		return restbuf, -1, nil
	}
	code, err := strconv.Atoi(string(res[0][1]))
	if err != nil {
		code = -1
	}
	return restbuf, code, err
}

func removeCommandAndPS1(ori []byte, cmd string) []byte {
	rtn := rePS1.ReplaceAllLiteral(ori, []byte{})
	rtn = bytes.Replace(rtn, []byte(cmd), []byte{}, 1)
	return rtn
}

// handle removes PS1 and command strings and return whether command ends
func shandle(origin []byte, cmd string) (rtn []byte, code int) {
	origin = bytes.Replace(origin, []byte(cmd), []byte{}, 1)
	res := rePS1.FindAllSubmatch(origin, -1)
	if len(res) == 0 {
		return origin, -1
	}
	code, err := strconv.Atoi(string(res[0][1]))
	if err != nil {
		code = -1
	}

	rtn = rePS1.ReplaceAllLiteral(origin, []byte{})
	return
}

//Filter filters out all ANSI/VT100/xterm control sequences
func Filter(ori []byte) []byte {
	return reCtrlseq.ReplaceAll(reNobackspace.ReplaceAll(ori, []byte{}), []byte{})
}

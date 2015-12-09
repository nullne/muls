package muls

import (
	"bytes"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"io"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"runtime"
	"sync"
	"time"
	"strings"
	// "log"
)

const (
	TIMEOUT             = 300
	DEFAULT_CONCURRENCY = 200
	MAX_CONCURRENCY     = 100
)

var errAbort = errors.New("Abort by user")
var scriptPath = "/tmp/"

type Script struct {
	Name, Content string
	Interaction   map[string]string
}

// Interaction is regexp expression and input pairs, i.e. \[sudo\]: password
type Command struct {
	Cmd         string
	Interaction map[string]string
}

type command struct {
	Command
	interaction map[*regexp.Regexp]string
}

// compile precompiles commands interaction
func (c *command) compile() {
	c.interaction = make(map[*regexp.Regexp]string)
	for key, val := range c.Interaction {
		re := regexp.MustCompile(key)
		c.interaction[re] = val
	}
}

// result returns result of type CommandResult
func (c command) result(output []byte, code int) CommandResult {
	res := CommandResult{}
	res.Command = c.Command
	// res.Output = output
	res.Output = make([]byte, len(output))
	copy(res.Output, output)
	res.ExitCode = code
	return res
}

// interact auto interacts based on interaction
func (c command) interact(buf []byte, w io.Writer) ([]byte, error) {
	// fmt.Printf("interact cmd: %s ,buf: %s \n", c.Cmd, buf)
	for re, val := range c.interaction {
		// fmt.Printf("interact buf: %s, re: %v\n", buf, re)
		if index := re.FindIndex(buf); index != nil {
			// fmt.Printf("[DEBUG]matched: %s, index: %v\n", buf, index)
			rest := buf[index[1]:]
			// rest := make([]byte, len(buf)-index[1]+1)
			// copy(rest, buf[index[1]:])
			// fmt.Printf("rest: %s, pointer: %p\n", rest, rest)
			_, err := w.Write([]byte(fmt.Sprintf("%s\n", val)))
			return rest, err
		}
	}
	return buf, nil
}

type CommandResult struct {
	Command
	Output   []byte
	ExitCode int
}

func (c CommandResult) String() string {
	return fmt.Sprintf("\nOutput:\n %s\nExit code: %d\n", Filter(c.Output), c.ExitCode)
}

type MachineMeta struct {
	Host string
	IP   string
	Port int
}

// status:	0 => not complete
//			1 => success
//			2 => error
type Machine struct {
	MachineMeta
	Result        []CommandResult
	Status        uint
	Err           error
	commandResult chan CommandResult
	done          chan struct{}
	statistic
}

//newMachine news a Machine instance
func newMachine(meta MachineMeta, cmdnums int) (*Machine, error) {
	m := &Machine{}
	if meta.IP == "" {
		return m, errors.New("IP can not be empty")
	}
	if meta.Port == 0 {
		meta.Port = 22
	}
	if meta.Host == "" {
		meta.Host = meta.IP
	}
	m.MachineMeta = meta
	m.statistic.total = cmdnums
	m.commandResult = make(chan CommandResult, cmdnums)
	m.done = make(chan struct{})
	return m, nil
}

//
func (m *Machine) RealtimeQuery() chan CommandResult {
	return m.commandResult
}

//
func (m *Machine) pushResult(result CommandResult) {
	m.Result = append(m.Result, result)
	m.commandResult <- result
	m.statistic.complete++
	if result.ExitCode != 0 {
		m.statistic.err++
	}
}

func (m *Machine) run(commands []command, script Script, config config) chan error {
	errch := make(chan error)
	go m.execute(commands, script, config, errch)
	return errch
}

func (m *Machine) execute(commands []command, script Script, config config, errch chan error) {
	defer close(m.commandResult)
	var err error
	defer func() {
		if err != nil {
			errch <- err
		}
		close(errch)
	}()

	client, err := SSHDialTimeout("tcp", fmt.Sprintf("%s:%d", m.IP, m.Port), config.sshConfig, config.Timeouts)
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			client.Close()
		} else {
			err = client.Close()
		}
	}()


	if script.Content != "" {
		err = m.scp(client, script.Name, script.Content)
		if err != nil {
			return
		}
	}

	mode := config.Mode
	if len(commands) > 1 {
		mode = 1
	}
	if mode == 0 && len(commands) == 1 {
		err = m.command(client, commands[0])
	} else if mode == 1 {
		err = m.shell(client, commands)
	} else {
		err = errors.New("No legal commands")
	}
	return
}

func (m *Machine) scp(client *ssh.Client, name, content string) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	go func() {
		w, _ := session.StdinPipe()
		defer w.Close()
		fmt.Fprintln(w, "C0700", len(content), strings.Replace(name, scriptPath, "", -1))
		fmt.Fprint(w, content)
		fmt.Fprint(w, "\x00")
	}()
	if err = session.Run(fmt.Sprintf("/usr/bin/scp -tr %s", scriptPath)); err != nil {
		return err
	}
	return nil
}

func (m *Machine) shell(client *ssh.Client, commands []command) (rtn error) {
	// func (m *Machine) shell(session *ssh.Session, commands []command) (rtn error) {
	var wg sync.WaitGroup
	defer close(m.done)

	session, err := client.NewSession()
	if err != nil {
		return err
	}
	//@TODO
	defer session.Close()
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("[DEBUG]recover", r)
			rtn = errors.New(fmt.Sprint(r))
		}
	}()
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	/*
		// this requires that server was configured to accept to modify PS1
		if err := session.Setenv("PS1", PS1); err != nil {
			return err
		}
	*/

	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return err
	}
	// TODO
	stderr, err := session.StderrPipe()
	if err != nil {
		return err
	}

	if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
		return err
	}

	inch, outch, errch := pseudoShell(stdout, stderr, stdin, m.done)
	defer func() {
		select {
		case rtn = <-errch:
		default:
		}
	}()

	if err := session.Shell(); err != nil {
		return err
	}

	wg.Add(1)
	go func() {
		// defer fmt.Println("OUTPUT Exit(Outer)")
		defer wg.Done()
		for o := range outch {
			m.pushResult(o)
		}
	}()

	go func() {
		// defer fmt.Println("INPUT Exit(Outer)")
		defer close(inch)
		for _, c := range commands {
			// fmt.Println("STDIN: ", c)
			select {
			case inch <- c:
			case <-m.done:
				return
			}
		}
	}()

	wg.Wait()
	// fmt.Println("[DEBUG] SHELL EXIT")
	return
}

// command executes a commond over ssh, default mode
func (m *Machine) command(client *ssh.Client, command command) error {
	var b, e bytes.Buffer
	result := CommandResult{
		Command: command.Command,
	}
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	session.Stdout = &b
	session.Stderr = &e
	if err := session.Run(command.Cmd); err != nil {
		switch err.(type) {
		default:
			return err
		case *ssh.ExitError:
			result.ExitCode = err.(*ssh.ExitError).ExitStatus()
		}
	} else {
		result.ExitCode = 0
	}
	// out := append(b.Bytes(), e.Bytes()...)
	// result.Output = make([]byte, len(out))
	// copy(result.Output, out)
	// result.Output = b.Bytes()
	result.Output = append(b.Bytes(), e.Bytes()...)
	// fmt.Println("[DEBUG]result:", result)
	m.pushResult(result)
	return nil
}

type Timeouts struct {
	Connect time.Duration
	Login   time.Duration
	Exec    time.Duration
}

type config struct {
	Timeouts
	Concurrency uint
	// 0 => execute command, 1 => interactive shell
	Mode int
	// can query result realtime if set to true
	sshConfig *ssh.ClientConfig
}

type statistic struct {
	total    int
	complete int
	err      int
}

// Progress get the currrent progresss include total, done, error
func (s *statistic) Progress() (total, complete, err int) {
	return s.total, s.complete, s.err
}
func (s *statistic) Percent() float64 {
	return (float64(s.complete) / float64(s.total)) * float64(100)
}

type Muls struct {
	statistic
	config
	commands    []command
	script      Script
	machines    []*Machine
	done, abort chan struct{}
	results     chan Machine
}

func New(sshConfig *ssh.ClientConfig, machines []MachineMeta, commands []Command, script Script) (*Muls, error) {
	m := &Muls{}
	m.sshConfig = sshConfig

	for _, c := range commands {
		tmp := command{}
		tmp.Command = c
		tmp.compile()
		m.commands = append(m.commands, tmp)
	}

	if script.Content != "" {
		tmp := command{}
		tmp.Cmd = fmt.Sprintf("%s%s-%v", scriptPath, script.Name, time.Now().Unix())
		tmp.Interaction = script.Interaction
		tmp.compile()
		m.commands = append(m.commands, tmp)
		m.script.Name = tmp.Cmd
		m.script.Content = script.Content
		m.script.Interaction = tmp.Interaction
	}

	nums := len(m.commands)

	for _, ma := range machines {
		tmp, err := newMachine(ma, nums)
		if err != nil {
			continue
		}
		m.machines = append(m.machines, tmp)
	}

	m.total = len(machines)

	m.results = make(chan Machine, m.total)
	m.done = make(chan struct{})
	m.abort = make(chan struct{})

	//default config
	m.Concurrency = uint(m.total)
	m.Timeouts = Timeouts{60 * time.Second, 300 * time.Second, 300 * time.Second}
	return m, nil
}

//
func (m *Muls) pushResult(result Machine) {
	m.results <- result
	m.statistic.complete++
	if result.Status == 2 {
		m.statistic.err++
	}
}

func (m *Muls) MachinesList() []*Machine {
	return m.machines
}

// Run run command list on provided machines, and return error
func (m *Muls) Run() error {
	return m.run()
}

func (m *Muls) run() (e error) {
	defer func() {
		if r := recover(); r != nil {
			e = errors.New(fmt.Sprint(r))
		}
	}()
	defer close(m.results)
	defer close(m.done)
	runtime.GOMAXPROCS(runtime.NumCPU())
	// machineChan := make(chan MachineMeta)
	machineChan := gen(m.machines, m.done)
	var chans []chan *Machine

	for i := uint(0); i < m.Concurrency; i++ {
		// fmt.Println("[DEBUG]start worker:", i)
		ch := worker(machineChan, m.commands, m.script, m.config, m.done, m.abort)
		chans = append(chans, ch)
	}

	res := m.merge(chans)
	for r := range res {
		m.pushResult(*r)
	}
	return nil
}

func (m *Muls) merge(chans []chan *Machine) chan *Machine {
	var wg sync.WaitGroup
	out := make(chan *Machine)
	output := func(in <-chan *Machine) {
		defer wg.Done()
		for i := range in {
			select {
			case out <- i:
			case <-m.done:
				return
			}
		}
	}

	for _, c := range chans {
		wg.Add(1)
		go output(c)
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

// Abort stops the whole runing process ASAP
func (m *Muls) Abort() error {
	close(m.abort)
	return nil
}

// Result returns all results sorted by machine
func (m *Muls) Results() []*Machine {
	return m.machines
}

// RealtimeResult return a channel which outputs realtime result
// This channel should be handled ASAP or it will block
func (m *Muls) RealtimeQuery() chan Machine {
	return m.results
}

// AuthConfig returns ssh.ClientConfig for basic SSH authentication
func AuthConfig(username string, auth map[string]interface{}) (*ssh.ClientConfig, error) {
	config := &ssh.ClientConfig{
		User: username,
	}
	for mode, val := range auth {
		method, err := authMethod(mode, val)
		if err != nil {
			return nil, err
		}
		config.Auth = append(config.Auth, method)
	}
	return config, nil
}

// authMethod return ssh.AuthMethod, include type password, key, agent forwarding
func authMethod(mode string, value interface{}) (ssh.AuthMethod, error) {
	switch mode {
	case "password":
		return ssh.Password(value.(string)), nil
	case "key":
		buf, err := ioutil.ReadFile(value.(string))
		if err != nil {
			return nil, err
		}
		key, err := ssh.ParsePrivateKey(buf)
		if err != nil {
			return nil, err
		}
		return ssh.PublicKeys(key), nil
	case "forwarding":
		sock, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
		if err != nil {
			return nil, err
		}
		agent := agent.NewClient(sock)
		signers, err := agent.Signers()
		if err != nil {
			return nil, err
		}
		return ssh.PublicKeys(signers...), nil
	default:
		return nil, errors.New("Illeagal mode")
	}
}

// Conn wraps a net.Conn, and sets a deadline for every read
// and write operation.
type Conn struct {
	net.Conn
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

func (c *Conn) Read(b []byte) (int, error) {
	err := c.Conn.SetReadDeadline(time.Now().Add(c.ReadTimeout))
	if err != nil {
		return 0, err
	}
	return c.Conn.Read(b)
}

func (c *Conn) Write(b []byte) (int, error) {
	err := c.Conn.SetWriteDeadline(time.Now().Add(c.WriteTimeout))
	if err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}

func SSHDialTimeout(network, addr string, config *ssh.ClientConfig, timeouts Timeouts) (*ssh.Client, error) {
	conn, err := net.DialTimeout(network, addr, timeouts.Connect)
	if err != nil {
		return nil, err
	}

	timeoutConn := &Conn{conn, timeouts.Exec, timeouts.Exec}
	c, chans, reqs, err := ssh.NewClientConn(timeoutConn, addr, config)
	if err != nil {
		return nil, err
	}
	client := ssh.NewClient(c, chans, reqs)
	return client, nil
}

// gen generates channel of type Machine
func gen(machines []*Machine, done chan struct{}) <-chan *Machine {
	out := make(chan *Machine)
	go func() {
		defer close(out)
		for _, m := range machines {
			select {
			case <-done:
				return
			case out <- m:
			}
		}
	}()
	return out
}

//
func worker(ms <-chan *Machine, commands []command, script Script, config config, done, abort chan struct{}) chan *Machine {
	out := make(chan *Machine)
	go func() {
		defer close(out)
		for m := range ms {
			// errch := make(chan error)
			// go m.run(commands, config, errch)
			errch := m.run(commands, script, config)
			select {
			case m.Err = <-errch:
			case <-abort:
				return
			}
			if m.Err != nil {
				m.Status = 2
			} else {
				m.Status = 1
			}
			// fmt.Println("[DEBUG]work err:", err)

			select {
			case out <- m:
			case <-done:
				return
			}
		}
	}()
	return out
}

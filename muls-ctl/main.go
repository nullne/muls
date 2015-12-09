package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"github.com/howeyc/gopass"
	"github.com/nullne/muls"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"os/user"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

//config const and var
const (
	LOGDIR              = "/tmp/log/"
	TIMEOUT             = 300
	MAX_CONCURRENCY     = 200
	RISQUERYMAX         = 100
	DEFAULT_CONCURRENCY = 10
	sudo_pattern        = `\[sudo\] password for.*\n`
	ip_pattern          = `^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`
	ip_port_pattern     = `(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(:\d+)`
)

var (
	gLogger                   *log.Logger
	gDebug                    *log.Logger
	gLogfile                  *os.File
	gReSudo, gReIP, gReIPPort *regexp.Regexp
)

//@TODO this function can be improved with nice arithmetic
func exist(ms []muls.MachineMeta, cur muls.MachineMeta) bool {
	for _, m := range ms {
		if cur == m {
			return true
		}
	}
	return false
}

type Config struct {
	concurrency *uint
	debug       *bool
	fast        *bool
	interact    *bool
	verbose     *bool
	timeout     *int
	output      *string
	filtSudo    bool
}

var (
	gDone chan struct{}
)

var (
	gMachines        []muls.MachineMeta
	gIllegalMachines []string
	gCommands        []muls.Command
	gConfig          Config
	gScript          muls.Script
	gSSHConfig       *ssh.ClientConfig
)

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	defer gLogfile.Close()

	err := run(gMachines)
	if err != nil {
		handlePanic(err)
	}
	fmt.Printf("\nThe detail was written to %s\n", *gConfig.output)
}

func run(ms []muls.MachineMeta) error {
	var interrupt bool = false
	var wg sync.WaitGroup
	var done chan struct{} = make(chan struct{})
	m, err := muls.New(gSSHConfig, ms, gCommands, gScript)
	if err != nil {
		return err
	}
	//@TODO
	if !*gConfig.fast {
		m.Mode = 1
	}
	m.Concurrency = *gConfig.concurrency
	timeout := time.Duration(*gConfig.timeout) * time.Second
	m.Timeouts = muls.Timeouts{timeout, timeout, timeout}

	wg.Add(1)
	go handle(m, &interrupt, done, &wg)
	if !*gConfig.verbose && !*gConfig.debug {
		wg.Add(1)
		go showProgress(m, done, &wg)
	}

	err = m.Run()
	if err != nil {
		if !interrupt {
			return err
			// gDebug.Fatalf("%s\n", err.Error())
		} else {
			gDebug.Printf("%s\n", err.Error())
		}
	}
	wg.Wait()
	res := m.Results()
	// hostNotMatchMachines := pickHostNotMatchMachines(res)
	errorMachines := pickErrorMachines(res)
	commandsWithNoZero := pickCommandsWithNoZero(res)

	//summary
	fmt.Println("\n\rError Statistic:")
	if nums := len(gIllegalMachines); nums != 0 {
		fmt.Printf("nums of illegal hostname/IP：%d\n", nums)
	}
	if nums := len(errorMachines); nums != 0 {
		fmt.Printf("nums of the kind of server error：%d, include\n", nums)
		for e, ms := range errorMachines {
			fmt.Printf("\t%s：%d\n", e, len(ms))
		}
	}
	machinesWithNoZero := getMachinesWithNoZero(commandsWithNoZero)
	if nums := len(machinesWithNoZero); nums != 0 {
		fmt.Printf("nums of machine on which command exit code is not 0：%d\n", nums)
	}
	fmt.Println("")

	if *gConfig.interact {
		err = interact(errorMachines, commandsWithNoZero)
		// err = interact(hostNotMatchMachines, errorMachines, commandsWithNoZero)
		if err != nil {
			return err
		}
	}
	return nil
}

func interact(errorMachines map[string][]muls.MachineMeta, commands map[string]map[int][]muls.MachineMeta) error {
	menu := `
Please select to continue:
	1 list all error machines and reason
	2 list all machines which exit code is not zore
	3 list all illegal ips
	4 retry on machines in 1
	5 retry on machines in 2
	6 retry on machines in 1 and 2 
	h help menu
	q quit`

	reader := bufio.NewReader(os.Stdin)
	fmt.Print(menu)
	nums := len(gMachines)
Outer:
	for {
		fmt.Print("\nPlease type: ")
		text, _ := reader.ReadString('\n')
		text = strings.Trim(text, "\n\r ")
		switch text {
		case "1":
			if len(errorMachines) == 0 {
				fmt.Println("Nothing")
			} else {
				for e, hosts := range errorMachines {
					fmt.Printf("%s\n", e)
					for _, h := range hosts {
						fmt.Printf("\t%s\n", h.Host)
					}
					fmt.Println("\n")
				}
			}
		case "2":
			for c, codes := range commands {
				if len(codes) == 0 {
					continue
				}
				fmt.Printf("Commands: %s\n", c)
				for code, hs := range codes {
					fmt.Printf("\tExit code:%d\n", code)
					for _, h := range hs {
						fmt.Printf("\t\t%s\n", h.Host)
					}
				}
				fmt.Println("")
			}
		case "3":
			if len(gIllegalMachines) == 0 {
				fmt.Println("Nothing")
			} else {
				for _, ip := range gIllegalMachines {
					fmt.Println(ip)
				}
			}
		case "4":
			machines := make([]muls.MachineMeta, 0, nums)
			for _, ms := range errorMachines {
				for _, m := range ms {
					if !exist(machines, m) {
						fmt.Println(m)
						machines = append(machines, m)
					}
				}
			}
			if len(machines) == 0 {
				fmt.Println("Nothing")
				continue
			}
			run(machines)
			fmt.Println("Retry exit.")
		case "5":
			machines := getMachinesWithNoZero(commands)
			if len(machines) == 0 {
				fmt.Println("Nothing")
				continue
			}
			run(machines)
			fmt.Println("Retry exit.")
		case "6":
			machines := make([]muls.MachineMeta, 0, nums)
			machines = append(machines, getMachinesWithNoZero(commands)...)

			for _, ms := range errorMachines {
				for _, m := range ms {
					if !exist(machines, m) {
						machines = append(machines, m)
					}
				}
			}
			if len(machines) == 0 {
				fmt.Println("Nothing")
				continue
			}
			run(machines)
			fmt.Println("Retry exit.")
		case "h":
			fmt.Print(menu)
		case "q":
			break Outer
		default:
			fmt.Println("Sorry, but what do you mean?")
		}
	}
	return nil
}


func pickErrorMachines(ms []*muls.Machine) map[string][]muls.MachineMeta {
	nums := len(ms)
	errs := make(map[string][]muls.MachineMeta)
	for _, m := range ms {
		if m.Err != nil {
			// key := utils.FilterIpHost(m.Err.Error())
			key := gReIPPort.ReplaceAllString(m.Err.Error(), "")
			if len(errs[key]) == 0 {
				errs[key] = make([]muls.MachineMeta, 0, nums)
			}
			errs[key] = append(errs[key], m.MachineMeta)
		}
	}
	return errs
}

func pickCommandsWithNoZero(ms []*muls.Machine) map[string]map[int][]muls.MachineMeta {
	cmds := make(map[string]map[int][]muls.MachineMeta)
	for _, m := range ms {
		for _, res := range m.Result {
			if len(cmds[res.Cmd]) == 0 {
				cmds[res.Cmd] = make(map[int][]muls.MachineMeta)
			}
			if res.ExitCode != 0 {
				if len(cmds[res.Cmd][res.ExitCode]) == 0 {
					cmds[res.Cmd][res.ExitCode] = make([]muls.MachineMeta, 0, len(ms))
				}
				cmds[res.Cmd][res.ExitCode] = append(cmds[res.Cmd][res.ExitCode], m.MachineMeta)
				// cmds[res.Cmd][res.ExitCode]=append(m.Host
			}
		}
	}
	return cmds
}

func getMachinesWithNoZero(commands map[string]map[int][]muls.MachineMeta) []muls.MachineMeta {
	nums := len(gMachines)
	machines := make([]muls.MachineMeta, 0, nums)
	for _, cmd := range commands {
		for _, ms := range cmd {
			for _, m := range ms {
				if !exist(machines, m) {
					machines = append(machines, m)
				}
			}
		}
	}
	return machines
}

func output(dest *os.File, wg *sync.WaitGroup) chan string {
	var mutex = &sync.Mutex{}
	var all string
	str := make(chan string)
	status := make(chan struct{})
	go func() {
		defer close(status)
		for s := range str {
			mutex.Lock()
			all += s
			mutex.Unlock()
			runtime.Gosched()
		}
	}()

	go func() {
		defer wg.Done()
		ticker := time.NewTicker(time.Millisecond * 100)
		defer ticker.Stop()
		for {
			length := len(all)
			select {
			case <-ticker.C:
				if length == 0 {
					break
				}
				mutex.Lock()
				dest.WriteString(all)
				all = ""
				mutex.Unlock()
				runtime.Gosched()
				dest.Sync()
			}
			select {
			case <-status:
				if all == "" {
					return
				}
			default:
			}
		}
	}()
	return str
}

//filter result, print to screen if necessary, output to file
func handle(m *muls.Muls, interrupt *bool, done chan struct{}, wg *sync.WaitGroup) {
	var logfile *os.File

	//capture CTRL+C signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		*interrupt = false
		select {
		case <-gDone:
			return
		case <-sig:
			*interrupt = true
			fmt.Println("\n", "Exiting...")
			m.Abort()
			close(done)
			return
		}
	}()
	if _, err := os.Stat(*gConfig.output); os.IsNotExist(err) {
		logfile, err = os.Create(*gConfig.output)
		if err != nil {
			exit(fmt.Sprintf("Log file cannot be created: %s", err.Error()))
		}
	} else {
		logfile, err = os.OpenFile(*gConfig.output, os.O_RDWR|os.O_APPEND, 0600)
		if err != nil {
			exit(fmt.Sprintf("Log file cannot be opened: %s", err.Error()))
		}
	}
	defer logfile.Close()
	defer wg.Done()

	var wginner sync.WaitGroup
	// printch, filech := output()
	wginner.Add(2)
	printch := output(os.Stdout, &wginner)
	filech := output(logfile, &wginner)
Outer:
	for {
		select {
		case <-gDone:
			break Outer
		case res, ok := <-m.RealtimeQuery():
			if !ok {
				break Outer
			}
			if *gConfig.verbose {
				msg := format(res, m.Percent(), false)

				printch <- msg
				// fmt.Print(msg)
			}
			fmsg := format(res, m.Percent(), true)

			filech <- fmsg
			// logfile.WriteString(fmt.Sprint(fmsg))
			// logfile.Sync()
		}
	}
	close(printch)
	close(filech)
	wginner.Wait()
}

func format(res muls.Machine, percent float64, filt bool) (rtn string) {
	var lf string
	if filt {
		lf = "\n"
	} else {
		lf = "\r\n"
	}
	if res.Err != nil {
		status := "ERROR"
		o := strings.SplitAfter(res.Err.Error(), "\n")
		rtn += fmt.Sprintf("%6.2f%-3s%-20s%-13s%-7s%s%s", percent, "%", res.Host, status, " ", strings.Trim(o[0], "\r\n"), lf)
		for i := 1; i < len(o); i++ {
			rtn += fmt.Sprintf("\n%49s%s%s", " ", strings.Trim(o[i], "\n\r"), lf)
		}
	} else {
		status := "OK"
		display := false
		for i, cmd := range res.Result {
			if cmd.Cmd == "hostname" {
				if i == 0 {
					display = true
				}
				continue
			}
			var o []string
			var output []byte
			if gConfig.filtSudo {
				output = gReSudo.ReplaceAll(cmd.Output, []byte{})
			} else {
				output = cmd.Output
			}
			// output := cmd.Output
			if filt {
				o = strings.SplitAfter(strings.Trim(string(muls.Filter(output)), "\n\r"), "\n")
			} else {
				o = strings.SplitAfter(strings.Trim(string(output), "\r\n"), "\n")
			}
			if i == 0 || display {
				display = false
				rtn += fmt.Sprintf("%6.2f%-3s%-20s%-13s%-7d%s%s", percent, "%", res.Host, status, cmd.ExitCode, strings.Trim(o[0], "\r\n"), lf)
			} else {
				rtn += fmt.Sprintf("%-42s%-7d%s%s", "", cmd.ExitCode, strings.Trim(o[0], "\r\n"), lf)
			}
			for j := 1; j < len(o); j++ {
				rtn += fmt.Sprintf("%49s%s%s", " ", strings.Trim(o[j], "\n\r"), lf)
			}
		}
	}
	return
}

func showProgress(m *muls.Muls, done chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	defer gDebug.Println("Exit from show progress")
	ticker := time.NewTicker(time.Millisecond * 100)
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			progress := m.Percent()
			t, c, e := m.Progress()
			fmt.Printf("[%6.2f%%]\tTotal %4d hosts/ips, Done: %4d, Error: %4d\r", progress, t, c, e)
			if c == t {
				return
			}
		}
	}
}

func init() {
}

//parse arguments
func init() {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	gDone = make(chan struct{})
	//@TODO
	gReSudo = regexp.MustCompile(sudo_pattern)
	gReIP = regexp.MustCompile(ip_pattern)
	gReIPPort = regexp.MustCompile(ip_port_pattern)

	// host/ip and host/ip list support format like: 192.1681.1.100:22
	host := flag.String("h", "", "single host/ip")
	list := flag.String("l", "", "list of hosts/ips")
	cmd := flag.String("c", "", "command to be excuted")
	//@TODO
	sf := flag.String("s", "", "script file")
	//auth
	username := flag.String("u", "", "user name")
	password := flag.Bool("p", false, "authentication by password")
	key := flag.String("key", "", "authentication by key")
	version := flag.Bool("version", false, "show version messages")
	sudo := flag.Bool("sudo", false, "need to provide sudo password if set")
	//config
	outputDefault := fmt.Sprintf("/tmp/muls-%v-%v.log", time.Now().Unix(), r.Intn(100))
	gConfig.output = flag.String("o", outputDefault, "file to which details are output")
	passstring := flag.String("P", "", "authentication by password and the pass string goes after -P")
	gConfig.debug = flag.Bool("debug", false, "show debug message")
	gConfig.verbose = flag.Bool("v", false, "verbose messages")
	gConfig.fast = flag.Bool("fast", false, "fast because not request a tty and do NOT verify hostname")
	gConfig.interact = flag.Bool("I", false, "provide interactive menu")
	gConfig.concurrency = flag.Uint("C", uint(DEFAULT_CONCURRENCY), fmt.Sprintf("number of concurrency channel,max is %d", MAX_CONCURRENCY))
	gConfig.timeout = flag.Int("t", TIMEOUT, fmt.Sprintf("timeout, default value is %ds", TIMEOUT))

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [optional flags][-h host|-l list] [-c cmd|-s shell script]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if len(os.Args) == 1 {
		flag.Usage()
		os.Exit(0)
	}

	if *version {
		fmt.Println("Muls 3.0, powered by le.yu@chinacache.com")
		os.Exit(0)
	}

	if err := os.Remove(*gConfig.output); err != nil && !os.IsNotExist(err) {
		fmt.Println(err)
		os.Exit(1)
	}

	// debug log
	var writer io.Writer
	if *gConfig.debug {
		writer = io.Writer(os.Stderr)
	} else {
		writer = ioutil.Discard
	}
	gDebug = log.New(writer, "[DEBUG]", log.Lshortfile)

	if *username == "" {
		*username = getUsername()
	}
	gDebug.Printf("uesrname: %s\n", *username)

	logdir := LOGDIR + *username
	if _, err := os.Stat(logdir); os.IsNotExist(err) {
		err := os.Mkdir(logdir, 0751)
		if err != nil {
			exit(fmt.Sprintf("Log directory cannot be created: %s", err.Error()))
		}
	}
	now := time.Now()
	logfile := fmt.Sprintf("%s/%v-%v.log", logdir, now.Year(), now.Month())

	// log
	if _, err := os.Stat(logfile); os.IsNotExist(err) {
		gLogfile, err = os.Create(logfile)
		if err != nil {
			exit(fmt.Sprintf("Log file cannot be created: %s", err.Error()))
		}
	} else {
		gLogfile, err = os.OpenFile(logfile, os.O_RDWR|os.O_APPEND, 0600)
		if err != nil {
			exit(fmt.Sprintf("Log file cannot be opened: %s", err.Error()))
		}
	}
	gLogger = log.New(io.Writer(gLogfile), "", log.Ldate|log.Ltime)

	gLogger.Println("--------------------Start--------------------")
	gLogger.Printf("%+v", os.Args)

	var sudoPasswd string
	if *passstring != "" {
		sudoPasswd = *passstring
		gConfig.filtSudo = true
	} else {
		if *sudo {
			fmt.Printf("Password: ")
			sudoPasswd = string(gopass.GetPasswdMasked())
		}
	}

	// host/ip
	if *list == "" && *host == "" {
		fmt.Println("No host/ip specified.")
		flag.Usage()
		os.Exit(1)
	}
	hostlists := hostList(*host, *list)
	gMachines, gIllegalMachines = genMachines(hostlists)
	if len(gMachines) == 0 {
		exit("No legal host/ip specified.")
	}
	gLogger.Printf("machines: %v", strings.Join(hostlists, ", "))
	if len(gIllegalMachines) != 0 {
		gLogger.Printf("illegal machines: %v", strings.Join(gIllegalMachines, ", "))
	}

	// commands
	if *cmd == "" && *sf == "" {
		fmt.Println("No command or script specified.")
		flag.Usage()
		os.Exit(1)
	}

	if *sf != "" {
		gScript.Name = *sf
		gScript.Interaction = make(map[string]string)
		s, err := readShell(*sf)
		if err != nil {
			fmt.Printf("Cannot read script file: %v\n", err)
			os.Exit(1)
		}
		gScript.Content = s
	}
	if *sudo {
		gCommands = genCommands(*cmd, sudoPasswd)
		if *sf != "" {
			gScript.Interaction[`\[sudo\]`] = sudoPasswd
		}
	} else {
		gCommands = genCommands(*cmd, "")
	}
	if *gConfig.fast {
		if len(gCommands) == 0 {
			exit("No command or bash script available to be executed!")
		}
	} else {
		if len(gCommands) == 1 {
			exit("No command or bash script available to be executed!")
		}
	}
	gDebug.Printf("generate commands: %v", gCommands)

	commandsLog := ""
	for _, c := range gCommands {
		commandsLog += fmt.Sprintf("%s, ", c.Cmd)
	}
	gLogger.Printf("commands: %q\n", commandsLog)

	// auth
	auths := []ssh.AuthMethod{}
	// var auth ssh.AuthMethod

	if *password || *passstring != "" {
		if sudoPasswd != "" {
			auths = append(auths, ssh.Password(sudoPasswd))
		} else {
			auth, err := authMethod("password")
			if err != nil {
				fmt.Printf("password error: %s", err.Error())
			} else {
				auths = append(auths, auth)
			}
		}
		gDebug.Println("password auth method added")
		// auths = append(auths, authMethod("password"))
	}
	if *key != "" {
		auth, err := authMethod(*key)
		if err != nil {
			fmt.Printf("key error: %s", err.Error())
		} else {
			auths = append(auths, auth)
			gDebug.Println("key auth method added")
		}
		// auths = append(auths, authMethod(*key))
	}
	if *key == "" {
		auth, err := authMethod("forwarding")
		if err != nil {
			gDebug.Printf("agent forwarding error: %s\n", err.Error())
		} else {
			auths = append(auths, auth)
			gDebug.Println("agent forwarding auth method added")
		}
		// auths = append(auths, authMethod("forwarding"))
	}

	if len(auths) == 0 {
		exit("No valid auth method provide")
		return
	}

	gSSHConfig = &ssh.ClientConfig{
		User: *username,
		Auth: auths,
	}
}

// genCommands return command array based on different source
func genCommands(command string, passwd string) []muls.Command {
	var rtn []muls.Command
	if command == "" {
		return rtn
	}

	if !*gConfig.fast {
		rtn = append(rtn, muls.Command{"hostname", map[string]string{"$HOSTNAME": "exit"}})
	}
	var cmd muls.Command
	cmd.Interaction = make(map[string]string)
	cmd.Cmd = command
	rtn = append(rtn, cmd)

	if passwd != "" {
		for _, r := range rtn {
			r.Interaction[`\[sudo\]`] = passwd
		}
	}
	return rtn
}

func genMachines(ms []string) ([]muls.MachineMeta, []string) {
	re := regexp.MustCompile(ip_pattern)
	length := len(ms)
	rtn := make([]muls.MachineMeta, 0, length)
	irtn := make([]string, 0, length)

	for _, m := range ms {
		h := strings.Split(m, ":")
		if re.MatchString(h[0]) {
			if len(h) < 2 {
				h = append(h, "22")
			}
			port, _ := strconv.Atoi(h[1])
			rtn = append(rtn, muls.MachineMeta{h[0], h[0], port})
		} else {
			irtn = append(irtn, m)
			continue
		}
	}
	return rtn, irtn
}

// hostList return list of hosts
func hostList(host, list string) (rtn []string) {
	if host != "" {
		rtn = append(rtn, strings.TrimSpace(host))
	}
	if list != "" {
		hosts, err := readLine(list)
		if err != nil {
			gDebug.Printf("cannot get host/ip from file:%s", err.Error())
			return
		}
		rtn = append(rtn, hosts...)
	}
	return
}

//
func readLine(filePth string) ([]string, error) {
	var hosts []string
	f, err := os.Open(filePth)
	defer f.Close()
	if err == nil {
		scanner := bufio.NewScanner(f)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			hosts = append(hosts, strings.TrimSpace(scanner.Text()))
		}
		if err := scanner.Err(); err != nil {
			return hosts, err
		}
	} else {
		return hosts, err
	}
	return hosts, nil
}

// readShell
func readShell(path string) (string, error) {
	fd, err := ioutil.ReadFile(path)
	if err != nil {
		return "", err
	}
	rtn := strings.Replace(string(fd), "\t", "        ", -1)
	return rtn, nil
}

//@TODO remove this
func errorHandle() {
	if r := recover(); r != nil {
		fmt.Println("Fatal Error:", r, "\nExit.")
		os.Exit(1)
	}
}

func authMethod(t string) (ssh.AuthMethod, error) {
	switch t {
	case "password":
		fmt.Printf("Password: ")
		pass := gopass.GetPasswdMasked()
		return ssh.Password(string(pass)), nil
	case "forwarding":
		sock, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
		if err != nil {
			return nil, err
		}
		agent := agent.NewClient(sock)
		signers, err := agent.Signers()
		if err != nil {
			return nil, err
			// log.Fatal(err)
		}
		return ssh.PublicKeys(signers...), nil
	default:
		// usr, _ := user.Current()
		buf, err := ioutil.ReadFile(t)
		if err != nil {
			return nil, err
		}
		key, err := ssh.ParsePrivateKey(buf)
		if err != nil {
			return nil, err
		}
		return ssh.PublicKeys(key), nil
	}
	return nil, errors.New("No Authmethod available")
}

func exit(str string) {
	fmt.Println(str)
	if len(gIllegalMachines) != 0 {
		fmt.Println("Illegal host/ip:")
		for _, i := range gIllegalMachines {
			fmt.Println(i)
		}
	}
	os.Exit(1)
}
func handlePanic(err error) {
	fmt.Print(err.Error())
	gLogger.Fatalf("panic: %s", err.Error())
}

func getUsername() string {
	user, err := user.Current()
	if nil != err {
		fmt.Println("Can not get username,exit.")
		os.Exit(1)
	}
	return user.Username
}

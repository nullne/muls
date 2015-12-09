package main

import (
	// "chinacache/ris"
	"encoding/json"
	"fmt"
	"github.com/nullne/muls"
	"github.com/streadway/amqp"
	"log"
	// "strings"
	"sync"
	// "io"
)

type InMessage struct {
	ID        []byte
	Auth      Auth
	Commands  []muls.Command
	Machines  []muls.MachineMeta
	Timestamp int64
}

type Auth struct {
	Username, Password string
}

type OutMessage struct {
	ID        []byte
	Host      string
	Status    uint
	Err       string
	CmdResult CommandResult
	Progress  Progress
}

type Progress struct {
	Total, Done int
}

type CommandResult struct {
	Cmd      string
	Output   string
	ExitCode int
	Progress Progress
}

func handle(jsonstr []byte) {
	var m InMessage
	err := json.Unmarshal(jsonstr, &m)
	if err != nil{
		panic(err)
	}
	err = run(&m)
	if err != nil {
		panic(err)
	}
}

func run(in *InMessage) error {
	sshConfig, err := muls.AuthConfig(in.Auth.Username, map[string]interface{}{"password": in.Auth.Password})
	if err != nil {
		return err
	}
	m, err := muls.New(sshConfig, in.Machines, in.Commands, muls.Script{})
	if err != nil {
		return err
	}
	m.Mode = 1

	var wg sync.WaitGroup
	for _, machine := range m.MachinesList() {
		wg. Add(1)
		go func(){
			defer wg.Done()
			ch := machine.RealtimeQuery()
			for res := range ch {
				out := OutMessage{}
				out.ID = in.ID
				out.Host = machine.Host
				out.Status = machine.Status
				if machine.Err != nil{
					out.Err = machine.Err.Error()
				}
				total, done, _ := m.Progress()
				out.Progress = Progress{total, done}
				out.CmdResult.Cmd = res.Cmd
				out.CmdResult.ExitCode = res.ExitCode
				out.CmdResult.Output = string(res.Output)
				total, done, _ = machine.Progress()
				out.CmdResult.Progress = Progress{total, done}
				b, err := json.Marshal(out)
				if err != nil {
					panic(err)
				}
				output(b)
			}
		}()
	}

	err = m.Run()
	if err != nil {
		return err
	}
	wg.Wait()
	return nil
}

func output(body []byte) {
	conn, err := amqp.Dial("amqp://guest:guest@192.168.15.211:5672/")
	failOnError(err, "Failed to connect")
	defer conn.Close()

	ch, err := conn.Channel()
	failOnError(err, "Failed to Open a channel")
	defer ch.Close()

	q, err := ch.QueueDeclare(
		"muls-result",
		false,
		false,
		false,
		false,
		nil,
	)
	failOnError(err, "Failed to declare a queue")

	err = ch.Publish(
		"",
		q.Name,
		false,
		false,
		amqp.Publishing{
			ContentType: "application/json",
			Body:        body,
		})
	failOnError(err, "Failed to publish a message")
}

func main() {
	conn, err := amqp.Dial("amqp://guest:guest@192.168.15.211:5672/")
	failOnError(err, "Failed to connect")
	defer conn.Close()
	ch, err := conn.Channel()
	failOnError(err, "Failed to Open a channel")
	defer ch.Close()
	q, err := ch.QueueDeclare(
		"muls-test",
		false,
		false,
		false,
		false,
		nil,
	)
	failOnError(err, "Failed to declare a queue")

	msgs, err := ch.Consume(
		q.Name,
		"",
		true,
		false,
		false,
		false,
		nil,
	)
	failOnError(err, "Failed to register a consumer")

	forever := make(chan bool)
	go func() {
		for msg := range msgs {
			go handle(msg.Body)
		}
	}()

	log.Printf(" [*] Waitting for messages. To exit press CTRL+C")
	<-forever
}

func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
		panic(fmt.Sprintf("%s: %s", msg, err))
	}
}

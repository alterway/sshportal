package bastion // import "github.com/alterway/sshportal/pkg/bastion"

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

type logChannel struct {
	channel ssh.Channel
	writer  io.WriteCloser
}

func writeTTYRecHeader(fd io.Writer, length int) {
	t := time.Now()

	tv := syscall.NsecToTimeval(t.UnixNano())

	if err := binary.Write(fd, binary.LittleEndian, int32(tv.Sec)); err != nil {
		log.Printf("failed to write log header: %v", err)
	}
	if err := binary.Write(fd, binary.LittleEndian, int32(tv.Usec)); err != nil {
		log.Printf("failed to write log header: %v", err)
	}
	if err := binary.Write(fd, binary.LittleEndian, int32(length)); err != nil {
		log.Printf("failed to write log header: %v", err)
	}
}

//nolint:all
func NewLogChannel(channel ssh.Channel, writer io.WriteCloser) *logChannel {
	return &logChannel{
		channel: channel,
		writer:  writer,
	}
}

func (l *logChannel) Read(_ []byte) (int, error) {
	return 0, fmt.Errorf("logChannel.Read is not implemented")
}

func (l *logChannel) Write(data []byte) (int, error) {
	writeTTYRecHeader(l.writer, len(data))

	if _, err := l.writer.Write(data); err != nil {
		log.Printf("failed to write log: %v", err)
	}

	return l.channel.Write(data)
}

func (l *logChannel) LogWrite(data []byte) (int, error) {
	writeTTYRecHeader(l.writer, len(data))

	v, err := l.writer.Write(data)
	if err != nil {
		log.Printf("failed to write log: %v", err)
	}

	return v, err
}

func (l *logChannel) Close() error {
	if err := l.writer.Close(); err != nil {
		log.Printf("failed to close log channel: %v", err)
	}

	return l.channel.Close()
}

package protocol

import (
	"fmt"
	"io"
	"net"
	"time"
)

type (
	Connector interface {
		ReadPacket() (Packet, error)
		WritePacket(Packet) error
		Auth(Connector) error
		TransportCmdResp(Connector) error
		Closed() bool
		Expired(time.Duration) bool
		RefreshUseTime()
		Close() error
	}

	Conn struct {
		c                 net.Conn
		initHandPacket    Packet
		authSuccessPacket Packet
		authSuccess       bool
		usedTime          time.Time
		closed            bool
	}
)

func NewConn(c net.Conn) Connector {
	return &Conn{c: c, usedTime: time.Now()}
}

func (c *Conn) ReadPacket() (Packet, error) {

	p := Packet{}
	if c.Closed() {
		return p, ErrConnClosed
	}

	// read header
	header := make([]byte, 4)
	if _, err := io.ReadFull(c.c, header); err != nil {
		c.Close()
		return p, fmt.Errorf("read packet header err: %w", err)
	}

	p.SeqId = uint8(header[3])

	dataLen := int(uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16)
	if dataLen < 1 {
		return p, nil
	}

	// read body
	data := make([]byte, dataLen)
	if _, err := io.ReadFull(c.c, data); err != nil {
		c.Close()
		return p, fmt.Errorf("read packet payload err: %w", err)
	}
	p.Payload = data

	if dataLen < MAX_PAYLOAD_LEN {
		return p, nil
	}

	// append split packet
	p2, err := c.ReadPacket()
	if err != nil {
		c.Close()
		return p, fmt.Errorf("read split packet err: %w", err)
	}

	p.Payload = append(p.Payload, p2.Payload...)
	return p, nil
}

func (c *Conn) WritePacket(p Packet) error {
	if c.Closed() {
		return ErrConnClosed
	}

	ps := p.Split()
	for _, p2 := range ps {
		writeData := append(p2.Header(), p2.Payload...)
		if n, err := c.c.Write(writeData); err != nil {
			return fmt.Errorf("write packet err: %w", err)
		} else if n != len(writeData) {
			return fmt.Errorf("write packet length err: write(%d) data(%d)", n, len(writeData))
		}
	}
	return nil
}

func (c *Conn) Auth(client Connector) error {
	if c.authSuccess {
		return c.fakeAuth(client)
	}
	return c.firstAuth(client)
}

// 整个认证的时序图可以参考： https://www.jianshu.com/p/ef286d39e41d
func (c *Conn) firstAuth(client Connector) error {
	var err error
	//这里得到proxy连接mysql server的包
	initPacket, err := c.ReadPacket()
	if err != nil {
		return fmt.Errorf("read init packet err: %w", err)
	}

	c.initHandPacket = initPacket

	//step1. 握手初始化(服务端主动发起)
	// send init packet 这里proxy把从服务端得到的包转发给client
	err = client.WritePacket(c.initHandPacket)
	if err != nil {
		return fmt.Errorf("send init err: %w", err)
	}

	//step2-1: 客户端发起登录认证
	// read auth packet
	authPacket, err := client.ReadPacket()
	if err != nil {
		return fmt.Errorf("read auth packet err: %w", err)
	}

	//step2-2 proxy转发给mysql服务端
	// send auth to server
	err = c.WritePacket(authPacket)
	if err != nil {
		return fmt.Errorf("send auth packet err: %w", err)
	}
	//step3-1： mysql server返回认证结果给proxy
	// read auth result
	authResult, err := c.ReadPacket()
	if err != nil {
		return fmt.Errorf("read auth result err: %w", err)
	}

	//step3-2： proxy返回认证结果给mysql client
	// send auth result
	err = client.WritePacket(authResult)
	if err != nil {
		return fmt.Errorf("send result err: %w", err)
	}

	if IsErrPacket(authResult) {
		return ErrAuth
	}

	c.authSuccessPacket = authResult
	c.authSuccess = true

	return nil
}

func (c *Conn) fakeAuth(client Connector) error {
	if c.authSuccess == false {
		return ErrNoAuth
	}

	var err error

	// send init packet
	err = client.WritePacket(c.initHandPacket)
	if err != nil {
		return fmt.Errorf("send init err: %w", err)
	}

	// read auth packet
	_, err = client.ReadPacket()
	if err != nil {
		return fmt.Errorf("read auth packet err: %w", err)
	}

	// send auth result
	err = client.WritePacket(c.authSuccessPacket)
	if err != nil {
		return fmt.Errorf("send result err: %w", err)
	}

	return nil
}

func (c *Conn) TransportCmdResp(client Connector) error {
	columnEnd := false

	for {
		respPacket, err := c.ReadPacket()
		if err != nil {
			return err
		}
		err = client.WritePacket(respPacket)
		if err != nil {
			return fmt.Errorf("write client err:%w", err)
		}

		if IsErrPacket(respPacket) {
			return nil
		}

		if IsOkPacket(respPacket) {
			return nil
		}

		if IsEofPacket(respPacket) {
			if columnEnd {
				// data end
				return nil
			} else {
				columnEnd = true
			}
		}
	}
}

func (c *Conn) Closed() bool {
	return c.closed
}

func (c *Conn) Expired(t time.Duration) bool {
	if time.Now().Sub(c.usedTime) < t {
		return false
	}
	return true
}

func (c *Conn) RefreshUseTime() {
	c.usedTime = time.Now()
}

func (c *Conn) Close() error {
	if c.closed {
		return ErrConnClosed
	}
	c.closed = true
	return c.c.Close()
}

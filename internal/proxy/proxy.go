package proxy

import (
	"github.com/lyuangg/umyproxy/protocol"
	"log"
	"net"
	"os"
)

type (
	Proxy struct {
		server     net.Listener
		pool       *Pool
		socketFile string
		listenAddr string
		debug      bool
	}
)

func NewProxy(p *Pool, socketfile string, listenAddr string) *Proxy {
	return &Proxy{
		pool:       p,
		socketFile: socketfile,
		listenAddr: listenAddr,
	}
}

func (p *Proxy) Run() {
	//修改原有的socket监听，改成监听端口
	//p.deleteSocketFile()
	//serv, err := net.Listen("unix", p.socketFile)

	serv, err := net.Listen("tcp", p.listenAddr)
	if err != nil {
		log.Fatalln("Listen err:", err)
	}
	p.server = serv
	p.startPrint()

	for {
		conn, err := p.server.Accept()
		if err != nil {
			log.Fatalln("conn err:", err)
		}
		p.debugPrintf("accept conn")

		go p.HandleConn(conn)
	}
}

func (p *Proxy) SetDebug() {
	p.debug = true
	p.debugPrintf("debug mode")
}

func (p *Proxy) debugPrintf(format string, v ...interface{}) {
	if p.debug {
		format = "[DEBUG]" + format + "\n"
		log.Printf(format, v...)
	}
}

func (p *Proxy) startPrint() {
	log.Println("start server: ", p.socketFile)
	log.Println("host:", p.pool.option.Host)
	log.Println("port:", p.pool.option.Port)
	log.Println("pool_size:", p.pool.option.PoolMaxSize)
	log.Println("conn_maxlifetime:", p.pool.option.MaxLifetime)
	log.Println("wait_timeout:", p.pool.option.WaitTimeout)
}

func (p *Proxy) HandleConn(conn net.Conn) {
	//1.接受客户端联接
	client := protocol.NewConn(conn)
	defer client.Close()
	//2.代理与服务端建立一个连接
	mysqlServ, err := p.Get()
	if err != nil {
		log.Printf("get mysql conn err: %+v \n", err)
		return
	}
	p.debugPrintf("get mysql conn")
	defer p.Put(mysqlServ)

	// 3.认证
	if err := mysqlServ.Auth(client); err != nil {
		log.Printf("mysql auth err: %+v \n", err)
		return
	}
	p.debugPrintf("client auth success")

	// 发送命令
	for {
		cmdPacket, err := client.ReadPacket()
		if err != nil {
			log.Printf("read client cmd err: %+v \n", err)
			break
		}
		p.debugPrintf("read cmd: %+v", cmdPacket)

		if protocol.IsQuitPacket(cmdPacket) {
			p.debugPrintf("quit cmd")
			break
		}

		err2 := mysqlServ.WritePacket(cmdPacket)
		if err2 != nil {
			log.Printf("write cmd packet to server err: %+v \n", err2)
			break
		}
		p.debugPrintf("write cmd to mysql")

		// read response
		p.debugPrintf("start transport mysql response")
		err = mysqlServ.TransportCmdResp(client)
		if err != nil {
			log.Printf("transport response err: %+v \n", err)
			break
		}
		p.debugPrintf("end transport mysql response")
	}
}

func (p *Proxy) Get() (protocol.Connector, error) {
	return p.pool.Get()
}

func (p *Proxy) Put(conn protocol.Connector) error {
	p.debugPrintf("put conn")
	return p.pool.Put(conn)
}

func (p *Proxy) Close() {
	p.pool.Close()
	p.server.Close()
}

func (p *Proxy) deleteSocketFile() error {
	_, err := os.Stat(p.socketFile)
	if err == nil || os.IsExist(err) {
		return os.Remove(p.socketFile)
	}
	return err
}

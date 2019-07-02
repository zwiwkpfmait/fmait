
#include "config.hh"
#include <uv.h>
#include "fmait/lang.hh"


#ifndef LOG_LIB
#define debug(format,...) printf(format,__VA_ARGS__);printf("\n")
#define info(format,...) printf(format,__VA_ARGS__);printf("\n")
#define warn(format,...) printf(format,__VA_ARGS__);printf("\n")
#define error(format,...) printf(format,__VA_ARGS__);printf("\n")
#define fatal(format,...) printf(format,__VA_ARGS__);printf("\n")
#else
#define debug(format,...) 
#define info(format,...) 
#define warn(format,...) 
#define error(format,...) 
#define fatal(format,...) 

#endif



typedef int task_t;
typedef int conn_t;

class Task
{
public:
	enum Type
	{
		kTypeNone,
		kTypeConn,
		kTypeSend,
		kTypeRecv,
		kTypeClose,
	};
private:
	task_t m_id;
	Type m_type;
	conn_t m_conn;
	byte* m_data;
	size_t m_capacity;
public:
	Task():
		m_id(0),m_type(kTypeNone),m_conn(0),m_data(nullptr),m_capacity(0)
	{}
	Task(task_t id,Type type,conn_t conn,byte* data, size_t capacity):
		m_id(id),m_type(type), m_conn(conn), m_data(data), m_capacity(capacity)
	{}
	~Task() {}
public:
	task_t get_id() { return m_id; }
	Type get_type() { return m_type; }
	conn_t get_conn() { return m_conn; }
	byte* get_data() { return m_data; }
	size_t get_capacity() { return m_capacity; }

	void set_id(task_t id) { m_id = id; }
	void set_type(Type type) { m_type = type; }
	void set_conn(conn_t conn) { m_conn = conn; }
	void set_data(byte* data) { m_data = data; }
	void set_capacity(size_t capacity) { m_capacity = capacity; }
};

class ConnInfo
{
private:
	std::string m_ip;
	int m_port;
public:
	ConnInfo():m_port(0)
	{}
	ConnInfo(const std::string& ip, int port) :
		m_ip(ip), m_port(port)
	{}
	ConnInfo(const ConnInfo& info):m_ip(info.m_ip),m_port(info.m_port)
	{}
	~ConnInfo() {}
public:
	const std::string& get_ip() { return m_ip; }
	int get_port() { return m_port; }

	void set_ip(const std::string& ip) { m_ip = ip; }
	void set_port(int port) { m_port = port; }

};
class IConnection
{
public:
	IConnection() {}
	virtual ~IConnection() {}
public:
	virtual int Send() =0;
	virtual int Recv() =0;
	virtual int Close() = 0;
	virtual int Malloc(size_t capacity, byte** buf) = 0;
	virtual int GetInfo(ConnInfo* info) = 0;
};
class IHandler
{
public:
	virtual int OnAccpet(conn_t conn) = 0;
	virtual int OnSend(conn_t conn, void* data, size_t data_len) = 0;
	virtual int OnRecv(conn_t conn, void* data, size_t data_len) = 0;
	virtual int OnClose(conn_t conn) = 0;
};
class IServer
{
public:
	IServer() {}
	virtual ~IServer() {}
public:
	virtual int Config(const std::string& conf_url) = 0;
	virtual int Listen(const std::string& ip, int port, IHandler* handler) =0;
	virtual int Run() =0;
	virtual int Stop() =0;
	virtual int Accpet(conn_t* conn) =0;
	virtual IHandler* GetHandler() = 0;
};

class TCPHandler :public IHandler
{
public:
	virtual int OnAccpet(conn_t conn)
	{
		debug("TCPHandler::OnAccpet() entry");
		return 0;
	}
	virtual int OnSend(conn_t conn, void* data, size_t data_len)
	{
		debug("TCPHandler::OnSend() entry");
		return 0;
	}
	virtual int OnRecv(conn_t conn, void* data, size_t data_len)
	{
		debug("TCPHandler::OnRecv() entry");
		return 0;
	}
	virtual int OnClose(conn_t conn)
	{
		debug("TCPHandler::OnClose() entry");
		return 0;
	}
};


class GeneralServer;

class TCPConnection:public IConnection
{
	friend class GeneralServer;
public:
	TCPConnection()
	{
		m_default_capacity = 4 * 1024;
		m_buf = new byte[m_default_capacity];
	}
	~TCPConnection()
	{
		delete[] m_buf;
	}
public:
	virtual int Send()
	{
		return 0;
	}
	virtual int Recv()
	{
		return 0;
	}
	virtual int Close()
	{
		return 0;
	}
	virtual int Malloc(size_t capacity, byte** buf)
	{
		if (capacity > m_default_capacity)
		{
			return -1;
		}
		*buf = m_buf;
		return 0;
	}
	virtual int GetInfo(ConnInfo* info)
	{
		*info = *m_info;
		return 0;
	}
private:
	conn_t m_id;
	ConnInfo* m_info;
	GeneralServer* m_server;
	size_t m_default_capacity;
	byte* m_buf;
};

class GeneralServer :public IServer
{
	friend class TCPConnection;
public:
	GeneralServer():
		m_conn_pos(0),m_task_pos(0)
	{

	}
	~GeneralServer()
	{

	}
public:
	virtual int Config(const std::string& conf_url)
	{
		return 0;
	}
	virtual int Listen(const std::string& ip,int port,IHandler* handler)
	{
		int err = 0;

		if ((err = uv_loop_init(&m_loop)) != 0)
		{
			error(uv_strerror(err));
			return err;
		}
		if ((err = uv_tcp_init(&m_loop, &m_listen)) != 0)
		{
			error(uv_strerror(err));
			return err;
		}

		sockaddr_in addr;
		if ((err = uv_ip4_addr(ip.c_str(), port, &addr)) != 0)
		{
			error(uv_strerror(err));
			return err;
		}

		if ((err = uv_tcp_bind(&m_listen, (const struct sockaddr*)&addr, 0)) != 0)
		{
			error(uv_strerror(err));
			return err;
		}


		if ((err = uv_listen((uv_stream_t*)&m_listen, 1000, OnAccpet)) != 0)
		{
			//m_logger->error(uv_strerror(error));
			return err;
		}
		m_loop.data = this;
		m_handler = handler;
		return 0;
	}
	virtual int Run()
	{
		int err = 0;
		debug("The server is running");
		if ((err = uv_run(&m_loop, UV_RUN_DEFAULT)) != 0)
		{
			error(uv_strerror(err));
			return err;
		}
		
		return 0;
	}
	virtual int Stop()
	{
		return 0;
	}
	virtual int Accpet(conn_t* conn)
	{
		int err = 0;
		uv_tcp_t* client = new uv_tcp_t;
		uv_tcp_init(&m_loop, client);
		if ((err = uv_accept((uv_stream_t*)&m_listen, (uv_stream_t*)client)) != 0)
		{
			error(uv_strerror(err));
			delete client;
			return -1;
		}
		//´´½¨Á¬½Ó
		auto ip = GetAddr((uv_stream_t*)client);
		m_conn_pos++;
		TCPConnection* pconn = new TCPConnection();
		pconn->m_info = new ConnInfo(ip.first,ip.second);
		pconn->m_server = this;
		pconn->m_id = m_conn_pos;

		m_conns[pconn->m_id] = pconn;
		m_clients[pconn->m_id] = client;

		info("%s:%d connected",ip.first.c_str(),ip.second);

		//´´½¨Á¬½Ó»Øµ÷ÈÎÎñ£¬½»¸øÏß³Ì³ØÖ´ÐÐ,Ö»ÓÐ¸ÃÖÖÈÏÎªÌØÊâ£¬²»·ÅÔÚÈÎÎñ¶ÓÁÐÀï£¬Ö±½ÓÈÃ
		//Ïß³Ì³ØÀ´Ö´ÐÐ

		task_t task_id = ++m_task_pos;
		Task* task = new Task();
		task->set_id(task_id);
		task->set_type(Task::kTypeConn);
		task->set_conn(pconn->m_id);
		task->set_data(nullptr);
		task->set_capacity(0);
		

		uv_work_t* req = new uv_work_t;
		req->data = task;
		uv_queue_work(m_listen.loop, req, OnWork, OnWorkAfter);
		
	
		//¶ÔÓÚ¸ÕÁ¬½ÓµÄ¿Í»§¶Ë£¬ÏÈ¶ÁÒ»ÏÂÊý¾Ý,Ö®Ç°Ö±½Óµ÷ÓÃ,·¢ÏÖÍ¬Ò»¸öÁ¬½Ó£¬·¢ËÍÁ½¸öioÇëÇó
		//»á¸²¸ÇdataÖÐµÄtaskÖ¸Õë£¬ËùÒÔÕâÀï·ÅÈëÈÎÎñ¶ÓÁÐÀï
		m_task_pos++;
		Task* recv_task = new Task(m_task_pos,Task::kTypeRecv, pconn->m_id,pconn->m_buf,pconn->m_default_capacity);
		client->data = task;
		uv_read_start((uv_stream_t*)client,OnAlloc,OnRecv);
		return 0;
	}

	virtual IHandler* GetHandler()
	{
		return m_handler;
	}
public:
	std::pair<std::string, int> GetAddr(uv_stream_t* client)
	{
		sockaddr sock_addr;
		int sock_addr_len = sizeof(sockaddr);
		uv_tcp_getsockname((uv_tcp_t*)client, &sock_addr, &sock_addr_len);
		sockaddr_in* addr = (sockaddr_in*)&sock_addr;
		char* ip = inet_ntoa(addr->sin_addr);
		std::string ip4(ip);
		int port = addr->sin_port;
		return std::make_pair(ip4, port);
	}

	Task* DetachTask(task_t id)
	{
		auto find_it = m_tasks.find(id);
		if (find_it == m_tasks.end())
		{
			return nullptr;
		}
		Task* task = find_it->second;
		auto conn_id = task->get_conn();
		auto& task_queue = m_task_queue[conn_id];

		auto find_it2 = std::find(task_queue.begin(),task_queue.end(),task->get_id());
		if (find_it2 != task_queue.end())
		{
			task_queue.erase(find_it2);
		}
		return task;
	}

	//¸Ãº¯Êý²»·ÖÅäÁ¬½ÓÈÎÎñ
	int AssignTask()
	{
		//ÕâÀïÏÈÃ¿´ÎÖ»È¡Ò»¸öÈÎÎñ²âÊÔÒ»ÏÂ
		Task* task = m_tasks.begin()->second;
		uv_tcp_t* client = m_clients[task->get_conn()];
		client->data = task;
		switch (task->get_type())
		{
		case Task::kTypeRecv:
		{
			uv_read_start((uv_stream_t*)client, OnAlloc, OnRecv);
			break;
		}
		case Task::kTypeSend:
		{
			uv_write_t* req = new uv_write_t;
			//uv_write2(req, (uv_handle_t*)client, ()task->get_data(), task->get_capacity(), OnSend);
			break;
		}
		case Task::kTypeClose:
		{
			break;
		}
		default:
			break;
		}
		return 0;
	}
private:
	static void OnAccpet(uv_stream_t* listen, int status)
	{
		int err = 0;

		GeneralServer* server = (GeneralServer*)listen->loop->data;

		conn_t conn;
		err = server->Accpet(&conn);
	}
	static void OnSend(uv_write_t* req, int status)
	{

	}
	static void OnRecv(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
	{
		debug("OnRecv()");
	}
	static void OnClose(uv_handle_t* handle)
	{

	}
	static void OnWork(uv_work_t* req)
	{
		int err = 0;
		GeneralServer* server = (GeneralServer*)req->loop->data;

		auto task = (Task*)req->data;
		switch (task->get_type())
		{
		case Task::kTypeConn:
			server->GetHandler()->OnAccpet(task->get_conn());
			break;
		default:
			break;
		}
	}
	static void OnWorkAfter(uv_work_t* req, int status)
	{
		int err = 0;
		GeneralServer* server = (GeneralServer*)req->loop->data;

		//»ØÊÕÏß³Ì³ØÇëÇó×ÊÔ´
		delete req->data;
		delete req;

		//·ÖÅäÈÎÎñ
		server->AssignTask();
	}
	static void OnAlloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
	{
		Task* task = (Task*)handle->data;
		if (task->get_capacity() < suggested_size)
		{
			return;
		}
		else
		{
			buf->base = (char*)task->get_data();
		}
	}
private:
	uv_loop_t m_loop;
	uv_tcp_t m_listen;
	IHandler* m_handler;
	std::map<conn_t, TCPConnection*> m_conns;
	std::map<conn_t, uv_tcp_t*> m_clients;
	std::map<conn_t, std::list<task_t> >m_task_queue;
	std::map<task_t, Task*> m_tasks;
	int m_task_pos;
	int m_conn_pos;
};


int main(int argc, char** argv)
{
	TCPHandler handler;
	GeneralServer server;
	server.Config("");
	server.Listen("0.0.0.0",80,&handler);
	server.Run();
	Sleep(10000);

}

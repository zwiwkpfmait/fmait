server.CreateConn();
server.CloseConn();
server.Send()
server.Recv()

handler.OnAccpet()
handler.OnClose()
handler.OnSend()
handler.OnRecv()

#ifndef LOG_LIB
#define debug(format,...) printf(format,__VA_ARGS__)
#define info(format,...) printf(format,__VA_ARGS__)
#define warn(format,...) printf(format,__VA_ARGS__)
#define error(format,...) printf(format,__VA_ARGS__)
#define fatal(format,...) printf(format,__VA_ARGS__)
#else
#define debug(format,...) 
#define info(format,...) 
#define warn(format,...) 
#define error(format,...) 
#define fatal(format,...) 

#endif


typedef int conn_id;
typedef int task_id;

void on_accpet(uv_stream_t* listen, int status)
{
	int error = 0;
	GeneralServer* pserver = (GeneralServer*)listen->loop->data;
	GeneralServer& server = *perser;
	//建立连接
	conn_id conn = 0;
	error = server.CreateConn(&conn);

	if(error != 0)
	{
		error("%s",uv_strerror(error));
		return;
	}

	if(conn == 0) return;
	//创建连接任务
	task_id task;
	error = server.CreateTask(conn,kTypeConn,nullptr,&task);
}

void on_send(uv_write_t* req, int status)
{
	int error = 0;

	GeneralServer* pserver = (GeneralServer*)listen->loop->data;
	GeneralServer& server = *perser;

	conn_id conn = *(conn_id*)req->data;
	delete req->data;
	task_id task = 0;
	error = server.CreateTask(conn,kTypeSend,,&task);
}

void on_recv(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
	int error = 0;

	GeneralServer* pserver = (GeneralServer*)listen->loop->data;
	GeneralServer& server = *perser;

	conn_id conn = *(conn_id*)req->data;
	delete req->data;
	task_id task = 0;
	error = server.CreateTask(conn,kTypeRecv,,&task);
}

void on_close(uv_handle_t* handle)
{
	int error = 0;

	GeneralServer* pserver = (GeneralServer*)listen->loop->data;
	GeneralServer& server = *perser;

}


void on_work(uv_work_t* req)
{
	int error = 0;

	task_id t_id = *(task_id*) = req->data;
	GeneralServer* pserver = (GeneralServer*)listen->loop->data;
	GeneralServer& server = *perser;

	IHandler* phandler = server.GetHandler();
	IHandler& handler = *phandler;

	Task* task = server.DetachTask(t_id);

	conn_id conn = task->GetConn();

	if(server.IsClosedAndTryClose(conn))
	{
		handler.OnClose(conn);
		return;
	}

	switch(task->GetType())
	{
		case Task::kTypeConn:
			handler.OnConn(conn);
			break;
		case Task::kTypeSend:
			handler.OnSend(conn,task->GetData(),task->GetDataLen())
		case Task::kTypeRecv:
			handler.OnRecv(conn,task->GetData(),task->GetDataLen())
		default:
			break;
	}

}

void on_work_after(uv_work_t* req, int status)
{

	//释放资源
	Task* task =  (Task*)req->data;
	delete[]  task->GetData();

	delete req->data;
	delete req;
}

void on_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
	buf->base = new byte(suggested_size);
}
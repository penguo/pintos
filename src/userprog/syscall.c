#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include <devices/shutdown.h>
#include <filesys/filesys.h>
#include "userprog/process.h"
#include <filesys/file.h>
#include <devices/input.h>

static void syscall_handler (struct intr_frame *);
void check_address(void *addr);
void get_argument(void *esp, int *arg, int count);
void halt(void);
void exit(int status);
tid_t exec(const char *cmd_line);
bool create(const char* file, unsigned inital_size);
bool remove(const char* file);
int wait(tid_t pid);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer,unsigned size);
int write(int fd, void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

	//lock 초기화
	lock_init(&filesys_lock);
}

void
halt(void)
{
//	printf("\nhalt!!!\n");
	printf("%s\n", thread_name());
	shutdown_power_off();
}

void
exit(int status)
{
	//프로세스 디스크립터에 exit_status 저장
	thread_current()->exit_status = status;
	printf("%s: exit(%d)\n", thread_name(), status);
	thread_exit();
}

bool 
create(const char* file, unsigned initial_size)
{
//	printf("\ncreate!!!\n");
//	printf("%s: create(%s)\n", thread_name(), file);

	return filesys_create(file, initial_size);
}


bool
remove(const char* file)
{
//	printf("\nremove!!!\n");
//	printf("%s: remove(%s)\n", thread_name(), file);
	
	return filesys_remove(file);
}

//자식 프로세스를 생성하고 프로그램을 실행시키는 시스템 콜
tid_t 
exec(const char *cmd_line)
{	
	
	struct thread *child;
	tid_t pid;

	//명령어(cmd_line)에 해당하는 프로그램을 수행하는 프로세스 생성
	pid = process_execute(cmd_line); 

	//생성된 자식 프로세스의 프로세스 디스크립터 검색
	child = get_child_process(pid);

	//자식 프로세스의 프로그램이 로드될 때 까지 대기
	sema_down(&child->load_sema);
	
	//프로그램 로드 성공 시 자식 프로세스 pid 반환
	if(child->loaded ==true)
		return pid;
	
	//프로그램 로드 실패시 -1 리턴
	else				
		return -1; 
}

int 
wait(tid_t pid)
{
	//자식 프로세스가 종료될 때 까지 대기
	return process_wait(pid);
}

int
open(const char *file)
{
	//파일 open			
	struct file *f = filesys_open(file);
	int fd;
	
	//g해당 파일이 존재하지 않을 시 -1 리턴
	if(f == NULL)
		return -1;
	
	//해당 파일 객체에 파일 디스크립터 부여
	fd = process_add_file(f);

	//파일 디스크립터 리턴
	return fd;
}

int
filesize(int fd)
{
	struct file *f = process_get_file(fd);

	if(!f)
		return -1;

	return file_length(f);
}

int
read(int fd, void *buffer, unsigned size)
{

	//파일 디스크립터를 이용하여 파일 객체 검색		
	struct file *f = process_get_file(fd);
	int i;
	
	if( fd ==1)
		return -1;


	//파일 디스크립터가 0인 경우
	if (fd == 0)
	{
		char *cur_buffer = (char *)buffer;
		
		//input_getc 함수 이용하여 키보드 데이터 읽음
		for(i=0 ; i<size ; i++)
		{
			cur_buffer[i] = input_getc();
		}
	
		//버퍼 크기 리턴
		return size;
	}

	//lock 사용하여 동시 접근 방지
	lock_acquire(&filesys_lock);

	if(f == NULL)
	{
		lock_release(&filesys_lock);
		return 0;
	}

	else
	{
		//파일 read
		size = file_read(f,buffer,size);
		
		//lock 해제
		lock_release(&filesys_lock);
		
		//읽은 바이트 수 리턴
		return size;
	}

}

int
write(int fd, void *buffer, unsigned size)
{

	struct file *f = process_get_file(fd);

	if(fd == 0)
		return -1;


	//파일 디스크립터가 1인 경우
	if(fd == 1)
	{
		//버퍼에 저장된 값 화면 출력
		putbuf(buffer, size);
		
		//버퍼의 크기 리턴
		return size;
	}


	lock_acquire(&filesys_lock);

	if(f == NULL)
	{
		lock_release(&filesys_lock);
		return 0;
	}

	else
	{
		//파일 write
	 	size= file_write(f,buffer,size);
		
		//락 해제
		lock_release(&filesys_lock);

		//파일에 쓴 바이트 수 리턴
		return size;
	}

}


void
seek(int fd, unsigned position)
{
	struct file *f = process_get_file(fd);
	
	if(f == NULL)
		return;
	//해당 열린 파일의 위치를 position만큼 이동
	file_seek(f, position);
	
}

unsigned
tell(int fd)
{
	struct file *f = process_get_file(fd);

	if(f == NULL)
		return;
	//해당 열린 파일의 위치를 반환
	return file_tell(f);
}

void
close(int fd)
{
	//해당 파일 디스크립터에 해당하는 파일을 닫고 
	//파일 디스크립터 엔트리 초기화		
	process_close_file(fd);
}




static void
syscall_handler (struct intr_frame *f) 
{
	//system call's argument loading from stack
	int *h_esp = f->esp;
	int syscall_num = *h_esp;	
	int arg[5];	
//	printf("\nsyscall number : %d\n", syscall_num);	

	switch(syscall_num)
	{
		case SYS_HALT:
		halt();
		break;
		
		case SYS_EXIT:
		get_argument(h_esp, arg, 1);
		exit(arg[0]);
		f->eax = arg[0];
		break;

		case SYS_EXEC:
		get_argument(h_esp, arg, 1);
		check_address(arg[0]); //check
		f->eax = exec(arg[0]); //return tid_t
		break;

		case SYS_WAIT:
		get_argument(h_esp, arg, 1);
	//	printf("%d", arg[0]);
	//	check_address(arg[0]); //check
		f->eax = wait(arg[0]); //return int
		break;

		case SYS_CREATE:
		get_argument(h_esp, arg, 2); //get argument
		check_address(arg[0]); //check
		f->eax = create(arg[0], arg[1]); // get return
		break;

		case SYS_REMOVE:
		get_argument(h_esp, arg, 1);
		check_address(arg[0]); //check
		f->eax = remove(arg[0]);
		break;

		case SYS_OPEN:
		get_argument(h_esp, arg,1);
		check_address(arg[0]);
		f->eax = open(arg[0]);
		break;
		
		case SYS_FILESIZE:
		get_argument(h_esp, arg, 1);
//		check_address(arg[0]);
		f->eax = filesize(arg[0]);
		break;

		case SYS_READ:
		get_argument(h_esp , arg, 3);
		check_address(arg[1]);
		f->eax = read (arg[0], (const void *)arg[1], (unsigned)arg[2]);
		break;

		case SYS_WRITE:
		get_argument(h_esp, arg,3);
		check_address(arg[1]);
		f->eax = write(arg[0] , (const void *)arg[1], (unsigned)arg[2]);
		break;

		case SYS_SEEK:
		get_argument(h_esp, arg, 2);
	//	check_address(arg[0]);
		seek(arg[0], (unsigned)arg[1]);
		break;

		case SYS_TELL:
		get_argument(h_esp, arg,1);
	//	check_address(arg[0]);
		f->eax = tell(arg[0]);
		break;

		case SYS_CLOSE:
		get_argument(h_esp, arg,1);
		close(arg[0]);
		break;

		default :
		printf("default\n");
	}
}

void 
get_argument(void *esp, int *arg, int count)
{ //esp for stack pointer, count is number of argument
	int i;	
	int *ptr;
//	esp += 4;
	
//	printf("esp: %p\n", esp);
//	check_address(esp);
//	check_address(esp + ((count-1)*4)); //address checking for security
	
	for (i=0; i<count; i++){
	
		ptr = (int *)esp + i + 1;
		check_address(ptr);
		arg[i] = *ptr;

//		printf("arg[%d] is %d\n", i, arg[i]);
	}
}

void 
check_address(void *addr)
{ //check address is user's address
	//user address : 0x08048000~0xc0000000
	if(!((void *)0x08048000 < addr && addr < (void *)0xc0000000)){
		printf("\ncheck_address error!!\n");
		thread_exit();
	}
}

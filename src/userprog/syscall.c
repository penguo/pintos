#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include <devices/shutdown.h>
#include <filesys/filesys.h>

static void syscall_handler (struct intr_frame *);
void check_address(void *addr);
void get_argument(void *esp, int *arg, int count);
void halt(void);
void exit(int status);
tid_t exec(const char *cmd_line);
bool create(const char* file, unsigned inital_size);
bool remove(const char* file);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void
halt(void)
{
	printf("\nhalt!!!\n");
	printf("%s\n", thread_name());
	shutdown_power_off();
}

void exit(int status)
{
	//프로세스 디스크립터에 exit_status 저장
	thread_current()->exit_status = status;
	printf("%s: exit(%d)\n", thread_name(), status);
	thread_exit();
}

bool 
create(const char* file, unsigned initial_size)
{
	printf("\ncreate!!!\n");
	printf("%s: create(%s)\n", thread_name(), file);

	return filesys_create(file, initial_size);
}


bool
remove(const char* file)
{
	printf("\nremove!!!\n");
	printf("%s: remove(%s)\n", thread_name(), file);
	
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
wait(int pid)
{
	//자식 프로세스가 종료될 때 까지 대기
	return process_wait(pid);
}


static void
syscall_handler (struct intr_frame *f) 
{
	//system call's argument loading from stack
	int *h_esp = f->esp;
	int syscall_num = *h_esp;	
	int arg[5];	
	printf("\nsyscall number : %d\n", syscall_num);	

	switch(syscall_num)
	{
		case SYS_HALT:
		halt();
		break;
		
		case SYS_EXIT:
		get_argument(h_esp, arg, 1);
		exit((int)arg[0]);
		f->eax = arg[0];
		break;

		case SYS_EXEC:
		get_argument(h_esp, arg, 1);
		check_address((void *)arg[0]); //check
		f->eax = exec((const char *)arg[0]);//return tid_t
		break;

		case SYS_WAIT:
		get_argument(h_esp,arg,1);
		check_address((void *)arg[0]); //check
		f->eax = process_wait((int)arg[0]);//return int
		break;

		case SYS_CREATE:
		get_argument(h_esp, arg, 2); //get argument
		check_address((void *)arg[0]); //check
		f->eax = create((const char *)arg[0], arg[1]); // get return
		break;

		case SYS_REMOVE:
		get_argument(h_esp, arg, 1);
		check_address((void *)arg[0]); //check
		f->eax = remove((const char *)arg[0]);
		break;

		case SYS_FILESIZE:
		break;

		case SYS_READ:
		break;

		case SYS_WRITE:
		break;

		case SYS_SEEK:
		break;

		case SYS_TELL:
		break;

		case SYS_CLOSE:
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
	esp += 4;
	
	check_address(esp);
	check_address(esp + ((count-1)*4)); //address checking for security
	
	for (i=0; i<count; i++){
		ptr = (int *)esp + i;
		arg[i] = *ptr;

//		printf("arg[%d] is %d\n", i, arg[i]);
	}
}

void 
check_address(void *addr)
{ //check address is user's address
	//user address : 0x08048000~0xc0000000
	if(!((void *)0x08048000 < addr && addr < (void *)0xc0000000)){
		thread_exit();
	}
}

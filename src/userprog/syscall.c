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
bool create(const char* file, unsigned inital_size);
bool remove(const char* file);


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void halt(void){
	printf("\nhalt!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
	printf("%s\n", thread_name());
	shutdown_power_off();
}

void exit(int status){
	printf("\nexit!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
	printf("%s: exit(%d)\n", thread_name(), status);
	thread_exit();
}

bool create(const char* file, unsigned initial_size){
	printf("\ncreate!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
	printf("%s: create(%s)\n", thread_name(), file);
	return filesys_create(file, initial_size);
}

bool remove(const char* file){
	printf("\nremove!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
	printf("%s: remove(%s)\n", thread_name(), file);
	return filesys_remove(file);
}

syscall_handler (struct intr_frame *f) 
{
	//printf("System call!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
	printf("\nsyscall number : %d\n",*(int *)(f->esp));
	//system call's argument loading from stack
	int arg[5];
	switch(*(int *)(f->esp)){
case SYS_HALT:
	printf("it's me???? halt\n");
	halt();
	break;
case SYS_EXIT:
	printf("it's me???? exit\n");
	get_argument(f->esp, arg, 1);
	exit(*(int *)arg[0]);
	f->eax = arg[0];
	break;
case SYS_EXEC:
	break;
case SYS_WAIT:
	break;
case SYS_CREATE:
	printf("it's me???? create\n");
	get_argument(f->esp, arg, 2); //get argument
	check_address(arg[0]); //check
	f->eax = create(arg[0],arg[1]); // get return
	break;
case SYS_REMOVE:
	printf("it's me???? remove\n");
	get_argument(f->esp, arg, 1);
	check_address(arg[0]); //check
	f->eax = remove(arg[0]);
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
void get_argument(void *esp, int *arg, int count){ //esp for stack pointer, count is number of argument
	esp += 4; //syscall number
	int i;

	check_address(esp);
	check_address(esp+(count*4)); //address checking for security
	for (i=0; i<count; i++){
		arg[i] = (int)(esp+i*4);//esp[i]
	}
}
void check_address(void *addr){ //check address is user's address
	//user address : 0x8048000~0xc0000000
	if(!(0x80480000 < addr && addr < 0xc0000000))
		thread_exit();
	
}

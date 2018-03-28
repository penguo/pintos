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
  shutdown_power_off();
}

void exit(int status){
  printf("%s: exit(%d)\n", thread_name(), status);
  thread_exit();
}

bool create(const char* file, unsigned initial_size){
  return filesys_create(file, initial_size);
}

bool remove(const char* file){
  return filesys_remove(file);
}

void get_argument(void *esp, int *arg, int count)
{
  /* 유저 스택에 저장된 인자값들을 커널에 복사 */
  int i;
  esp += 4;

  /* 인자가 저장된 위치가 유저영역인지 확인한다 */
  check_address(esp);
  check_address(esp+(count*4));

  for (i = 0; i<count; i++){
    esp += i*4;
    arg[i] = (int)esp; // esp[i];
  }
}

void check_address(void *addr)
{
  // TODO 맞는지 확인해보자
  if(!((void *)0x0008048 < addr && addr < (void *)0xc000000)){
    thread_exit();
  }
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
// TODO
  int syscall_nr = (int)f->esp;
  int arg[5]; // 사이즈는 마음대로, 상수값이니 define 하는게 더 좋을듯.*
  switch (syscall_nr){
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      get_argument(f->esp, arg, 1);
      exit(arg[0]);
      f->eax = arg[0];
      break;
    case SYS_CREATE:
      get_argument(f->esp, arg, 2);
      check_address((void*)arg[0]);
      f->eax = create((const char*)arg[0], (unsigned)arg[1]);
      break;
    case SYS_REMOVE:
      get_argument(f->esp, arg, 1);
      check_address((void*)arg[0]);
      f->eax = remove((const char*)arg[0]);
      break;
  }
  thread_exit ();
}

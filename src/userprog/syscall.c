#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);
void check_address(void *addr);
void get_argument(void *esp, int *arg, int count);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
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
  void* esp = f->esp;
  int syscall_nr = (int)esp;
  int arg[5]; // 사이즈는 마음대로, 상수값이니 define 하는게 더 좋을듯.*
  switch (syscall_nr){
    case SYS_HALT:
//      halt();
      break;
    case SYS_EXIT:
      get_argument(esp, arg, 1);
//      f->eax = exit(arg[0]);
      break;
    case SYS_CREATE:
      get_argument(esp, arg, 2);
      check_address((void*)arg[0]);
//      f->eax = create(arg[0], arg[1]);
      break;
    case SYS_REMOVE:
      get_argument(esp, arg, 1);
      check_address((void*)arg[0]);
//      f->eax = remove(arg[0]);
      break;
  }
  thread_exit ();
}

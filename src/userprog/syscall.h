#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"
#include "vm/page.h"

//락 선언
struct lock filesys_lock;
void syscall_init (void);

void exit(int);




#endif /* userprog/syscall.h */

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"
#include "vm/page.h"

//락 선언
struct lock filesys_lock;
void syscall_init (void);

void exit(int);

static void syscall_handler(struct intr_frame *);
struct vm_entry *check_address(void *addr, void *esp);
void check_valid_buffer(void *buffer, unsigned size, void *esp, bool to_write);
void get_argument(void *esp, int *arg, int count);
void halt(void);
void exit(int status);
tid_t exec(const char *cmd_line);
bool create(const char *file, unsigned inital_size);
bool remove(const char *file);
int wait(tid_t pid);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);



#endif /* userprog/syscall.h */

#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "syscall.h"
#include "vm/page.h"


tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

struct thread *get_child_process(int pid);
void remove_child_process(struct thread *cp);
void process_close_file(int fd);
int process_add_file(struct file *f);
struct file *process_get_file(int fd);

//vm
bool handle_mm_fault(struct vm_entry *vme); 



#endif /* userprog/process.h */

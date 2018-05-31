#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/synch.h"
#include <hash.h>

/* States in a thread's life cycle. */
enum thread_status
{
  THREAD_RUNNING, /* Running thread. */
  THREAD_READY,   /* Not running but ready to run. */
  THREAD_BLOCKED, /* Waiting for an event to trigger. */
  THREAD_DYING    /* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t)-1) /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0      /* Lowest priority. */
#define PRI_DEFAULT 31 /* Default priority. */
#define PRI_MAX 63     /* Highest priority. */

/* A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */
struct thread
{
  /* Owned by thread.c. */
  tid_t tid;                 /* Thread identifier. */
  enum thread_status status; /* Thread state. */
  char name[16];             /* Name (for debugging purposes). */
  uint8_t *stack;            /* Saved stack pointer. */
  int priority;              /* Priority. */
  struct list_elem allelem;  /* List element for all threads list. */

  // 프로젝트 알람 클락
  int64_t wakeup_tick;

  //priority donation

  //donation이후 우선순위를 초기화 하기위해 초기값 저장
  int init_priority;

  //해당 스레드가 대기하고있는 lock 자료구조의 주소를 저장
  struct lock *wait_on_lock;

  //multiple donation을 고려하는데 사용
  struct list donations;
  struct list_elem donation_elem;

  /* Shared between thread.c and synch.c. */
  struct list_elem elem; /* List element. */

#ifdef USERPROG
  /* Owned by userprog/process.c. */
  uint32_t *pagedir; /* Page directory. */
#endif

  /* Owned by thread.c. */
  unsigned magic; /* Detects stack overflow. */

  //thread의 가상 메모리 공간을 저장하는 hash table
  struct hash vm;

  //부모 프로세스의 디스크립터
  struct thread *parent;

  //자식 리스트의 element
  struct list_elem child_elem;

  //자식 리스트
  struct list child_list;

  //프로세스 메모리 탑재 유무 flag
  bool loaded;
  bool exited;
  bool waited;

  //exit 세마포어
  struct semaphore exit_sema;

  //load 세마포어
  struct semaphore load_sema;

  //exit 호출시 종료 status 반환값 - 부모가 wait 호출시의 리턴 값
  int exit_status;

  //파일 디스크립터 테이블
  struct file **fdt;

  //다음 차례에 할당될 파일 디스크립터 번호
  int next_fd;

  //프로그램 파일을 가리키는 파일 구조체 포인터
  struct file *exec_file;

  // mmap list
  struct list mmap_list;
};

//실행중인 thread sleep
void thread_sleep(int64_t ticks);

//sleep queue에서 wake
void thread_awake(int64_t ticks);

//최소 tick을 가진 thread update
void update_next_tick_to_awake(int64_t ticks);

//getter of next_tick_to_awake
int64_t get_next_tick_to_awake(void);

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init(void);
void thread_start(void);

void thread_tick(void);
void thread_print_stats(void);

typedef void thread_func(void *aux);
tid_t thread_create(const char *name, int priority, thread_func *, void *);

void thread_block(void);
void thread_unblock(struct thread *);

struct thread *thread_current(void);
tid_t thread_tid(void);
const char *thread_name(void);

void thread_exit(void) NO_RETURN;
void thread_yield(void);

/* Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func(struct thread *t, void *aux);
void thread_foreach(thread_action_func *, void *);

int thread_get_priority(void);
void thread_set_priority(int);

int thread_get_nice(void);
void thread_set_nice(int);
int thread_get_recent_cpu(void);
int thread_get_load_avg(void);

// 실행 중인 스레드를 슬립으로 만듦
void thread_sleep(int64_t ticks);

// 슬립큐에서 깨워야 할 스레드를 깨움
void thread_awake(int64_t ticks);

// 최소 틱을 가진 스레드 저장
void update_next_tick_to_awake(int64_t ticks);

// thread.c의 next_tick_to_awake 반환
int64_t get_next_tick_to_awake(void);

//현재 스레드와 우선순위 비교
void test_max_priority(void);

//두개 항목의 우선순위 비교
bool cmp_priority(const struct list_elem *a,
                  const struct list_elem *b,
                  void *aux UNUSED);

//priority donations
void donate_priority(void);
void remove_with_lock(struct lock *lock);
void refresh_priority(void);

#endif /* threads/thread.h */

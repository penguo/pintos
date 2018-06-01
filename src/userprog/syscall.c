#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include <devices/shutdown.h>
#include <filesys/filesys.h>
#include "userprog/process.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "threads/malloc.h"

#include "vm/page.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"

static void syscall_handler(struct intr_frame *);
struct vm_entry *check_address(void *addr, void *esp);
void check_valid_buffer(void *buffer, unsigned size, void *esp, bool to_write);
void check_valid_string(const void *str, void *esp);
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
int mmap(int fd, void *addr);
void munmap(int mapid);
void do_munmap(struct mmap_file *mmap_file);

void syscall_init(void)
{
	intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");

	//lock 초기화
	lock_init(&filesys_lock);
}

void halt(void)
{
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

bool create(const char *file, unsigned initial_size)
{
	//파일 생성
	lock_acquire(&filesys_lock);
	bool success = filesys_create(file, initial_size);
	lock_release(&filesys_lock);
	return success;
}

bool remove(const char *file)
{
	//파일 제거
	lock_acquire(&filesys_lock);
	bool success = filesys_remove(file);
	lock_release(&filesys_lock);
	return success;
}

//자식 프로세스를 생성하고 프로그램을 실행시키는 시스템 콜
tid_t exec(const char *cmd_line)
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
	if (child->loaded == true)
		return pid;

	//프로그램 로드 실패시 -1 리턴
	else
		return -1;
}

int wait(tid_t pid)
{
	//자식 프로세스가 종료될 때 까지 대기
	return process_wait(pid);
}

int open(const char *file)
{
	lock_acquire(&filesys_lock);

	//파일 open
	struct file *f = filesys_open(file);
	int fd;
	
	//해당 파일이 존재하지 않을 시 -1 리턴
	if (f == NULL)
	{
		lock_release(&filesys_lock);
		return -1;
	}

	//해당 파일 객체에 파일 디스크립터 부여
	fd = process_add_file(f);

	lock_release(&filesys_lock);

	//파일 디스크립터 리턴
	return fd;
}

int filesize(int fd)
{
	lock_acquire(&filesys_lock);
	struct file *f = process_get_file(fd);
	if (!f)
	{
		lock_release(&filesys_lock);
		return -1;
	}
	int size = file_length(f);
	lock_release(&filesys_lock);
	return size;
}

int read(int fd, void *buffer, unsigned size)
{
	//파일 디스크립터를 이용하여 파일 객체 검색
	int i;

	//파일 디스크립터가 0인 경우
	if (fd == 0)
	{
		char *cur_buffer = (char *)buffer;

		//input_getc 함수 이용하여 키보드 데이터 읽음
		for (i = 0; i < size; i++)
		{
			cur_buffer[i] = input_getc();
		}

		//버퍼 크기 리턴
		return size;
	}

	//lock 사용하여 동시 접근 방지
	lock_acquire(&filesys_lock);
	struct file *f = process_get_file(fd);
	int bytes;

	if (f == NULL)
	{
		//널일 경우 lock 해제 후 리턴 -1
		lock_release(&filesys_lock);
		return -1;
	}
	else
	{
		//파일 read
		bytes = file_read(f, buffer, size);

		//lock 해제
		lock_release(&filesys_lock);

		//읽은 바이트 수 리턴
		return bytes;
	}
}

int write(int fd, void *buffer, unsigned size)
{

	//파일 디스크립터가 1인 경우
	if (fd == 1)
	{
		//버퍼에 저장된 값 화면 출력
		putbuf((const char *)buffer, size);

		//버퍼의 크기 리턴
		return size;
	}

	//lock 사용하여 동시 접근 방지
	lock_acquire(&filesys_lock);
	struct file *f = process_get_file(fd);
	int bytes;

	if (f == NULL)
	{
		//널일 경우 lock 해제 후 리턴 -1
		lock_release(&filesys_lock);
		return -1;
	}
	else
	{
		//파일 write
		bytes = file_write(f, buffer, size);

		//락 해제
		lock_release(&filesys_lock);

		//파일에 쓴 바이트 수 리턴
		return bytes;
	}
}

void seek(int fd, unsigned position)
{
	lock_acquire(&filesys_lock);
	struct file *f = process_get_file(fd);

	if (f == NULL)
	{
		lock_release(&filesys_lock);
		return;
	}
	//해당 열린 파일의 위치를 position만큼 이동
	file_seek(f, position);
	lock_release(&filesys_lock);
}

unsigned tell(int fd)
{
	lock_acquire(&filesys_lock);
	struct file *f = process_get_file(fd);
	if (!f)
	{
		lock_release(&filesys_lock);
		return -1;
	}
	off_t offset = file_tell(f);
	lock_release(&filesys_lock);
	return offset;
}

void close(int fd)
{
	//해당 파일 디스크립터에 해당하는 파일을 닫고
	//파일 디스크립터 엔트리 초기화
	lock_acquire(&filesys_lock);
	process_close_file(fd);
	lock_release(&filesys_lock);
}

static void
syscall_handler(struct intr_frame *f)
{
	//system call's argument loading from stack
	int *h_esp = f->esp;
	int syscall_num = *h_esp;
	int arg[5];
	//	printf("\nsyscall number : %d\n", syscall_num);

	check_address(h_esp, h_esp);

	switch (syscall_num)
	{
	case SYS_HALT: // 0
		halt();
		break;

	case SYS_EXIT: // 1
		get_argument(h_esp, arg, 1);
		exit(arg[0]);
		f->eax = arg[0];
		break;

	case SYS_EXEC: // 2
		get_argument(h_esp, arg, 1);
		check_valid_string((const void *)arg[0], h_esp); //check
		f->eax = exec(arg[0]);							 //return tid_t
		break;

	case SYS_WAIT: // 3
		get_argument(h_esp, arg, 1);
		f->eax = wait(arg[0]); //return int
		break;

	case SYS_CREATE:											 // 4
		get_argument(h_esp, arg, 2);							 //get argument
		check_valid_string((const void *)arg[0], h_esp);		 //check
		f->eax = create((const char *)arg[0], (unsigned)arg[1]); //get return
		break;

	case SYS_REMOVE: // 5
		get_argument(h_esp, arg, 1);
		check_valid_string((const void *)arg[0], h_esp); //check
		f->eax = remove((const void *)arg[0]);
		break;

	case SYS_OPEN: // 6
		get_argument(h_esp, arg, 1);
		check_valid_string((const void *)arg[0], h_esp);
		f->eax = open(arg[0]);
		break;

	case SYS_FILESIZE: // 7
		get_argument(h_esp, arg, 1);
		f->eax = filesize(arg[0]);
		break;

	case SYS_READ: // 8
		get_argument(h_esp, arg, 3);
		check_valid_buffer((void *)arg[1], (unsigned)arg[2], h_esp, true);
		f->eax = read(arg[0], (const void *)arg[1], (unsigned)arg[2]);
		break;

	case SYS_WRITE: // 9
		get_argument(h_esp, arg, 3);
		check_valid_buffer((void *)arg[1], (unsigned)arg[2], h_esp, false);
		f->eax = write(arg[0], (const void *)arg[1], (unsigned)arg[2]);
		break;

	case SYS_SEEK: // 10
		get_argument(h_esp, arg, 2);
		seek(arg[0], (unsigned)arg[1]);
		break;

	case SYS_TELL: // 11
		get_argument(h_esp, arg, 1);
		f->eax = tell(arg[0]);
		break;

	case SYS_CLOSE: // 12
		get_argument(h_esp, arg, 1);
		close(arg[0]);
		break;

	case SYS_MMAP:
		get_argument(h_esp, arg, 2);
		f->eax = mmap(arg[0], (void *)arg[1]);
		break;

	case SYS_MUNMAP:
		get_argument(h_esp, arg, 1);
		munmap(arg[0]);
		break;

	default:
		printf("default\n");
	}
}

void get_argument(void *esp, int *arg, int count)
{ //esp for stack pointer, count is number of argument
	int i;
	int *ptr;

	for (i = 0; i < count; i++)
	{
		//esp 다음 자리에 arg[i] 배정
		ptr = (int *)esp + i + 1;
		//ptr이 커널 영역을 침입하지 않는지 체크
		check_address(ptr, esp);
		arg[i] = *ptr;
	}
}

struct vm_entry *check_address(void *addr, void *esp)
{
	//check address is user's address
	//user address : 0x08048000~0xc0000000
	// if (!((void *)0x08048000 < addr && addr < (void *)0xc0000000))
	if (addr < (void *)0x08048000 || addr >= (void *)0xc0000000)
		exit(-1);

	struct vm_entry *vme = find_vme(addr);
	return vme;
}

void check_valid_buffer(void *buffer, unsigned size, void *esp, bool to_write)
{
	int i;
	struct vm_entry *vme;
	char *l_buffer = (char *)buffer;

	for (i = 0; i < size; i++)
	{
		//주소 유저영역 여부 검사와 vm_entry 획득
		vme = check_address((void *)l_buffer, esp);

		//해당 주소에 대한 vm_entry존재 여부와 vm_entry의 writable멤버가 true인지 검사
		if ((vme != NULL) && to_write)
			if (!vme->writable)
				exit(-1);
		l_buffer++;
	}
}

void check_valid_string(const void *str, void *esp)
{
	//str에 대한 vm_entry 존재 여부 확인
	struct vm_entry *vme = check_address(str, esp);

	while (*(char *)str != 0)
	{
		if (vme == NULL)
		{
			exit(-1);
		}
		str = (char *)str + 1;
		vme = check_address(str, esp);
	}
}

/* mmap
	fd: 프로세스의 가상 주소공간에 매핑할 파일
	addr: 매핑을 시작할 주소(page 단위 정렬)
	성공 시 mapping id를 리턴, 실패 시 에러코드(-1) 리턴
	요구페이징에 의해 파일 데이터를 메모리로 로드
	*/
int mmap(int fd, void *addr)
{
	struct mmap_file *m_file;
	struct file *f, *rf;
	off_t ofs = 0;
	static int map_id = 0;

	f = process_get_file(fd);

	if (f == NULL || !is_user_vaddr(addr) || addr <= 0 || (int)addr % PGSIZE != 0)
	{
		return -1; // 이상한 인자
	}

	rf = file_reopen(f);

	if (!rf || file_length(rf) == 0)
	{
		return -1;
	}

	//mmap구조체 생성
	m_file = (struct mmap_file *)malloc(sizeof(struct mmap_file));
	if (m_file == NULL)
	{
		return -1;
	}
	//mmap 구조체 초기화
	list_init(&m_file->vme_list);
	m_file->mapid = ++map_id;
	m_file->file = rf;

	uint32_t read_bytes = file_length(rf);

	while (read_bytes > 0)
	{
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		// 이미 존재한다면 에러
		if (find_vme(addr))
		{
			return -1;
		}
		struct vm_entry *vme = malloc(sizeof(struct vm_entry));

		if (!vme)
			return -1;

		// vme 초기화;
		vme->type = VM_FILE;
		vme->vaddr = addr;
		vme->writable = true;
		vme->is_loaded = false;
		vme->file = rf;
		vme->offset = ofs;
		vme->read_bytes = page_read_bytes;
		vme->zero_bytes = page_zero_bytes;

		list_push_back(&m_file->vme_list, &vme->mmap_elem);
		// hash vm에 삽입
		insert_vme(&thread_current()->vm, vme);

		read_bytes -= page_read_bytes;
		ofs += page_read_bytes;
		addr += PGSIZE;
	}
	list_push_back(&thread_current()->mmap_list, &m_file->elem);
	return m_file->mapid;
}

void munmap(int mapping)
{
	struct thread *t = thread_current();
	struct list_elem *e = list_begin(&t->mmap_list);
	struct list_elem *next_elem;

	//mmap_list에서 해제할 mmap_file 검색
	while (e != list_end(&t->mmap_list))
	{
		struct mmap_file *m_file = list_entry(e, struct mmap_file, elem);
		next_elem = list_next(e);

		//mmap_list내에서 mapping에 해당하는 mapid를 갖는 모든 vm_entry을 해제
		//인자로 넘겨진 mapping값이 CLOSE_ALL인경우 모든 파일매핑을 제거
		//매핑 제거 시 do_munmap()함수호출
		if (m_file->mapid == mapping || mapping == CLOSE_ALL)
		{
			do_munmap(m_file);
			list_remove(&m_file->elem);
			free(m_file);
			if (mapping != CLOSE_ALL)
				break;
		}
		e = next_elem;
	}
}

// 매핑 제거
void do_munmap(struct mmap_file *mmap_file)
{
	struct thread *t = thread_current();
	struct list_elem *next_elem;
	struct list_elem *e = list_begin(&mmap_file->vme_list);
	struct file *f = mmap_file->file;
	//vme list 순회

	while (e != list_end(&mmap_file->vme_list))
	{
		next_elem = list_next(e);
		struct vm_entry *vme = list_entry(e, struct vm_entry, mmap_elem);

		//vm_entry가 물리 페이지와 load되어 있다면
		if (vme->is_loaded)
		{
			//dirty bit 검사 pagedir.c
			if (pagedir_is_dirty(t->pagedir, vme->vaddr))
			{
				//lock
				lock_acquire(&filesys_lock);
				//file write
				file_write_at(vme->file, vme->vaddr, vme->read_bytes, vme->offset);
				lock_release(&filesys_lock);
			}

			// pagedir_get_page(t->pagedir, vme->vaddr);
			palloc_free_page(pagedir_get_page(t->pagedir, vme->vaddr));
			//page clear
			pagedir_clear_page(t->pagedir, vme->vaddr);
		}

		//mmap_list에서 제거
		list_remove(&vme->mmap_elem);
		delete_vme(&t->vm, vme);

		free(vme);

		e = next_elem;
	}
	//file close 처리
	/*	if(f)
	{
		lock_acquire(&filesys_lock);
		file_close(f);
		lock_release(&filesys_lock);

	}*/
}

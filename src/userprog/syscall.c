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
	return filesys_create(file, initial_size);
}

bool remove(const char *file)
{
	//파일 제거
	return filesys_remove(file);
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
	//파일 open
	struct file *f = filesys_open(file);
	int fd;

	//해당 파일이 존재하지 않을 시 -1 리턴
	if (f == NULL)
		return -1;

	//해당 파일 객체에 파일 디스크립터 부여
	fd = process_add_file(f);

	//파일 디스크립터 리턴
	return fd;
}

int filesize(int fd)
{
	struct file *f = process_get_file(fd);

	if (!f)
		return -1;

	return file_length(f);
}

int read(int fd, void *buffer, unsigned size)
{

	//파일 디스크립터를 이용하여 파일 객체 검색
	struct file *f = process_get_file(fd);
	int i;

	//파일 디스크립터가 1인 경우
	if (fd == 1)
		return -1;

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

	if (f == NULL)
	{
		//널일 경우 lock 해제 후 리턴 0
		lock_release(&filesys_lock);
		return 0;
	}
	else
	{
		//파일 read
		size = file_read(f, buffer, size);

		//lock 해제
		lock_release(&filesys_lock);

		//읽은 바이트 수 리턴
		return size;
	}
}

int write(int fd, void *buffer, unsigned size)
{

	struct file *f = process_get_file(fd);

	//파일 디스크립터가 0인 경우
	if (fd == 0)
		return -1;

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

	if (f == NULL)
	{
		//널일 경우 lock 해제 후 리턴 0
		lock_release(&filesys_lock);
		return 0;
	}
	else
	{
		//파일 write
		size = file_write(f, buffer, size);

		//락 해제
		lock_release(&filesys_lock);

		//파일에 쓴 바이트 수 리턴
		return size;
	}
}

void seek(int fd, unsigned position)
{
	struct file *f = process_get_file(fd);

	if (f == NULL)
		return;
	//해당 열린 파일의 위치를 position만큼 이동
	file_seek(f, position);
}

unsigned
tell(int fd)
{
	struct file *f = process_get_file(fd);

	if (f == NULL)
		return;
	//해당 열린 파일의 위치를 반환
	return file_tell(f);
}

void close(int fd)
{
	//해당 파일 디스크립터에 해당하는 파일을 닫고
	//파일 디스크립터 엔트리 초기화
	process_close_file(fd);
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
		//check_valid_string((const void *)arg[0], h_esp);		 //check
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
		f->eax = mmap(arg[0], (void *) arg[1]);
		break;

	case SYS_MUNMAP:
		get_argument(h_esp,arg, 1);
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
	if (!vme)
		exit(-1);
	else
	{
		return vme;
	}
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
	struct file *f = process_get_file(fd);
	struct file *rf;
	struct mmap_file *mf;
	static int mapid = 0;
	//TODO error 뜸
	if (!f || !addr || ((int)addr % 4096 == 0) || (int)addr < 0x0804800)
	{
		return -1;
	}
	rf = file_reopen(f);
	mf = (struct mmap_file *)malloc(sizeof(struct mmap_file));
	mf->mapid = mapid++;
	mf->file = rf;

	// load_segment에서 한 것처럼
	off_t ofs = 0;
	uint32_t read_bytes = file_length(rf);

	while (read_bytes > 0)
	{
			size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		  size_t page_zero_bytes = PGSIZE - page_read_bytes;

			struct vm_entry *vme = (struct vm_entry *)malloc(sizeof(struct vm_entry));
		
			if(!vme)
				return -1;

		// vme 내용들 초기화;
        vme->type = VM_FILE;
        vme->vaddr = addr;
        vme->writable = true;
        vme->is_loaded = false;
				vme->file = rf;
				vme->offset = ofs;
				vme->read_bytes = page_read_bytes;
				vme->zero_bytes = page_zero_bytes;

        list_push_back(&mf->vme_list, &vme->mmap_elem);
        // hash vm에 삽입
        insert_vme(&thread_current()->vm, vme);
            
        read_bytes -= page_read_bytes;
        ofs += page_read_bytes;
        addr += PGSIZE;
	}
    list_push_back(&thread_current()->mmap_list, &mf->elem);
	return mf->mapid;
}

void munmap(int mapid)
{
	struct thread *t = thread_current();
	struct list_elem *next;
	struct list_elem *e = list_begin(&t->mmap_list);

	//mmap_list 순회
	while(e != list_end(&t->mmap_list))
	{
		next = list_next(e);
		struct mmap_file *m = list_entry(e, struct mmap_file, elem);
		//mmap 내부의 vme list
			//mapid가 같은 경우 vm_entry 해제
		if(m->mapid == mapid)
		{
			do_munmap(m);
			list_remove(&m->elem);
			free(m);
		}
		e = next;
	}

}

void do_munmap(struct mmap_file* mmap_file)
{
	struct thread *t = thread_current();
	struct list_elem *vme_next;
	struct list_elem *e = list_begin(&mmap_file->vme_list);
	//vme list 순회
	while(e != list_end(&mmap_file->vme_list))
	{
		struct vm_entry *vme = list_entry(e, struct vm_entry, mmap_elem);

		//vm_entry가 물리 페이지와 load되어 있다면
		if(vme->is_loaded)
		{
			//dirty bit 검사 pagedir.c
			if(pagedir_is_dirty(t->pagedir, vme->vaddr))
			{
				//lock
				lock_acquire(&filesys_lock);
				//file write
				file_write_at(vme->file,vme->vaddr,vme->read_bytes, vme->offset);
				lock_release(&filesys_lock);
			}
	
	// pagedir_get_page(t->pagedir, vme->vaddr);
		palloc_free_page(pagedir_get_page(t->pagedir, vme->vaddr));
		//page clear
		pagedir_clear_page(t->pagedir, vme->vaddr);
	
	
	//mmap_list에서 제거
		list_remove(&vme->mmap_elem);
		delete_vme(&t->vm, vme);
	
	//file close 처리
		if(mmap_file->mapid != 0)
		{
			if(mmap_file->file)
			{
				lock_acquire(&filesys_lock);
				file_close(mmap_file->file);
				lock_release(&filesys_lock);
			}
		}
		//vme와 mmap을 할당 해제
		free(vme);
		free(mmap_file);
	}
		e = vme_next;
	}
}

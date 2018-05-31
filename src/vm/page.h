#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include <list.h>
#include <threads/synch.h>

#define VM_BIN 0  /*binary file - elf format*/
#define VM_FILE 1 /*ordinary file*/
#define VM_ANON 2 /*anonymous erea - swapping erea*/

struct vm_entry
{
	uint8_t type;   /* VM_BIN, VM_FILE, VM_ANON의 타입 */
	void *vaddr;	/* vm_entry의 가상페이지 번호 */
	bool writable;  /* True일 경우 해당 주소에 write 가능		 False일 경우 해당 주소에 write 불가능 */
	bool is_loaded; /* 물리메모리의 탑재 여부를 알려주는 플래그 */
	bool pinned;
  
	struct file *file; /* 가상주소와 맵핑된 파일 */

	struct list_elem mmap_elem; /* mmap 리스트 element */

	size_t offset;	 /* 읽어야 할 파일 오프셋 */
	size_t read_bytes; /* 가상페이지에 쓰여져 있는 데이터 크기 */
	size_t zero_bytes; /* 0으로 채울 남은 페이지의 바이트 */

	size_t swap_slot; /* 스왑 슬롯 */

	struct hash_elem elem; /* 해시 테이블 Element */
};

struct page
{
	void *kaddr;
	struct vm_entry *vme;
	struct thread *thread;
	struct list_elem lru;
};

bool install_page(void *upage, void *kpage, bool writable);

void vm_init(struct hash *vm);

// mmap 381p
struct mmap_file
{
	int mapid;
	struct file* file;
	struct list_elem elem;
	struct list vme_list;
};

static unsigned vm_hash_func(const struct hash_elem *e, void *aux);
static bool vm_less_func(const struct hash_elem *a, const struct hash_elem *b);
/*TODO 314p*/

bool insert_vme(struct hash *vm, struct vm_entry *vme);
bool delete_vme(struct hash *vm, struct vm_entry *vme);

struct vm_entry *find_vme(void *vaddr);

void vm_destroy(struct hash *vm);

bool handle_mm_fault(struct vm_entry *vme);

bool load_file(void *kaddr, struct vm_entry *vme);

#endif/* vm/page.h */

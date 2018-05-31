#include "filesys/file.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "vm/page.h"

#include <hash.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>


//vm pagenumber hashing
static unsigned vm_hash_func(const struct hash_elem *e, void *aux UNUSED)
{
	// hash_entry로 element에 대한 vm_entry 구조체 검색
	struct vm_entry *vme = hash_entry(e, struct vm_entry, elem);

	//hash_int()를 이용해서 vm_entry의 멤버 vaddr에 대한 해시값을 구하고 반환
	return hash_int((int)vme->vaddr);
}

//compare vm entry pagenumber
static bool vm_less_func(const struct hash_elem *a, const struct hash_elem *b)
{

	struct vm_entry *vmea = hash_entry(a, struct vm_entry, elem);
	struct vm_entry *vmeb = hash_entry(b, struct vm_entry, elem);

	// b가 크다면 true, a가 크다면 false
	if (vmea->vaddr < vmeb->vaddr)
		return true;
	else
		return false;
}


static void vm_destroy_func(struct hash_elem *e, void *aux)
{
   struct vm_entry *vme;
 
   //hash의 element 획득
   vme = hash_entry(e, struct vm_entry, elem);
	
	//load가 되어있는 page의 vm_entry인경우
	if(vme->is_loaded){
      //페이지 할당& 매핑 해제
     palloc_free_page(pagedir_get_page(thread_current()->pagedir,     vme->vaddr));
     pagedir_clear_page(thread_current()->pagedir, vme->vaddr);
   }
   //vm_entry 객체 할당 해제
   free(vme); 
}

//insert entry
bool insert_vme(struct hash *vm, struct vm_entry *vme)
{
	struct hash_elem *h_elem;

	h_elem = hash_insert(vm, &vme->elem);

	if(!h_elem)
		return true;
	
	return false;
}

//delete entry
bool delete_vme(struct hash *vm, struct vm_entry *vme)
{
	struct hash_elem *h_elem;

	h_elem = hash_delete(vm, &vme->elem);
	
	if(!h_elem){
		return false;
	}
	return true;
}

/*TODO 318p 가상 주소공간 초기화에서 활용*/

struct vm_entry *find_vme(void *vaddr)
{
	struct hash_elem *h_elem;
	struct vm_entry vme;
	
	// vaddr의 페이지 번호를 얻음
	vme.vaddr = pg_round_down(vaddr);
	// hash_elem 구조체 얻음
	//struct hash_elem *hash_find (struct hash *, struct hash_elem *);
	h_elem = hash_find(&thread_current()->vm, &vme.elem);
	
	if(!h_elem){ // 존재하지 않는다면 NULL 리턴
	//	printf("h_elem ==NULL \n");
//		printf("vm/page.c - find_vme error\n");
		return NULL;
	}
	
	return hash_entry(h_elem, struct vm_entry, elem);
}

void vm_destroy(struct hash *vm)
{
	hash_destroy(vm, vm_destroy_func);
}

void vm_init(struct hash  *vm)
{
	hash_init(vm, vm_hash_func, vm_less_func, NULL);
}

//ppt 349p after success allocateing phy-memory, load
bool load_file(void *kaddr, struct vm_entry *vme)
{
	/*Using file_read_at()*/
	// file_read_at으로 물리페이지에read_bytes만큼 데이터를 쓰고
	// file_read_at 여부 반환

	if(vme->read_bytes >0)
	{
		lock_acquire(&filesys_lock);
		if((int)vme->read_bytes != file_read_at(vme->file, kaddr, vme->read_bytes, vme->offset))
		{		
			lock_release(&filesys_lock);
			return false;
		}
		lock_release(&filesys_lock);
		memset(kaddr+vme->read_bytes,0,vme->zero_bytes);
	
	}
	
	/* zero_bytes만큼 남는 부분을‘0’으로 패딩*/
	else
	{
		memset(kaddr,0,PGSIZE);
	}

	/*정상적으로 file을 메모리에 loading 하면 true 리턴*/
	return true;
}



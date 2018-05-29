#include "vm/page.h"
#include "threads/thread.h"
#include "filesys/file.h"
#include "userprog/process.h"
#include <hash.h>
#include <string.h>
#include <stdio.h>

//hash table initialize
void vm_init(struct hash *vm)
{
	// 해시테이블 초기화
	hash_init(vm, vm_hash_func, vm_less_func, NULL);
}

//vm pagenumber hashing
static unsigned vm_hash_func(const struct hash_elem *e, void *aux)
{
	// hash_entry로 element에 대한 vm_entry 구조체 검색
	struct vm_entry *vme = hash_entry(e, struct vm_entry, elem);

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

//insert entry
bool insert_vme(struct hash *vm, struct vm_entry *vme)
{
	struct hash_elem *h_elem;

	h_elem = hash_insert(vm, &vme->elem);

	if(h_elem != NULL){
		return false;
	}
	return true;
}

//delete entry
bool delete_vme(struct hash *vm, struct vm_entry *vme)
{
	struct hash_elem *h_elem;

	h_elem = hash_delete(vm, &vme->elem);
	
	if(h_elem == NULL){
		return false;
	}
	return true;
}

/*TODO 318p 가상 주소공간 초기화에서 활용*/

struct vm_entry *find_vme(void *vaddr)
{
	void *page_num;
	struct hash_elem *h_elem;
	struct vm_entry *vme;

	// vaddr의 페이지 번호를 얻음
	page_num = pg_round_down(vaddr);

	// hash_elem 구조체 얻음
	//struct hash_elem *hash_find (struct hash *, struct hash_elem *);
	vme->vaddr = page_num;
	h_elem = hash_find(&thread->current()->vm, &vme->elem);

	if(h_elem == NULL){ // 존재하지 않는다면 NULL 리턴
		return NULL
	}
	return hash_entry(h_elem, struct vm_entry, elem);
}
/*TODO 320p 요구 페이징 구현에서 활용*/

void vm_destroy(struct hash *vm)
{
	hash_destroy(vm, &vm_destroy_func);
	return;
}

void vm_destroy_func(struct hash_elem *e, void *aux)
{
	struct vm_entry *vme;

	vme = hash_entry(e, struct vm_entry, elem);

	if(vme->is_loaded){
		palloc_free_page(pagedir_get_page(thread_current()->pagedir, vme->vaddr));
		pagedir_clear_page(thread_current()->pagedir, vme->vaddr);
	}
	free(vme);
	return;
}

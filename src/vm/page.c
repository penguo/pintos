#include "vm/page.h"
#include "threads/thread.h"
#include "filesys/file.h"
#include "userprog/process.h"
#include <hash.h>
#include <string.h>
#include <stdio.h>



//hash table initialize
void vm_init (struct hash *vm){
	
	hash_init(vm, vm_hash_func, vm_less_func, NULL);
}

//vm pagenumber hashing
static unsigned vm_hash_func (const struct hash_elem *e,void *aux){
	
	struct vm_entry *vme = hash_entry(e, struct vm_entry, elem);

	return hash_int((int)vme->vaddr);
}

//compare vm entry pagenumber
static bool vm_less_func (const struct hash_elem *a, const struct hash_elem *b){

	struct vm_entry *vmea = hash_entry(a, struct vm_entry ,elem);
	struct vm_entry *vmeb = hash_entry(b, struct vm_entry, elem);

	if(vmea->vaddr < vmeb ->addr)
		return true;
	else	
		return false;
}


//insert entry 
bool insert_vme (struct hash *vm, struct vm_entry *vme){
	return false;
}


//delete entry
bool delete_vme (struct hash *vm, struct vm_entry *vme){
	return false;
}

/*TODO 317p 가상 주소공간 초기화에서 활용*/

struct vm_entry *find_vme (void *vaddr){
	return NULL;
}
/*TODO 319p 요구 페이징 구현에서 활용*/

void vm_destroy (struct hash *vm){
	return;
}
void vm_destroy_func (struct hash_elem *e, void *aux){
	return;
}


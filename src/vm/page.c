#include "vm/page.h"
#include "threads/thread.h"
#include "filesys/file.h"
#include "userprog/process.h"
#include <hash.h>
#include <string.h>
#include <stdio.h>




void vm_init (struct hash *vm){
	return;
}
static unsigned vm_hash_func (const struct hash_elem *e,void *aux){
	return;
}
static bool vm_less_func (const struct hash_elem *a, const struct hash_elem *b){
	return false;
}
/*TODO 314p*/

bool insert_vme (struct hash *vm, struct vm_entry *vme){
	return false;
}
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


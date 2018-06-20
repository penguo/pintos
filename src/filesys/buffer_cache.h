nclude "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/synch.h"

//buffer cache entry 를 관리
struct buffer_head{
	int dirty; //dirty
	int used; //is used?
	block_sector_t address; //disk sector 주소
	int clock; //clock 알고리즘
	struct lock l;//lock
	void *buffer;
}

#include "filesys/buffer_cache.h"
#include "threads/palloc.h"
#include <string.h>

//buffer cache entry의 개수 32kb = (64*512byte)
#define BUFFER_CACHE_ENTRY_NB 64

//buffer cache 메모리 영역
static char *p_buffer_cache;

//buffer_head 배열
static struct buffer_head buffer_head[BUFFER_CACHE_ENTRY_NB];

//clock 알고리즘을 위해
static struct buffer_head *clock_hand;

void bc_init (void){
	int i;
	struct buffer_head *head;
	void *cache = p_buffer_cache;
	//buffer_head init
	for(i = 0; i<BUFFER_CACHE_ENTRY_NB; i++){
		head = buffer_head[i];
		//cache size
		cache += BLOCK_SECTOR_SIZE;
		memset(head, 0, sizeof(buffer_head));
		lock_init(&head->lock);
		head->buffer = buffer;
	}
	clock_hand = buffer_head;

}



//buffer 단위로 read
bool bc_read (block_sector_t sector_idx, void *buffer, off_t bytes_read, int chunk_size, int sector_ofs){
	struct buffer_head *head;
	//bc_lookup으로 캐싱이 되지 않음을 확인
	if(!(head = bc_lookup(sector_idx))){
		//clock알고리즘을 통해 victim entry를 구함 
		head = bc_select_victim();
		//buffer cache 데이터를 디스크로 flush
		bc_flush_entry(head);
		//사용중이므로 used=1 변경되지 않았으므로 dirty=0
		head->used = 1;
		head->dirty = 0;
		head->address = sector_idx;
		block_read(fs_device, sector_idx, head->buffer);
	}
	head->clock = 1;
	//user buffer의 offset에  
	memcpy(buffer + bytes_read, head->buffer + sector_ofs,chunk_size);
	lock_release(&head->lock);
	return true;
}
//TODO 472p까지 밑으로는 앞으로 구현할 함수


//buffer 단위로 write
bool bc_write (block_sector_t sector_idx, void *buffer, off_t	bytes_written, int chunk_size, int sector_ofs){
	return true;
}

void bc_term(void){

}

struct buffer_head* bc_select_victim(void){
return NULL;
}

//block 캐싱 여부 검사
struct buffer_head* bc_lookup (block_sector_t sector){
	int i;
	struct buffer_head *head;
	for(i = 0; i<BUFFER_CACHE_ENTRY_NB; i++){
		head = buffer_head[i];
		//head가 사용중이고 sector 주소가 같을 경우
		if(head->used && head->address == sector){
			//data 접근 시 lock획득
			lock_aquire(&head->lock);
			return head;
		}
	}
	return NULL;
}

void bc_flush_entry (struct buffer_head *p_flush_entry){
}

void bc_flush_all_entries (void){
}

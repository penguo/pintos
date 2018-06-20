#include "filesys/buffer_cache.h"
#include "threads/palloc.h"
#include <string.h>
#include <debug.h>

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
		head = buffer_head+i;
		//cache size
		cache += BLOCK_SECTOR_SIZE;
		memset(head, 0, sizeof(buffer_head));
		lock_init(&head->l);
		head->buffer = cache;
	}
	//clock_hand의 초기값은 head
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
	lock_release(&head->l);
	return true;
}


//buffer 단위로 write
bool bc_write (block_sector_t sector_idx, void *buffer, off_t bytes_read, int chunk_size, int sector_ofs){
	bool success = false;
	struct buffer_head *head;
	//bc_lookup으로 캐싱이 되지 않음을 확인
	if(!(head = bc_lookup(sector_idx))){
		//clock알고리즘을 통해 victim entry를 구함 
		head = bc_select_victim();
		//buffer cache 데이터를 디스크로 flush
		bc_flush_entry(head);
		//사용중이므로 used=1
		head->used = 1;
		head->address = sector_idx;
		block_read(fs_device, sector_idx, head->buffer);
	}
	head->clock = 1;
	//write되면 dirty되므로
	head->dirty = 1;
	//buffer에서 읽기
	memcpy(head->buffer + sector_ofs, buffer + bytes_read, chunk_size);
	lock_release(&head->l);
	success = true;
	return success;
}

void bc_term(void){
	bc_flush_all_entries();
	//buffer_cache 영역 할당 해제
	free(p_buffer_cache);

}

struct buffer_head* bc_select_victim(void){
	while(1){
		for(; clock_hand != buffer_head + BUFFER_CACHE_ENTRY_NB; clock_hand++){
			lock_acquire(&clock_hand->l);
			//사용중이 아니거나 이미 참조한 경우 victim
			if(!clock_hand->used || !clock_hand->clock)
				return clock_hand++;
			bc_flush_entry(clock_hand);
			//참조를 완료했으므로 clock=0
			clock_hand->clock = 0;
			lock_release(&clock_hand->l);
		}
		//끝에 도달했을 때 처음으로 돌아가 앞부분 검사
		clock_hand = buffer_head;
	}
return NULL;
}

//block 캐싱 여부 검사
struct buffer_head* bc_lookup (block_sector_t sector){
	int i;
	struct buffer_head *head;
	for(i = 0; i<BUFFER_CACHE_ENTRY_NB; i++){
		head = buffer_head+i;
		//head가 사용중이고 sector 주소가 같을 경우
		if(head->used && head->address == sector){
			//data 접근 시 lock획득 - read or write가 끝날 때까지
			lock_acquire(&head->l);
			return head;
		}
	}
	return NULL;
}

void bc_flush_entry (struct buffer_head *p_flush_entry){
	if(!p_flush_entry->used || !p_flush_entry->dirty)
		return;
	//entry가 사용중이고 더러울 때 깨끗하게 하면서 block_write로 disk 쓰기
	p_flush_entry->dirty = 0;
	block_write(fs_device, p_flush_entry->address, p_flush_entry->buffer);
}

void bc_flush_all_entries (void){
	int i;
	struct buffer_head *head;
	for(i = 0; i<BUFFER_CACHE_ENTRY_NB; i++){
		head = buffer_head+i;
		//dirty 한 사용중인 모든 엔트리를 실제로 쓰고 깨끗하게 함
		lock_acquire(&head->l);
		bc_flush_entry(head);
		lock_release(&head->l);
	}
}


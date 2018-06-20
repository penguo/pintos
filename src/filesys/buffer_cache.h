#include "filesys/filesys.h"
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
};


void bc_init(void);

bool bc_read (block_sector_t sector_idx, void *buffer, off_t bytes_read, int chunk_size, int sector_ofs);

bool bc_write (block_sector_t sector_idx, void *buffer, off_t	bytes_written, int chunk_size, int sector_ofs);

void bc_term(void);

struct buffer_head* bc_select_victim(void);

struct buffer_head* bc_lookup (block_sector_t sector);

void bc_flush_entry (struct buffer_head *p_flush_entry);

void bc_flush_all_entries (void);

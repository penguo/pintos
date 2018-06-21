#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "filesys/buffer_cache.h"
#include <stdio.h>
#include <string.h>
#include "threads/malloc.h"

struct buffer_head buffer_head[BUFFER_CACHE_ENTRY_NB];
//buffer 영역
void *p_buffer_cache;

//clock algorithm을 구현하기 위한 buffer_head
static int clock_hand;

//buffer cache 초기화
void bc_init(void)
{

  int i;
  void *buf_data;

  // 버퍼 할당
  p_buffer_cache = malloc(BLOCK_SECTOR_SIZE * BUFFER_CACHE_ENTRY_NB);
  if (p_buffer_cache == NULL)
  {
    printf("Memory Allocation Fail.\n");
    return;
  }
  else
  {
    buf_data = p_buffer_cache;
  }

  // 버퍼 초기화
  for (i = 0; i < BUFFER_CACHE_ENTRY_NB; i++)
  {
    buffer_head[i].dirty = false;
    buffer_head[i].sector = -1;
    buffer_head[i].clock_bit = 0;
    buffer_head[i].used = false;

    lock_init(&buffer_head[i].lock);
    buffer_head[i].data = buf_data;

    buf_data = buf_data + BLOCK_SECTOR_SIZE;
  }
}

void bc_term(void)
{
  // 버퍼를 종료하기 전 마지막으로 모든 엔트리를 flush
  bc_flush_all_entries();
  //버퍼 할당 해제
  free(p_buffer_cache);
}

bool bc_read(block_sector_t sector_i, void *buffer, off_t buffer_ofs, int chunk_size, int sector_ofs)
{
  struct buffer_head *head;

  head = bc_lookup(sector_i);

  if (!head)
  {
    head = bc_select_victim();
    if (!head)
    {
      return false;
    }
    lock_acquire(&head->lock);
    block_read(fs_device, sector_i, head->data);

    //버퍼 헤드 업데이트 - 읽을 뿐이므로 not dirty 사용중이므로 not used
    head->dirty = false;
    head->used = true;
    head->sector = sector_i;
    lock_release(&head->lock);
  }
  lock_acquire(&head->lock);
  //buffer에서 읽어들이기
  memcpy(buffer + buffer_ofs, head->data + sector_ofs, chunk_size);
  //참조하였으므로 clock_bit true
  head->clock_bit = true;
  lock_release(&head->lock);

  return true;
}

bool bc_write(block_sector_t sector_i, void *buffer, off_t buffer_ofs, int chunk_size, int sector_ofs)
{

  bool success = false;
  struct buffer_head *head;

  head = bc_lookup(sector_i);

  if (head == NULL)
  {
    head = bc_select_victim();
    if (head == NULL)
    {
      return success;
    }
    block_read(fs_device, sector_i, head->data);
  }

  lock_acquire(&head->lock);
  //버퍼에서 쓰기
  memcpy(head->data + sector_ofs, buffer + buffer_ofs, chunk_size);

  //버퍼 헤드 업데이트 - 새로 썼으므로 dirty
  head->dirty = true;
  head->used = true;
  head->sector = sector_i;
  head->clock_bit = true;
  lock_release(&head->lock);

  success = true;
  return success;
}

//버퍼 캐시 데이터를 disk로 flush
void bc_flush_entry(struct buffer_head *p_flush_entry)
{
  lock_acquire(&p_flush_entry->lock);
  block_write(fs_device, p_flush_entry->sector, p_flush_entry->data);
  p_flush_entry->dirty = false;
  lock_release(&p_flush_entry->lock);
}

//buffer_head에 있는 모든 dirty한 entry를 flush
void bc_flush_all_entries(void)
{
  int i;

  for (i = 0; i < BUFFER_CACHE_ENTRY_NB; i++)
  {
    if (buffer_head[i].dirty == true)
      bc_flush_entry(&buffer_head[i]);
  }
}

//clock algorithm을 통해 flush될 buffer cache entry를 선택
struct buffer_head *bc_select_victim(void)
{
  int i;

  while (1)
  {
    i = clock_hand;

    if (i == BUFFER_CACHE_ENTRY_NB)
      i = 0;
    //clock_hand는 i보다 하나 뒤 - 끝에 닿으면 처음으로
    if (++clock_hand == BUFFER_CACHE_ENTRY_NB)
      clock_hand = 0;
    //clock_bit가 1이면 참조 안 했었으므로 0으로 변경
    if (buffer_head[i].clock_bit)
    {
      lock_acquire(&buffer_head[i].lock);
      buffer_head[i].clock_bit = 0;
      lock_release(&buffer_head[i].lock);
    }
    else
    { //0이면 참조해야 하므로 1로 변경하고 victim으로 선정
      lock_acquire(&buffer_head[i].lock);
      buffer_head[i].clock_bit = 1;
      lock_release(&buffer_head[i].lock);
      break;
    }
  }

  //buffer_head가 dirty하면 flush
  if (buffer_head[i].dirty == true)
  {
    bc_flush_entry(&buffer_head[i]);
  }

  //버퍼 헤드 초기화
  lock_acquire(&buffer_head[i].lock);
  buffer_head[i].dirty = false;
  buffer_head[i].used = false;
  buffer_head[i].sector = -1;
  lock_release(&buffer_head[i].lock);

  return &buffer_head[i];
}

// buffer_head를 순회하며 entry를 검색
struct buffer_head *bc_lookup(block_sector_t sector)
{

  int i;
  for (i = 0; i < BUFFER_CACHE_ENTRY_NB; i++)
  {
    if (buffer_head[i].used && buffer_head[i].sector == sector)
    {
      return &buffer_head[i];
    }
  }

  return NULL;
}

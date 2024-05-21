/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "include/userprog/process.h"
#include "include/lib/round.h"
#include "include/threads/vaddr.h"
#include "include/threads/mmu.h"

static bool file_backed_swap_in(struct page *page, void *kva);
static bool file_backed_swap_out(struct page *page);
static void file_backed_destroy(struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void vm_file_init(void)
{
}

/* Initialize the file backed page */
bool file_backed_initializer(struct page *page, enum vm_type type, void *kva)
{
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
	file_page->file_data = page->uninit.aux;
	file_page->type = VM_FILE | VM_LOADED;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in(struct page *page, void *kva)
{
	struct file_page *file_page UNUSED = &page->file;

	if (!(VM_TYPE(page->file.type) & VM_LOADED))
	{
		struct lazy_load_segment_aux *param = (struct lazy_load_segment_aux *)page->file.file_data;

		file_seek(param->file, param->ofs);
		off_t read = file_read(param->file, page->frame->kva, param->page_read_bytes);

		uint32_t page_zero_bytes = PGSIZE - read;

		if (page_zero_bytes)
		{
			memset(page->frame->kva + param->page_read_bytes, 0, page_zero_bytes);
		}
	}

	file_page->type = VM_ANON | VM_LOADED;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out(struct page *page)
{
	struct file_page *file_page UNUSED = &page->file;
	struct lazy_load_segment_aux *param = (struct lazy_load_segment_aux *)file_page->file_data;

	if (pml4_is_dirty(thread_current()->pml4, page->va))
		file_write_at(param->file, page->frame->kva, param->page_read_bytes, param->ofs);

	// 1. 해당 page 의 pml4 connection 삭제
	pml4_clear_page(page->frame->owner->pml4, page->va);

	// 2. 프레임 비워줌
	ft_remove_frame(page->frame);
	palloc_free_page(page->frame->kva);
	page->frame->page = NULL;
	free(page->frame);

	// 3. page->frame connection 해제
	page->frame = NULL;

	// page 의 type 을 unloaded 로 변경
	file_page->type = VM_FILE;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy(struct page *page)
{
	struct thread *curr = thread_current();

	// frame 이 존재한다면 관련 데이터제거해주고
	// if (page->frame)
	// {
	// 	ft_remove_frame(page->frame);
	// 	palloc_free_page(page->frame->kva);
	// 	free(page->frame);
	// }
	if (page->frame)
	{
		if (page->frame->ref_count)
		{
			page->frame->ref_count--;
		}
		else
		{
		palloc_free_page(page->frame->kva);
		}
		ft_remove_frame(page->frame);
		free(page->frame);
	}
	// page hash 에서 제거해주고
	// lock_acquire(&curr->spt.spt_lock);
	hash_delete(&curr->spt.hash, &page->hash_elem);
	// lock_release(&curr->spt.spt_lock);

	// pml4 에서 해당 주소 지우기
	pml4_clear_page(curr->pml4, page->va);
}

static bool
lazy_load_segment(struct page *page, void *aux)
{
	struct lazy_load_segment_aux *param = (struct lazy_load_segment_aux *)page->file.file_data;

	file_seek(param->file, param->ofs);
	off_t read = file_read(param->file, page->frame->kva, param->page_read_bytes);

	uint32_t page_zero_bytes = PGSIZE - read;

	if (page_zero_bytes)
	{
		memset(page->frame->kva + param->page_read_bytes, 0, page_zero_bytes);
	}

	return true;
}

/* Do the mmap */
void *
do_mmap(void *addr, size_t length, int writable,
		struct file *file, off_t offset)
{
	void *saved_addr = addr;
	size_t start_ofs = offset;

	struct file *reopened_file = file_reopen(file);

	struct mmap_entry *me = calloc(1, sizeof(struct mmap_entry));
	me->file = reopened_file;
	me->size = length;
	me->vaddr = addr;
	me->offset = offset;

	list_push_back(&thread_current()->mmap_list, &me->list_elem);

	uint32_t zero_bytes = (ROUND_UP(length, PGSIZE) - length);

	while (length > 0 || zero_bytes > 0)
	{
		size_t page_read_bytes = length < PGSIZE ? length : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		struct lazy_load_segment_aux *aux = calloc(1, sizeof(struct lazy_load_segment_aux));
		aux->file = reopened_file;
		aux->ofs = start_ofs;
		aux->page_read_bytes = page_read_bytes;

		if (!vm_alloc_page_with_initializer(VM_FILE, addr, writable, lazy_load_segment, aux))
			return NULL;

		length -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		addr += PGSIZE;
		start_ofs += PGSIZE;
	}

	return saved_addr;
}

/* Do the munmap */
void do_munmap(void *addr)
{
	struct page *p = spt_find_page(&thread_current()->spt, addr);

	if (!p)
	{
		exit(-1);
	}

	struct list mmap_list = thread_current()->mmap_list;

	struct list_elem *e = list_head(&mmap_list);

	struct mmap_entry *me = NULL;
	while ((e = list_next(e)) != list_end(&mmap_list))
	{
		me = list_entry(e, struct mmap_entry, list_elem);

		if (me->vaddr == addr)
			break;
	}

	if (!me)
	{
		exit(-1);
	}

	struct lazy_load_segment_aux *aux = p->uninit.aux;

	size_t page_read_bytes;
	struct file *file = me->file;
	size_t length = me->size;
	size_t disk_offset = me->offset;
	void *frame_start = p->frame ? p->frame->kva : NULL;

	while (length > 0)
	{
		size_t page_read_bytes = length < PGSIZE ? length : PGSIZE;

		if (frame_start && pml4_is_dirty(thread_current()->pml4, p->va))
			file_write_at(file, frame_start, page_read_bytes, disk_offset);

		length -= PGSIZE;

		disk_offset += PGSIZE;

		addr += PGSIZE;

		spt_remove_page(&thread_current()->spt, p);

		p = spt_find_page(&thread_current()->spt, addr);

		struct file_page *file_page = &p->file;

		if (!p)
			break;

		if (p->frame)
			frame_start = p->frame->kva;
		else
			frame_start = NULL;
	}

	list_remove(e); // mmap_list 에서 해당 파일 정보 삭제
	file_close(me->file);
	free(me); // me 데이터 free
}

void mmap_list_kill(struct list *mmap_list)
{
	int num = list_size(mmap_list);
	while (list_size(mmap_list))
	{
		struct mmap_entry *entry = list_entry(list_front(mmap_list), struct mmap_entry, list_elem);

		do_munmap(entry->vaddr);
	}
}
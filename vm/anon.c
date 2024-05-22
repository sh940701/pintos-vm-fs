/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"
#include "include/threads/vaddr.h"
#include "include/lib/kernel/bitmap.h"
#include "include/threads/mmu.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
struct bitmap *swap_map;
int clear[512];
static bool anon_swap_in(struct page *page, void *kva);
static bool anon_swap_out(struct page *page);
static void anon_destroy(struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void vm_anon_init(void)
{
	/* TODO: Set up the swap_disk. */
	swap_disk = disk_get(1, 1);
	swap_map = bitmap_create(disk_size(swap_disk) / SLOT_SIZE); // bitmap 의 각 slot 을 PGSIZE 단위로 관리할 것임
	memset(clear, 0, sizeof(clear));
}

/* Initialize the file mapping */
bool anon_initializer(struct page *page, enum vm_type type, void *kva)
{
	/* Set up the handler */
	page->operations = &anon_ops;

	memset(kva, 0, PGSIZE); // 빼도 될듯?

	struct anon_page *anon_page = &page->anon;

	anon_page->type = VM_ANON | VM_LOADED;
	anon_page->swap_offset = NULL;

	return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in(struct page *page, void *kva)
{
	struct thread *curr = thread_current();

	struct anon_page *anon_page = &page->anon;

	// swap_in 이 실행된 시점에서 page 가 loaded 되었다고 표시되는건
	// do_fork 에서 부모의 page 를 가져온 것이라고 판단.
	if (!(VM_TYPE(page->anon.type) & VM_LOADED))
	{
		struct frame *frame = page->frame;

		// 해당 disk 위치에 데이터가 있는지 확인
		if (!bitmap_test(swap_map, anon_page->swap_offset))
		{
			ft_remove_frame(frame);
			free(frame->kva);
			free(frame);
			exit(30);
		}

		void *kva_for_write = frame->kva;

		// memory 에 disk 데이터 write
		for (int sec_no = anon_page->swap_offset * SLOT_SIZE; sec_no < anon_page->swap_offset * SLOT_SIZE + SLOT_SIZE; sec_no++)
		{
			disk_read(swap_disk, sec_no, kva_for_write);
			disk_write(swap_disk, sec_no, clear); // 사용하고 지워줌
			kva_for_write += DISK_SECTOR_SIZE;
		}

		// 데이터를 사용했으니 bitmap 에서 해당 idx 값을 false 로 변경
		bitmap_set(swap_map, anon_page->swap_offset, false);
		// 또한 swap_offset 도 초기화
		anon_page->swap_offset = NULL;

		// page 의 type 을 loaded 로 변경
		anon_page->type = VM_ANON | VM_LOADED;
	}
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out(struct page *page)
{
	struct anon_page *anon_page = &page->anon;

	// 아직 할당되지 않은 공간 확인
	size_t swap_offset = bitmap_scan(swap_map, 0, 1, false);
	if (swap_offset == BITMAP_ERROR)
	{
		exit(40);
	}

	// page 에 swap_offset 할당
	page->anon.swap_offset = swap_offset;

	void *kva_for_write = page->frame->kva;

	// disk 에 메모리 write
	for (int sec_no = anon_page->swap_offset * SLOT_SIZE; sec_no < anon_page->swap_offset * SLOT_SIZE + SLOT_SIZE; sec_no++)
	{
		disk_write(swap_disk, sec_no, kva_for_write); // 사용하고 지워줌
		kva_for_write += DISK_SECTOR_SIZE;
	}

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
	anon_page->type = VM_ANON;

	// bitmap 사용중으로 업데이트
	bitmap_set(swap_map, swap_offset, true);
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy(struct page *page)
{
	struct anon_page *anon_page = &page->anon;

	struct thread *curr = thread_current();

	// frame 이 존재한다면 관련 데이터제거해주고
	if (page->frame)
	{
		if (page->frame->ref_count)
		{
			page->frame->ref_count--;
		}
		else
		{
			palloc_free_page(page->frame->kva);
			ft_remove_frame(page->frame);
			free(page->frame);
		}
	}
	/* todo swap device 영역도 해제해줘야 하는데, copy on write 의 경우 부모의 swap device 를 해제하게 되므로, 이에 대한 식별자가 필요함
	따라서 현재 구조에서는 구현이 어렵고 시간 또한 춛분하지 않아 todo 로 남김*/
	// // swap offset 이 존재한다면, swap 영역에 데이터가 보관되어있다는 의미이므로 swap 영역도 비워준다.
	// else if (anon_page->swap_offset)
	// {
	// 	for (int sec_no = anon_page->swap_offset * SLOT_SIZE; sec_no < anon_page->swap_offset * SLOT_SIZE + SLOT_SIZE; sec_no++)
	// 	{
	// 		disk_write(swap_disk, sec_no, clear); // 비어있는 swap 영역을 지워줌
	// 	}

	// 	bitmap_set(swap_map, anon_page->swap_offset, false); // 해당 bitmap 영역 사용 가능으로 표시
	// }

	// page hash 에서 제거해주고
	hash_delete(&curr->spt.hash, &page->hash_elem);

	// pml4 에서 해당 주소 지우기
	pml4_clear_page(curr->pml4, page->va);
}

/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "include/threads/vaddr.h"
#include "include/threads/mmu.h"
#include "include/userprog/process.h"

struct frame_table ft;

// #include "mmu.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void vm_init(void)
{
	vm_anon_init();
	vm_file_init();
#ifdef EFILESYS /* For project 4 */
	pagecache_init();
#endif
	register_inspect_intr();
	frame_table_init();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type(struct page *page)
{
	int ty = VM_TYPE(page->operations->type);
	switch (ty)
	{
	case VM_UNINIT:
		return VM_TYPE(page->uninit.type);
	default:
		return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim(void);
static bool vm_do_claim_page(struct page *page);
static struct frame *vm_evict_frame(void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable,
									vm_initializer *init, void *aux)
{

	ASSERT(VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page(spt, upage) == NULL)
	{
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */

		/* TODO: Insert the page into the spt. */

		// upage = palloc_get_page(PAL_USER);

		struct page *p = calloc(1, sizeof(struct page));
		uninit_new(p, upage, init, type, aux, type == VM_ANON ? anon_initializer : file_backed_initializer);

		p->writable = writable;

		return spt_insert_page(spt, p);
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page(struct supplemental_page_table *spt UNUSED, void *va UNUSED)
{
	struct page p;
	struct hash_elem *e;
	struct hash pages = spt->hash;

	p.va = va;

	e = hash_find(&pages, &p.hash_elem);

	return e != NULL ? hash_entry(e, struct page, hash_elem) : NULL;
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt UNUSED,
					 struct page *page UNUSED)
{
	int succ = false;

	if (hash_insert(&spt->hash, &page->hash_elem) == NULL)
	{
		succ = true;
	};

	return succ;
}

bool ft_insert_frame(struct frame *frame)
{
	int succ = false;
	lock_acquire(&ft.ft_lock);

	if (hash_insert(&ft.hash, &frame->hash_elem) == NULL)
	{
		succ = true;
	};
	lock_release(&ft.ft_lock);

	return succ;
}

void ft_remove_frame(struct frame *frame)
{
	lock_acquire(&ft.ft_lock);

	hash_delete(&ft.hash, &frame->hash_elem);

	lock_release(&ft.ft_lock);
}

void spt_remove_page(struct supplemental_page_table *spt, struct page *page)
{
	vm_dealloc_page(page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim(void)
{
	struct frame *victim = NULL;
	/* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame(void)
{
	struct frame *victim UNUSED = vm_get_victim();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
struct frame *
vm_get_frame(void)
{
	struct frame *frame = NULL;

	frame = calloc(1, sizeof(struct frame));
	if (!frame)
	{
		return NULL;
	}
	frame->kva = palloc_get_page(PAL_USER);
	if (!frame->kva)
	{
		free(frame);
		return NULL;
	}
	frame->owner = thread_current();
	ft_insert_frame(frame);

	ASSERT(frame != NULL);
	ASSERT(frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static bool
vm_stack_growth(void *addr UNUSED)
{
	bool success;
	success = vm_alloc_page(VM_ANON, addr, 1);

	if (!success)
		return success;

	success = vm_claim_page(addr);

	return success;
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp(struct page *page UNUSED)
{
}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f UNUSED, void *addr UNUSED,
						 bool user UNUSED, bool write UNUSED, bool not_present UNUSED)
{
	struct supplemental_page_table *spt UNUSED = &thread_current()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */

	// if (!user || !not_present)
	// 	return false;

	if (!not_present)
		return false;

	addr = pg_round_down(addr);

	page = spt_find_page(spt, addr);

	if ((write && !page->writable))
	{
		return false;
	}

	if (page == NULL)
	{
		if ((uint64_t)f->rsp > (uint64_t)addr &&
			((uint64_t)USER_STACK - (1 << 20)) <= (uint64_t)addr &&
			(uint64_t)f->rsp - PGSIZE <= (uint64_t)addr)
		{
			return vm_stack_growth(addr);
		}
		else
		{
			return false;
		}
	}

	return vm_do_claim_page(page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page)
{
	destroy(page);
	free(page);
}

/* Claim the page that allocate on VA. */
bool vm_claim_page(void *va UNUSED)
{
	va = pg_round_down(va);
	struct page *page = spt_find_page(&thread_current()->spt, va);

	if (!page)
	{
		return false;
	}

	return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page(struct page *page)
{
	struct thread *curr = thread_current();

	struct frame *frame = vm_get_frame();

	// frame 할당을 못받았다면 victim page 찾기
	if (!frame)
	{
		// victim page 도 없다면 프로그램 종료
		if (!(frame = find_victim_frame()))
		{
			printf("\n\nvm.c: 315\n\n");
			exit(50);
		}

		swap_out(frame->page);

		frame = vm_get_frame();
		if (!frame)
		{
			printf("\n\nvm.c: 324\n\n");
			exit(60);
		}
	}

	/* Set links */
	frame->page = page;
	page->frame = frame;

	ASSERT(frame != NULL);

	bool result = pml4_set_page(curr->pml4, page->va, frame->kva, page->writable); // r/w 세팅 다시 확인 필요

	ASSERT(result != 0);

	return swap_in(page, frame->kva);
}

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt UNUSED)
{
	/* vm */
	struct hash pages;
	hash_init(&pages, page_hash, page_less, NULL);

	spt->hash = pages;
}

/* Initialize new supplemental page table */
void frame_table_init()
{
	/* vm */
	hash_init(&ft.hash, frame_hash, frame_less, NULL);
	lock_init(&ft.ft_lock);
}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED,
								  struct supplemental_page_table *src UNUSED)
{
	struct hash_iterator i;

	hash_first(&i, &src->hash);
	while (hash_next(&i))
	{
		struct page *old_p = hash_entry(hash_cur(&i), struct page, hash_elem);

		// 할당 되기 전
		if (old_p->operations->type == VM_UNINIT)
		{
			struct lazy_load_segment_aux *aux_p = calloc(1, sizeof(struct lazy_load_segment_aux));
			memcpy(aux_p, old_p->uninit.aux, sizeof(struct lazy_load_segment_aux));

			vm_alloc_page_with_initializer(
				old_p->uninit.type,
				old_p->va,
				old_p->writable,
				old_p->uninit.init,
				aux_p);
		}
		else if (old_p->operations->type == VM_ANON)
		{
			if (VM_TYPE(old_p->anon.type) & VM_LOADED) // anon -> frame
			{
				if (vm_alloc_page(old_p->operations->type, old_p->va, old_p->writable) && vm_claim_page(old_p->va))
				{
					struct page *dst_page = spt_find_page(&thread_current()->spt, old_p->va);

					memcpy(dst_page->frame->kva, old_p->frame->kva, PGSIZE);
				}
			}
			else // anon -> swap device
			{
			}
		}
		else if (old_p->operations->type == VM_FILE)
		{
			if (VM_TYPE(old_p->file.type) & VM_LOADED) // file-backed -> frame
			{
				if (vm_alloc_page(old_p->operations->type, old_p->va, old_p->writable) && vm_claim_page(old_p->va))
				{
					struct page *dst_page = spt_find_page(&thread_current()->spt, old_p->va);

					dst_page->file.file_data = old_p->file.file_data;

					memcpy(dst_page->frame->kva, old_p->frame->kva, PGSIZE);
				}
			}
			else // file-backed -> disk
			{
			}
		}
	};

	return true;
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED)
{
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	hash_destroy(&spt->hash, destructor);
}

struct frame *find_victim_frame()
{
	lock_acquire(&ft.ft_lock);

	struct hash_iterator i;

	hash_first(&i, &ft.hash);
	while (hash_next(&i))
	{
		struct frame *frame_entry = hash_entry(hash_cur(&i), struct frame, hash_elem);
		if (pml4_is_accessed(frame_entry->owner->pml4, frame_entry->page->va))
		{
			pml4_set_accessed(frame_entry->owner->pml4, frame_entry->page->va, false);
		}
		else
		{
			lock_release(&ft.ft_lock);
			return frame_entry;
		}
	}

	lock_release(&ft.ft_lock);

	struct hash_iterator j;
	hash_first(&j, &ft.hash);
	hash_next(&j);

	return hash_entry(hash_cur(&j), struct frame, hash_elem);
}
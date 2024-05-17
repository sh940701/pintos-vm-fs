/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "include/threads/vaddr.h"
#include "include/userprog/process.h"
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
static struct frame *
vm_get_frame(void)
{
	struct frame *frame = NULL;

	frame = calloc(1, sizeof(struct frame));
	frame->kva = palloc_get_page(PAL_USER);

	ASSERT(frame != NULL);
	ASSERT(frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth(void *addr UNUSED)
{
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

	addr = pg_round_down(addr);

	page = spt_find_page(spt, addr);

	if (page == NULL || (write && !page->writable))
		return false;

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
			struct lazy_load_segment_aux *aux_p = calloc(1, sizeof (struct lazy_load_segment_aux));
			memcpy(aux_p, old_p->uninit.aux, sizeof (struct lazy_load_segment_aux));

			vm_alloc_page_with_initializer(
				old_p->uninit.type,
				old_p->va,
				old_p->writable,
				old_p->uninit.init,
				aux_p
			);
		}
		else
		{
			if (vm_alloc_page(old_p->operations->type, old_p->va, old_p->writable) && vm_claim_page(old_p->va)) {
				struct page *dst_page = spt_find_page(&thread_current()->spt, old_p->va);

				memcpy(dst_page->frame->kva, old_p->frame->kva, PGSIZE);
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

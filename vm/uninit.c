/* uninit.c: Implementation of uninitialized page.
 *
 * All of the pages are born as uninit page. When the first page fault occurs,
 * the handler chain calls uninit_initialize (page->operations.swap_in).
 * The uninit_initialize function transmutes the page into the specific page
 * object (anon, file, page_cache), by initializing the page object,and calls
 * initialization callback that passed from vm_alloc_page_with_initializer
 * function.
 * */

#include "vm/vm.h"
#include "vm/uninit.h"

static bool uninit_initialize(struct page *page, void *kva);
static void uninit_destroy(struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations uninit_ops = {
	.swap_in = uninit_initialize, // uninit 상태의 spt 요소에 접근하면 최종적으로 이 함수가 실행됨
	.swap_out = NULL,
	.destroy = uninit_destroy,
	.type = VM_UNINIT,
};

/* DO NOT MODIFY this function */
void uninit_new(struct page *page, void *va, vm_initializer *init,
				enum vm_type type, void *aux,
				bool (*initializer)(struct page *, enum vm_type, void *))
{
	ASSERT(page != NULL);

	*page = (struct page){
		.operations = &uninit_ops,
		.va = va,
		.frame = NULL, /* no frame for now */
		.uninit = (struct uninit_page){
			.init = init, // uninit 상태 struct 의 init 함수 -> 여기선 lazy_load_segment
			.type = type, // uninit -> 어떤 상태로 될지
			.aux = aux,	  // init 함수에 들어갈 인자값
			.page_initializer = initializer,
		}};
}

/* Initalize the page on first fault */
static bool
uninit_initialize(struct page *page, void *kva)
{
	struct uninit_page *uninit = &page->uninit;

	/* Fetch first, page_initialize may overwrite the values */
	vm_initializer *init = uninit->init;
	void *aux = uninit->aux;

	/* TODO: You may need to fix this function. */
	return uninit->page_initializer(page, uninit->type, kva) &&
		   (init ? init(page, aux) : true);
}

/* Free the resources hold by uninit_page. Although most of pages are transmuted
 * to other page objects, it is possible to have uninit pages when the process
 * exit, which are never referenced during the execution.
 * PAGE will be freed by the caller. */
static void
uninit_destroy(struct page *page)
{
	struct uninit_page *uninit UNUSED = &page->uninit;
	/* TODO: Fill this function.
	 * TODO: If you don't have anything to do, just return. */

	switch (uninit->type)
	{
	case VM_ANON:
		hash_delete(&thread_current()->spt.hash, &page->hash_elem);
		break;
	case VM_FILE:
		// page hash 에서 제거해주고
		// lock_acquire(&curr->spt.spt_lock);
		hash_delete(&thread_current()->spt.hash, &page->hash_elem);
		// lock_release(&curr->spt.spt_lock);

		// pml4 에서 해당 주소 지우기
		pml4_clear_page(thread_current()->pml4, page->va);
		break;

	default:
		break;
	}
}

#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/interrupt.h"
#include "threads/synch.h" /* for priority lock */

#ifdef VM
#include "vm/vm.h"
#endif

/* States in a thread's life cycle. */
enum thread_status
{
	THREAD_RUNNING, /* Running thread. */
	THREAD_READY,	/* Not running but ready to run. */
	THREAD_BLOCKED, /* Waiting for an event to trigger. */
	THREAD_DYING	/* About to be destroyed. */
};

struct fdt {
	struct file_entry *fety;
	int fd_val;
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t)-1) /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0			 /* Lowest priority. */
#define PRI_DEFAULT 31		 /* Default priority. */
#define PRI_MAX 63			 /* Highest priority. */
#define MAX_DONATION_LEVEL 8 /* for chain donation_priority */

/* A kernel thread or user process.
 *
 * Each thread structure is stored in its own 4 kB page.  The
 * thread structure itself sits at the very bottom of the page
 * (at offset 0).  The rest of the page is reserved for the
 * thread's kernel stack, which grows downward from the top of
 * the page (at offset 4 kB).  Here's an illustration:
 *
 *      4 kB +---------------------------------+
 *           |          kernel stack           |
 *           |                |                |
 *           |                |                |
 *           |                V                |
 *           |         grows downward          |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           +---------------------------------+
 *           |              magic              |
 *           |            intr_frame           |
 *           |                :                |
 *           |                :                |
 *           |               name              |
 *           |              status             |
 *      0 kB +---------------------------------+
 *
 * The upshot of this is twofold:
 *
 *    1. First, `struct thread' must not be allowed to grow too
 *       big.  If it does, then there will not be enough room for
 *       the kernel stack.  Our base `struct thread' is only a
 *       few bytes in size.  It probably should stay well under 1
 *       kB.
 *
 *    2. Second, kernel stacks must not be allowed to grow too
 *       large.  If a stack overflows, it will corrupt the thread
 *       state.  Thus, kernel functions should not allocate large
 *       structures or arrays as non-static local variables.  Use
 *       dynamic allocation with malloc() or palloc_get_page()
 *       instead.
 *
 * The first symptom of either of these problems will probably be
 * an assertion failure in thread_current(), which checks that
 * the `magic' member of the running thread's `struct thread' is
 * set to THREAD_MAGIC.  Stack overflow will normally change this
 * value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
 * the run queue (thread.c), or it can be an element in a
 * semaphore wait list (synch.c).  It can be used these two ways
 * only because they are mutually exclusive: only a thread in the
 * ready state is on the run queue, whereas only a thread in the
 * blocked state is on a semaphore wait list. */
struct thread
{
	/* Owned by thread.c. */
	tid_t tid;				   /* Thread identifier. */
	enum thread_status status; /* Thread state. */
	char name[16];			   /* Name (for debugging purposes). */
	int priority;			   /* Priority. */

	/* Shared between thread.c and synch.c. */
	struct list_elem elem; /* List element. */

#ifdef USERPROG
	/* Owned by userprog/process.c. */
	uint64_t *pml4; /* Page map level 4 */

	/* System Call */
	struct fdt *fdt;
	bool *fd_isval;		// for finding smallest fd in syscall open()
	int fdt_maxidx;
	struct semaphore fork_sema;
	struct semaphore wait_sema;
	struct list fork_list;
	struct list_elem fork_elem;
	int exit_status;
	struct intr_frame temp_tf;
	struct file *opend_file; 
#endif
#ifdef VM
	/* Table for whole virtual memory owned by thread. */
	struct supplemental_page_table spt;
#endif

	/* Owned by thread.c. */
	struct intr_frame tf; /* Information for switching */
	/* Alarm Clock */
	int64_t wakeup_ticks; // 일어날 시각 추가
	/* Priority scheduling */
	int init_priority;
	struct lock *wait_on_lock;
	struct list donations;			/* 이 스레드한테 도네이션 한 스레드들 목록 */
	struct list_elem donation_elem; /* 다른 스레드한테 도네이션 했을때, 다른 스레드의 donations list에 들어갈 list_elem */
	/* Advanced Scheduler */
	int nice;
	int recent_cpu;
	struct list_elem thread_elem;
	unsigned magic; /* Detects stack overflow. */
};

/* for alaram-multiple */
void thread_sleep(int64_t ticks);
void thread_wakeup(int64_t current_ticks);

/* for priority scheduling */
typedef enum {
	READY_LIST,
	WAIT_LIST,
	DONATION_LIST,
	COND_LIST,
	SLEEP_LIST
} typelist;
void preempt_priority(void);
bool priority_larger(const struct list_elem *insert_elem, const struct list_elem *cmp_elem, typelist type);
void update_priority_for_donations(void);
void thread_readylist_reorder(struct thread *t);

/* for advanced scheduler */
void mlfq_scheduler(struct thread *t);
void mlfq_cal_priority(struct thread *t);
void thread_cal_load_avg(void);
void thread_cal_recent_cpu(struct thread *t);

/* arithmetic cal */
#define N_to_FP(n) ((n) * f)
#define X_TRUN_INT(x) ((x) / f)
#define X_NEAR_INT(x) (((x) >= 0) ? (((x) + (f / 2)) / f) : (((x) - (f / 2)) / f))
#define ADD_X_Y(x, y) ((x) + (y))
#define ADD_X_N(x, n) ((x) + ((n) * f))
#define SUB_X_Y(x, y) ((x) - (y))
#define SUB_X_N(x, n) ((x) - ((n) * f))
#define MUL_X_Y(x, y) ((((int64_t)(x)) * (y)) / f)
#define MUL_X_N(x, n) ((x) * (n))
#define DIV_X_Y(x, y) ((((int64_t)(x)) * f) / (y))
#define DIV_X_N(x, n) ((x) / (n))

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init(void);
void thread_start(void);

void thread_tick(void);
void thread_print_stats(void);

typedef void thread_func(void *aux);
tid_t thread_create(const char *name, int priority, thread_func *, void *);

void thread_block(void);
void thread_unblock(struct thread *);

struct thread *thread_current(void);
tid_t thread_tid(void);
const char *thread_name(void);

void thread_exit(void) NO_RETURN;
void thread_yield(void);

int thread_get_priority(void);
void thread_set_priority(int);

int thread_get_nice(void);
void thread_set_nice(int);
int thread_get_recent_cpu(void);
int thread_get_load_avg(void);

void do_iret(struct intr_frame *tf);

#endif /* threads/thread.h */

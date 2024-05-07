#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* Random value for basic thread
   Do not modify this value. */
#define THREAD_BASIC 0xd42df210

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Thread destruction requests */
static struct list destruction_req;

/* memory ticks for timer_sleep */
static struct list sleep_list;

/* Statistics. */
static long long idle_ticks;   /* # of timer ticks spent idle. */
static long long kernel_ticks; /* # of timer ticks in kernel threads. */
static long long user_ticks;   /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4		  /* # of timer ticks to give each thread. */
static unsigned thread_ticks; /* # of timer ticks since last yield. */

/* advanced scheduler */
#define TIMER_FREQ 100
static int load_avg = 0;
static struct list thread_list;

/* p.q float number */
int f = (1 << 14);

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread(thread_func *, void *aux);
static void idle(void *aux UNUSED);
static struct thread *next_thread_to_run(void);
static void init_thread(struct thread *, const char *name, int priority);
static void do_schedule(int status);
static void schedule(void);
static tid_t allocate_tid(void);

/* Returns true if T appears to point to a valid thread. */
#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC)

/* Returns the running thread.
 * Read the CPU's stack pointer `rsp', and then round that
 * down to the start of a page.  Since `struct thread' is
 * always at the beginning of a page and the stack pointer is
 * somewhere in the middle, this locates the curent thread. */
#define running_thread() ((struct thread *)(pg_round_down(rrsp())))

// Global descriptor table for the thread_start.
// Because the gdt will be setup after the thread_init, we should
// setup temporal gdt first.
static uint64_t gdt[3] = {0, 0x00af9a000000ffff, 0x00cf92000000ffff};

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void thread_init(void)
{
	ASSERT(intr_get_level() == INTR_OFF);

	/* Reload the temporal gdt for the kernel
	 * This gdt does not include the user context.
	 * The kernel will rebuild the gdt with user context, in gdt_init (). */
	struct desc_ptr gdt_ds = {
		.size = sizeof(gdt) - 1,
		.address = (uint64_t)gdt};
	lgdt(&gdt_ds);

	/* Init the global thread context */
	lock_init(&tid_lock);
	list_init(&ready_list);
	list_init(&destruction_req);
	list_init(&sleep_list);
	list_init(&thread_list);

	/* Set up a thread structure for the running thread. */
	initial_thread = running_thread();
	init_thread(initial_thread, "main", PRI_DEFAULT);
	initial_thread->status = THREAD_RUNNING;
	initial_thread->tid = allocate_tid();
	if (thread_mlfqs)
	{
		mlfq_cal_priority(initial_thread);
	}
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void thread_start(void)
{
	/* Create the idle thread. */
	struct semaphore idle_started;
	sema_init(&idle_started, 0);
	thread_create("idle", PRI_MIN, idle, &idle_started);

	/* Start preemptive thread scheduling. */
	intr_enable();

	/* Wait for the idle thread to initialize idle_thread. */
	sema_down(&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void thread_tick(void)
{
	struct thread *t = thread_current();

	/* Update statistics. */
	if (t == idle_thread)
		idle_ticks++;
#ifdef USERPROG
	else if (t->pml4 != NULL)
		user_ticks++;
#endif
	else
	{
		kernel_ticks++;
	}

	if (thread_mlfqs)
		mlfq_scheduler(t);

	/* Enforce preemption. */
	if (++thread_ticks >= TIME_SLICE)
		intr_yield_on_return();
}

void mlfq_scheduler(struct thread *t)
{
	struct thread *tar_t;
	struct list_elem *tar_elem;
	int now_tick = timer_ticks();

	if (t != idle_thread)
		t->recent_cpu += N_to_FP(1);

	// TIMER_FREQ(100) 마다 전체 thread를 순회하며 recent_cpu와 load_avg 갱신
	if (now_tick % 4 == 0)
	{
		if (now_tick % TIMER_FREQ == 0)
			thread_cal_load_avg();
		tar_elem = list_head(&thread_list);
		while ((tar_elem = tar_elem->next) != &thread_list.tail)
		{
			tar_t = list_entry(tar_elem, struct thread, thread_elem);
			if (now_tick % TIMER_FREQ == 0)
				thread_cal_recent_cpu(tar_t);
			mlfq_cal_priority(tar_t); // 4 tick마다 priority 갱신
			if (tar_t->status == THREAD_BLOCKED)
				thread_reschedule(tar_t);
		}
		list_sort(&ready_list, priority_larger, READY_LIST);
	}
}

/* Prints thread statistics. */
void thread_print_stats(void)
{
	printf("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
		   idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t thread_create(const char *name, int priority,
					thread_func *function, void *aux)
{
	struct thread *t;
	tid_t tid;

	ASSERT(function != NULL);

	/* Allocate thread. */
	t = palloc_get_page(PAL_ZERO);
	if (t == NULL)
		return TID_ERROR;

	/* Initialize thread. */
	init_thread(t, name, priority);
	tid = t->tid = allocate_tid();

#ifdef USERPROG
	t->fdt = palloc_get_multiple(PAL_ZERO, 3); // for multi-oom test
#endif

	/* Call the kernel_thread if it scheduled.
	 * Note) rdi is 1st argument, and rsi is 2nd argument. */
	t->tf.rip = (uintptr_t)kernel_thread;
	t->tf.R.rdi = (uint64_t)function;
	t->tf.R.rsi = (uint64_t)aux;
	t->tf.ds = SEL_KDSEG;
	t->tf.es = SEL_KDSEG;
	t->tf.ss = SEL_KDSEG;
	t->tf.cs = SEL_KCSEG;
	t->tf.eflags = FLAG_IF;

	if (thread_mlfqs)
	{
		t->nice = thread_current()->nice;
		t->recent_cpu = thread_current()->recent_cpu;
		mlfq_cal_priority(t);
	}

	/* Add to run queue. */
	if (t != idle_thread)
		thread_unblock(t);
	preempt_priority();
	return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void thread_block(void)
{
	ASSERT(!intr_context());
	ASSERT(intr_get_level() == INTR_OFF);
	thread_current()->status = THREAD_BLOCKED;
	schedule();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void thread_unblock(struct thread *t)
{
	enum intr_level old_level;

	ASSERT(is_thread(t));

	old_level = intr_disable();
	ASSERT(t->status == THREAD_BLOCKED);
	t->status = THREAD_READY;
	/* 우선순위 크기순으로 내림차순정렬 */
	list_insert_ordered(&ready_list, &t->elem, priority_larger, READY_LIST);
	intr_set_level(old_level);
}

/* 잠든 스레드를 sleep_list에 삽입하는 함수 */
void thread_sleep(int64_t ticks)
{
	struct thread *curr = thread_current();
	ASSERT(curr != idle_thread);

	enum intr_level old_level;
	old_level = intr_disable();

	curr->wakeup_ticks = ticks;
	list_insert_ordered(&sleep_list, &curr->elem, priority_larger, SLEEP_LIST);
	thread_block();

	intr_set_level(old_level);
}

/* 깨울 스레드를 sleep_list에서 제거하고 ready_list에 삽입 */
void thread_wakeup(int64_t current_ticks)
{
	enum intr_level old_level;
	old_level = intr_disable();

	struct list_elem *curr_elem = list_begin(&sleep_list);
	while (curr_elem != list_end(&sleep_list))
	{
		struct thread *curr_thread = list_entry(curr_elem, struct thread, elem);
		if (current_ticks >= curr_thread->wakeup_ticks) // 깰 시간이 됐으면
		{
			curr_elem = list_remove(curr_elem);
			thread_unblock(curr_thread);
		}
		else
			break;
	}
	intr_set_level(old_level);
}

/* ready_list에 현재 스레드의 priority보다 높은 priority를 가지는 스레드가 있으면 그 스레드에게 양보 */
void preempt_priority(void)
{
	if (thread_current() == idle_thread)
		return;
	if (list_empty(&ready_list))
		return;
	struct thread *curr = thread_current();
	struct thread *ready = list_entry(list_front(&ready_list), struct thread, elem);
	if (curr->priority < ready->priority) // ready_list에 현재 실행중인 스레드보다 우선순위가 높은 스레드가 있으면
		thread_yield();
}

/* Returns the name of the running thread. */
const char *
thread_name(void)
{
	return thread_current()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current(void)
{
	struct thread *t = running_thread();

	/* Make sure T is really a thread.
	   If either of these assertions fire, then your thread may
	   have overflowed its stack.  Each thread has less than 4 kB
	   of stack, so a few big automatic arrays or moderate
	   recursion can cause stack overflow. */
	ASSERT(is_thread(t));
	ASSERT(t->status == THREAD_RUNNING);

	return t;
}

/* Returns the running thread's tid. */
tid_t thread_tid(void)
{
	return thread_current()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void thread_exit(void)
{
	ASSERT(!intr_context());

#ifdef USERPROG
	process_exit();
	struct list_elem *curr = &thread_current()->fork_elem;
	while (curr->prev != NULL)
		curr = curr->prev;
	struct thread *parent = list_entry(curr, struct thread, fork_list.head);
	parent->exit_status = thread_current()->exit_status;
	sema_up(&parent->wait_sema);
	list_remove(&thread_current()->fork_elem);
	
#endif

	/* Just set our status to dying and schedule another process.
	   We will be destroyed during the call to schedule_tail(). */
	intr_disable();
	do_schedule(THREAD_DYING);
	NOT_REACHED();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void thread_yield(void)
{
	struct thread *curr = thread_current();
	enum intr_level old_level;

	ASSERT(!intr_context());

	old_level = intr_disable();
	if (curr != idle_thread)
		list_insert_ordered(&ready_list, &curr->elem, priority_larger, READY_LIST); /* 우선순위 크기 순으로 내림차순정렬 */
	do_schedule(THREAD_READY);
	intr_set_level(old_level);
}

/* list_insert_order에 사용되는 우선순위 크기 비교함수 */
bool priority_larger(const struct list_elem *insert_elem, const struct list_elem *cmp_elem,
					 typelist type)
{
	struct thread *t, *cmp_t;
	switch (type)
	{
	case WAIT_LIST:
	case READY_LIST:
		t = list_entry(insert_elem, struct thread, elem);
		cmp_t = list_entry(cmp_elem, struct thread, elem);
		break;
	case DONATION_LIST:
		t = list_entry(insert_elem, struct thread, donation_elem);
		cmp_t = list_entry(cmp_elem, struct thread, donation_elem);
		break;
	case COND_LIST:
		t = thread_current();
		struct semaphore cmp = list_entry(cmp_elem, struct semaphore_elem, elem)->semaphore;
		cmp_t = list_entry(list_begin(&cmp.waiters), struct thread, elem);
		break;
	case SLEEP_LIST:
		t = list_entry(insert_elem, struct thread, elem);
		cmp_t = list_entry(cmp_elem, struct thread, elem);
		return t->wakeup_ticks < cmp_t->wakeup_ticks;
	}
	return t->priority > cmp_t->priority;
}
/* ready list에 있는 thread의 순서를 재정렬 */
void thread_readylist_reorder(struct thread *t)
{
	ASSERT(t->status == THREAD_READY);

	enum intr_level old_level;
	old_level = intr_disable();
	list_remove(&t->elem);
	list_insert_ordered(&ready_list, &t->elem, priority_larger, READY_LIST);
	intr_set_level(old_level);
}

/* 우선순위 재설정 후 높은 우선순위가 있다면 양보 */
void thread_set_priority(int new_priority)
{
	thread_current()->init_priority = new_priority;
	update_priority_for_donations();
	preempt_priority();
}

/* Returns the current thread's priority. */
int thread_get_priority(void)
{
	return thread_current()->priority;
}

/* Sets the current thread's nice value to NICE. */
void thread_set_nice(int nice UNUSED)
{
	ASSERT((-20 <= nice) && (nice <= 20));

	thread_current()->nice = nice;
	mlfq_cal_priority(thread_current());
	preempt_priority();
}

/* Returns the current thread's nice value. */
int thread_get_nice(void)
{
	return thread_current()->nice;
}

/* Returns 100 times the system load average. */
int thread_get_load_avg(void)
{
	return X_NEAR_INT(MUL_X_N(load_avg, 100));
}

/* Returns 100 times the current thread's recent_cpu value. */
int thread_get_recent_cpu(void)
{
	return X_NEAR_INT(MUL_X_N(thread_current()->recent_cpu, 100));
}

/* calculate load_avg */
void thread_cal_load_avg(void)
{
	int ready_threads = (thread_current() != idle_thread) ? 1 : 0;
	ready_threads += list_size(&ready_list);
	load_avg = ADD_X_Y(MUL_X_Y(DIV_X_N(N_to_FP(59), 60), load_avg), MUL_X_N(DIV_X_N(N_to_FP(1), 60), ready_threads));
}

/* calculate recent_cpu */
void thread_cal_recent_cpu(struct thread *t)
{
	int recent_cpu = ADD_X_N(MUL_X_Y(DIV_X_Y(MUL_X_N(load_avg, 2), ADD_X_N(MUL_X_N(load_avg, 2), 1)), t->recent_cpu), t->nice);
	t->recent_cpu = recent_cpu;
}

/* mlfq(4.4BSD scheduler)방법으로 현재시각 기준 계산 */
void mlfq_cal_priority(struct thread *t)
{
	int priority = X_TRUN_INT(ADD_X_N(ADD_X_N(-DIV_X_N(t->recent_cpu, 4), PRI_MAX), -t->nice * 2));
	t->priority = (priority > 63) ? 63 : ((priority < 0) ? 0 : priority);
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle(void *idle_started_ UNUSED)
{
	struct semaphore *idle_started = idle_started_;

	idle_thread = thread_current();
	sema_up(idle_started);

	for (;;)
	{
		/* Let someone else run. */
		intr_disable();
		thread_block();

		/* Re-enable interrupts and wait for the next one.

		   The `sti' instruction disables interrupts until the
		   completion of the next instruction, so these two
		   instructions are executed atomically.  This atomicity is
		   important; otherwise, an interrupt could be handled
		   between re-enabling interrupts and waiting for the next
		   one to occur, wasting as much as one clock tick worth of
		   time.

		   See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
		   7.11.1 "HLT Instruction". */
		asm volatile("sti; hlt" : : : "memory");
	}
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread(thread_func *function, void *aux)
{
	ASSERT(function != NULL);

	intr_enable(); /* The scheduler runs with interrupts off. */
	function(aux); /* Execute the thread function. */
	thread_exit(); /* If function() returns, kill the thread. */
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread(struct thread *t, const char *name, int priority)
{
	ASSERT(t != NULL);
	ASSERT(PRI_MIN <= priority && priority <= PRI_MAX);
	ASSERT(name != NULL);

	memset(t, 0, sizeof *t);
	t->status = THREAD_BLOCKED;
	strlcpy(t->name, name, sizeof t->name);
	t->tf.rsp = (uint64_t)t + PGSIZE - sizeof(void *);
	t->priority = priority;
	t->nice = 0;
	t->recent_cpu = 0;
	t->fdt_maxi = 2;
	t->exit_status = 123456789;
	lock_init(&t->fork_lock);
	cond_init(&t->fork_cond);
	sema_init(&t->wait_sema, 0);

	if (thread_mlfqs)
		list_push_back(&thread_list, &t->thread_elem);
	t->magic = THREAD_MAGIC;

	/* for donation */
	t->init_priority = priority;
	t->wait_on_lock = NULL;
	list_init(&t->donations);
	list_init(&t->fork_list);
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run(void)
{
	if (list_empty(&ready_list))
		return idle_thread;
	else
		return list_entry(list_pop_front(&ready_list), struct thread, elem);
}

/* Use iretq to launch the thread */
/* 새로운 스레드의 context를 레지스터에 저장 */
void do_iret(struct intr_frame *tf)
{
	__asm __volatile(
		"movq %0, %%rsp\n"
		"movq 0(%%rsp),%%r15\n"
		"movq 8(%%rsp),%%r14\n"
		"movq 16(%%rsp),%%r13\n"
		"movq 24(%%rsp),%%r12\n"
		"movq 32(%%rsp),%%r11\n"
		"movq 40(%%rsp),%%r10\n"
		"movq 48(%%rsp),%%r9\n"
		"movq 56(%%rsp),%%r8\n"
		"movq 64(%%rsp),%%rsi\n"
		"movq 72(%%rsp),%%rdi\n"
		"movq 80(%%rsp),%%rbp\n"
		"movq 88(%%rsp),%%rdx\n"
		"movq 96(%%rsp),%%rcx\n"
		"movq 104(%%rsp),%%rbx\n"
		"movq 112(%%rsp),%%rax\n"
		"addq $120,%%rsp\n"
		"movw 8(%%rsp),%%ds\n"
		"movw (%%rsp),%%es\n"
		"addq $32, %%rsp\n" // 다시 한 번 스택 포인터를 조정하여, iretq 명령어를 실행하기 전에 필요한 스택의 위치로 이동시킵니다. iretq는 'interrupt return'의 약자로, 이 명령어는 인터럽트 또는 예외가 처리된 후 초기 상태로 복귀하는데 사용됩니다.
		"iretq"				// 최종적으로 iretq 명령어를 실행하여, 이전 상태로 복귀합니다. 이 과정에는 코드 세그먼트 레지스터(CS), 인스트럭션 포인터(RIP), 그리고 프로그램 상태 레지스터(RFLAGS)가 스택에서 복원되어, 원래 실행하던 프로그램의 지점으로 정확히 돌아가 계속 실행될 수 있게 합니다.
		: : "g"((uint64_t)tf) : "memory");
}

/* Switching the thread by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function. */
/* 현재 스레드의 context를 스레드의 interrupt frame에 옮기는 작업 그리고 do_iret함수를 호출 register rdi에 tf포인터를 인자로 넘기며 */
static void
thread_launch(struct thread *th)
{
	uint64_t tf_cur = (uint64_t)&running_thread()->tf;
	uint64_t tf = (uint64_t)&th->tf;
	ASSERT(intr_get_level() == INTR_OFF);

	/* The main switching logic.
	 * We first restore the whole execution context into the intr_frame
	 * and then switching to the next thread by calling do_iret.
	 * Note that, we SHOULD NOT use any stack from here
	 * until switching is done. */
	__asm __volatile(
		/* Store registers that will be used. */
		/* register rax, rbx, rcx의 값을 stack에 저장한다(다른값(tf_cut과 tf의 interrupt frame을 가리키는 포인터(8바이트)))으로
		채울것이기 때문에, 스택에 저장해놓는것) */
		"push %%rax\n"
		"push %%rbx\n"
		"push %%rcx\n"
		/* Fetch input once */
		/* movq %0, %%rax : 첫 번째 입력(%0, 여기서는 tf_cur)을 rax 레지스터로 이동합니다.
		   movq는 64비트 값을 이동하는 명령어로, 여기서는 tf_cur 포인터를 rax에 저장합니다.
		   movq %1, %%rcx : 두 번째 입력(%1, 여기서는 tf)를 rcx 레지스터로 이동합니다.
		   이 작업도 포인터를 레지스터로 옮기는 작업입니다. */
		"movq %0, %%rax\n"
		"movq %1, %%rcx\n"
		/* rax가 가키리는 주소값+x에 레지스터들의 값들을 저장한다.(tf_cur의 interrupt frame에 다음에 실행할때의 context를 저장) */
		"movq %%r15, 0(%%rax)\n"
		"movq %%r14, 8(%%rax)\n"
		"movq %%r13, 16(%%rax)\n"
		"movq %%r12, 24(%%rax)\n"
		"movq %%r11, 32(%%rax)\n"
		"movq %%r10, 40(%%rax)\n"
		"movq %%r9, 48(%%rax)\n"
		"movq %%r8, 56(%%rax)\n"
		"movq %%rsi, 64(%%rax)\n"
		"movq %%rdi, 72(%%rax)\n"
		"movq %%rbp, 80(%%rax)\n"
		"movq %%rdx, 88(%%rax)\n"
		/* 스택에서 pop해서 register rbx에 저장(a, b, c순으로 넣었으므로 c가 나왔을것임) */
		"pop %%rbx\n" // Saved rcx
		/* 원래 rcx에 있던값을 tf_cur의 interrupt frame에 저장 */
		"movq %%rbx, 96(%%rax)\n"
		"pop %%rbx\n" // Saved rbx
		"movq %%rbx, 104(%%rax)\n"
		"pop %%rbx\n" // Saved rax
		"movq %%rbx, 112(%%rax)\n"
		/* addq $120, %%rax: rax 레지스터의 값에 120을 더합니다.
		이는 rax가 가리키는 위치를 조정하여 특정 저장 공간(예: 인터럽트 프레임)에 접근하기 위한 준비 작업입니다. */
		"addq $120, %%rax\n"
		"movw %%es, (%%rax)\n"
		"movw %%ds, 8(%%rax)\n"
		"addq $32, %%rax\n"
		/* 현재의 명령 포인터(rip) 값을 스택에 저장하고 __next 라벨로 점프합니다. 이는 rip 값을 얻기 위한 트릭입니다. */
		"call __next\n"						  // read the current rip.
		"__next:\n"							  // rip 값을 얻는 목적지 라벨입니다.
		"pop %%rbx\n"						  // 이전 명령(call __next)에 의해 스택에 저장되었던 rip 값을 rbx 레지스터로 가져옵니다.
		"addq $(out_iret -  __next), %%rbx\n" // rbx의 값(현재 rip의 값)에 (out_iret - __next)를 더합니다. 이는 인터럽트 후에 실행을 계속할 위치를 계산하기 위함입니다.
		"movq %%rbx, 0(%%rax)\n"			  // rip.  gpt의 설명 : 계산된 rip 값을 rax가 가리키는 위치에 저장합니다.
		"movw %%cs, 8(%%rax)\n"				  // cs.   gpt의 설명 : 코드 세그먼트 레지스터 cs의 값을 rax가 가리키는 위치로 부터 8바이트 떨어진 곳에 저장합니다.
		"pushfq\n"							  // 플래그 레지스터의 현재 상태를 스택에 저장합니다.
		"popq %%rbx\n"						  // 스택에서 플래그 레지스터 값을 꺼내어 rbx에 저장합니다.
		"mov %%rbx, 16(%%rax)\n"			  // eflags
		"mov %%rsp, 24(%%rax)\n"			  // rsp
		"movw %%ss, 32(%%rax)\n"			  // 스택 세그먼트 레지스터 ss의 값을 rax가 가리키는 위치로부터 32바이트 떨어진 곳에 저장합니다.
		"mov %%rcx, %%rdi\n"				  // 변수 혹은 포인터를 함수 do_iret에 전달하기 위해 rcx의 값을 rdi에 복사합니다. x86_64 호출 규약에서 첫 번째 인자는 rdi를 통해 전달됩니다.
		"call do_iret\n"					  // do_iret 함수를 호출합니다. 이 함수는 인터럽트 후에 처리를 진행합니다.
		"out_iret:\n"						  // addq 명령에서 사용된 라벨로, rip 위치 계산에 필요합니다.
		: : "g"(tf_cur), "g"(tf) : "memory");
}

/* Schedules a new process. At entry, interrupts must be off.
 * This function modify current thread's status to status and then
 * finds another thread to run and switches to it.
 * It's not safe to call printf() in the schedule(). */
static void
do_schedule(int status)
{
	ASSERT(intr_get_level() == INTR_OFF);
	ASSERT(thread_current()->status == THREAD_RUNNING);
	while (!list_empty(&destruction_req))
	{
		struct thread *victim =
			list_entry(list_pop_front(&destruction_req), struct thread, elem);
#ifdef USERPROG
		palloc_free_multiple(victim->fdt, 3);
		pml4_destroy(victim->pml4);
		for (int i = 3; i <= victim->fdt_maxi; i++)
			if (victim->fdt[i] != NULL)
				file_close(victim->fdt[i]);
#endif
		palloc_free_page(victim);
	}
	thread_current()->status = status;
	schedule();
}

static void
schedule(void)
{
	struct thread *curr = running_thread();
	struct thread *next = next_thread_to_run();

	ASSERT(intr_get_level() == INTR_OFF);
	ASSERT(curr->status != THREAD_RUNNING);
	ASSERT(is_thread(next));
	/* Mark us as running. */
	next->status = THREAD_RUNNING;

	/* Start new time slice. */
	thread_ticks = 0;

#ifdef USERPROG
	/* Activate the new address space. */
	process_activate(next);
#endif

	if (curr != next)
	{
		/* If the thread we switched from is dying, destroy its struct
		   thread. This must happen late so that thread_exit() doesn't
		   pull out the rug under itself.
		   We just queuing the page free reqeust here because the page is
		   currently used by the stack.
		   The real destruction logic will be called at the beginning of the
		   schedule(). */
		if (curr && curr->status == THREAD_DYING && curr != initial_thread)
		{
			ASSERT(curr != next);
			list_push_back(&destruction_req, &curr->elem);
			if (thread_mlfqs)
				list_remove(&curr->thread_elem);
		}
		/* Before switching the thread, we first save the information
		 * of current running. */
		thread_launch(next);
	}
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid(void)
{
	static tid_t next_tid = 1;
	tid_t tid;

	lock_acquire(&tid_lock);
	tid = next_tid++;
	lock_release(&tid_lock);

	return tid;
}

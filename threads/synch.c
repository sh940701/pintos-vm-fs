/* This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

/* Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.

   Permission to use, copy, modify, and distribute this software
   and its documentation for any purpose, without fee, and
   without written agreement is hereby granted, provided that the
   above copyright notice and the following two paragraphs appear
   in all copies of this software.

   IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
   ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
   CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
   AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
   HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
   BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
   PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
   MODIFICATIONS.
   */

#include "threads/synch.h"
#include <stdio.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

/* Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:

   - down or "P": wait for the value to become positive, then
   decrement it.

   - up or "V": increment the value (and wake up one waiting
   thread, if any). */
void
sema_init (struct semaphore *sema, unsigned value) {
	ASSERT (sema != NULL);

	sema->value = value;
	list_init (&sema->waiters);
}

/* Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on. This is
   sema_down function. */
void
sema_down (struct semaphore *sema) {
	enum intr_level old_level;

	ASSERT (sema != NULL);
	ASSERT (!intr_context ());

	old_level = intr_disable ();
	while (sema->value == 0) {	// 우선순위 크기순으로 내림차순 재정렬 
		list_insert_ordered(&sema->waiters, &thread_current()->elem, priority_larger, WAIT_LIST);
		thread_block ();
	}
	sema->value--;
	intr_set_level (old_level);
}

/* Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.

   This function may be called from an interrupt handler. */
bool
sema_try_down (struct semaphore *sema) {
	enum intr_level old_level;
	bool success;

	ASSERT (sema != NULL);

	old_level = intr_disable ();
	if (sema->value > 0)
	{
		sema->value--;
		success = true;
	}
	else
		success = false;
	intr_set_level (old_level);

	return success;
}

/* Up or "V" operation on a semaphore.  Increments SEMA's value
   and wakes up one thread of those waiting for SEMA, if any.

   This function may be called from an interrupt handler. */
void
sema_up (struct semaphore *sema) {
	enum intr_level old_level;
	struct thread *t;
	ASSERT (sema != NULL);

	old_level = intr_disable ();
	if (!list_empty (&sema->waiters)){
		t = list_entry (list_pop_front (&sema->waiters), struct thread, elem);
		thread_unblock(t);
		// 우선 순위가 높아 지는 경우 양보
		if (t->priority > thread_current()->priority){
			sema->value++;
			intr_set_level (old_level);
			thread_yield();
			return;
		}
	}
	sema->value++;
	intr_set_level (old_level);
}

static void sema_test_helper (void *sema_);

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void
sema_self_test (void) {
	struct semaphore sema[2];
	int i;

	printf ("Testing semaphores...");
	sema_init (&sema[0], 0);
	sema_init (&sema[1], 0);
	thread_create ("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
	for (i = 0; i < 10; i++)
	{
		sema_up (&sema[0]);
		sema_down (&sema[1]);
	}
	printf ("done.\n");
}

/* Thread function used by sema_self_test(). */
static void
sema_test_helper (void *sema_) {
	struct semaphore *sema = sema_;
	int i;

	for (i = 0; i < 10; i++)
	{
		sema_down (&sema[0]);
		sema_up (&sema[1]);
	}
}

/* Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.

   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. */

void
lock_init (struct lock *lock) {
	ASSERT (lock != NULL);

	lock->holder = NULL;
	sema_init (&lock->semaphore, 1);
}

/* Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void
lock_acquire (struct lock *lock) {
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (!lock_held_by_current_thread (lock));
	
	if (lock_try_acquire(lock)) 	/* priority donation이 발생하지 않음 */
		return;	
	struct thread *donator = thread_current();
	donator->blocked_lock = lock;
	priority_donation(lock, donator);		

	sema_down(&lock->semaphore);
	lock->holder = thread_current ();
	donator->blocked_lock = NULL;

	if (donator->donation_depth != -1){		// priority donation한 경우
		donation_withdraw(donator);
		donator->donation_depth = -1;
	}

}
/* 현재 blocked holder의 우선순위가 낮다면 priority donation이 발생함 */
void priority_donation(struct lock *lock, struct thread *donator)
{	
	struct thread *beneficiary = lock->holder;
	if (beneficiary->priority < donator->priority)
	{	
		int idx;	// 같은 lock에 대해 donation한 save priority를 찾아 지움
		for (idx =0; idx<=beneficiary->nested_depth; idx++)
			if (lock == beneficiary->saved_lock[idx]) {
				beneficiary->priority = beneficiary->saved_priority[idx];	// origin priority 값을 다시 불러옴
				for (; idx < beneficiary->nested_depth; idx++) {
					beneficiary->saved_priority[idx] = beneficiary->saved_priority[idx+1];
					beneficiary->saved_lock[idx] = beneficiary->saved_lock[idx+1];
				}
				beneficiary->nested_depth--;
				break;
			}
		beneficiary->saved_priority[++beneficiary->nested_depth] = beneficiary->priority;	 // 기부 받기전 우선순위 저장
		beneficiary->saved_lock[beneficiary->nested_depth] = lock;					// 기부 받은 lock 저장
		donator->beneficiary_list[++donator->donation_depth] = beneficiary;			// donation return을 위해 후원자 목록 저장
		donator->donation_list[donator->donation_depth] = donator->priority;		// donation return을 위해 후원한 우선순위 값 저장
		beneficiary->priority = donator->priority;									// 우선순위 기부
											
		// ready list에 넣어 마지막 수혜자부터 순서대로 lock_release 시도
		if ((beneficiary->nested_depth >= MAX_DONATION_LEVEL) || 
			(beneficiary->blocked_lock == NULL)) 
		{	// 우선순위 크기순으로 내림차순 재정렬 
			if (beneficiary->status == THREAD_BLOCKED) {
				list_remove(&beneficiary->elem);
				thread_unblock(beneficiary);
			}
			else if (beneficiary->status == THREAD_READY)
				thread_readylist_reorder(beneficiary);
			return thread_yield();		
		}
		else // MAX_DONATION_LEVEL 초과 혹은 lock-holder가 없을 때 까지, 재귀적으로 전달
		{
			thread_reschedule(beneficiary);
			priority_donation(beneficiary->blocked_lock, beneficiary);
		}
	}	
}
/* thread의 각 ready list or block list에서 우선순위 변경으로 인한 list 순서만 정렬(thread unblock과 다름) */
void thread_reschedule(struct thread* t)
{
	if (t->status == THREAD_BLOCKED){
		enum intr_level old_level;
		old_level = intr_disable();
		list_remove(&t->elem);
		list_insert_ordered(&t->blocked_lock->semaphore.waiters, &t->elem, priority_larger, WAIT_LIST);
		intr_set_level(old_level);
	}
	else if (t->status == THREAD_READY)
		thread_readylist_reorder(t);
}

/* 자기가 기부한 beneficiary_list의 thread의 priority를 회수 */
void donation_withdraw(struct thread *donator)
{	
	for (int depth = 0; depth <= donator->donation_depth; depth++) {
		struct thread *beneficiary = donator->beneficiary_list[depth];
		// benefitor의 현재 값을 바꾸는 경우
		if (beneficiary->priority == donator->donation_list[depth]){
			beneficiary->priority = beneficiary->saved_priority[beneficiary->nested_depth--];
			// 각 상태의 list에서 내림차순 재정렬
			thread_reschedule(beneficiary);
		}
		else {	// 저장된 priority목록 에서 삭제하는 경우
			int idx;
			for (idx = 1; idx <= beneficiary->nested_depth; idx++)
				if (beneficiary->saved_priority[idx] == donator->donation_list[depth]){
					// pop한 빈칸 당겨서 매우기
				for (; idx < beneficiary->nested_depth; idx++){
					beneficiary->saved_priority[idx] = beneficiary->saved_priority[idx+1];
					beneficiary->saved_lock[idx] = beneficiary->saved_lock[idx+1];
				}
				beneficiary->nested_depth--;
				break;
			}
		}
	}
}

/* Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. */
bool
lock_try_acquire (struct lock *lock) {
	bool success;

	ASSERT (lock != NULL);
	ASSERT (!lock_held_by_current_thread (lock));

	success = sema_try_down (&lock->semaphore);
	if (success)
		lock->holder = thread_current ();
	return success;
}

/* Releases LOCK, which must be owned by the current thread.
   This is lock_release function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler. */
void
lock_release (struct lock *lock) {
	ASSERT (lock != NULL);
	ASSERT (lock_held_by_current_thread (lock));

	lock->holder = NULL;
	sema_up (&lock->semaphore);
	if (thread_current()->nested_depth != -1)		// donation받은값이 존재하는 경우 양보
		thread_yield();
}

/* Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool
lock_held_by_current_thread (const struct lock *lock) {
	ASSERT (lock != NULL);

	return lock->holder == thread_current ();
}

/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void
cond_init (struct condition *cond) {
	ASSERT (cond != NULL);

	list_init (&cond->waiters);
}

/* Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.

   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.

   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void
cond_wait (struct condition *cond, struct lock *lock) {
	struct semaphore_elem waiter;

	ASSERT (cond != NULL);
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (lock_held_by_current_thread (lock));
	sema_init (&waiter.semaphore, 0);
	list_insert_ordered(&cond->waiters, &waiter.elem, priority_larger, COND_LIST);		/* 우선순위 크기순으로 내림차순정렬 */
	lock_release (lock);
	sema_down (&waiter.semaphore);
	lock_acquire (lock);
}

/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_signal (struct condition *cond, struct lock *lock UNUSED) {
	ASSERT (cond != NULL);
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (lock_held_by_current_thread (lock));

	if (!list_empty (&cond->waiters))
		sema_up (&list_entry (list_pop_front (&cond->waiters),
					struct semaphore_elem, elem)->semaphore);
}

/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_broadcast (struct condition *cond, struct lock *lock) {
	ASSERT (cond != NULL);
	ASSERT (lock != NULL);

	while (!list_empty (&cond->waiters))
		cond_signal (cond, lock);
}

void print_list(struct list *ls, int id)
{	
	if (list_empty(ls))
		return;
	struct list_elem *start_elem = list_head(ls);
	struct thread *t;
	int i = 0;
	printf("--------id: %d ------- entry start ---------------------\n", id);
	while ((start_elem = list_next(start_elem)) != list_tail(ls)){
		t = list_entry(start_elem, struct thread, elem);
		printf("%d : %s priority %d \n", ++i, t->name, t->priority);
	}
	printf("---------------------- entry end ---------------------\n");
}

void printf_locks(struct lock *locks){
  printf("========================== lock list start =========================\n");
  for (int i = 0; i < 8 - 1; i++)
    print_list(&locks[i].semaphore.waiters, i);
  printf("========================== lock list end =========================\n");
}

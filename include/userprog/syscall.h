#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
void check_address(void *addr);
void syscall_entry(void);

extern struct lock filesys_lock;
extern void *stdin_ptr;
extern void *stdout_ptr;
extern void *stderr_ptr;

struct file_entry
{
	struct file *file;
	uint64_t ref_cnt;
	struct list_elem elem;
};
#endif /* userprog/syscall.h */

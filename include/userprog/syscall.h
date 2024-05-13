#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
void check_address(void *addr);
void syscall_entry(void);
extern struct lock filesys_lock;
extern void *stdin_ptr;
extern void *stdout_ptr;
extern void *stderr_ptr;

#define MAX_FETY 126 // 126

#endif /* userprog/syscall.h */

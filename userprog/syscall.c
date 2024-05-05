#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "lib/user/syscall.h"

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081			/* Segment selector msr */
#define MSR_LSTAR 0xc0000082		/* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

struct file_entry
{
	struct file *file;
	uint32_t refcnt;
};

void syscall_entry(void);
void syscall_handler(struct intr_frame *);
pid_t fork(const char *thread_name);
int exec(const char *file);
int wait(pid_t);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned length);
int write(int fd, const void *buffer, unsigned length);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
void check_address(void *addr);

void syscall_init(void)
{
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
							((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			  FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

void check_address(void *uaddr)
{
	struct thread *cur = thread_current();
	if (uaddr == NULL || is_kernel_vaddr(uaddr) || pml4_get_page(cur->pml4, uaddr) == NULL)
	{
		exit(-1);
	}
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED)
{
	int temp = f->R.rax;
	switch (temp)
	{
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(f->R.rdi);
		break;
	case SYS_FORK:
		break;
	case SYS_WAIT:
		break;

	case SYS_CREATE:
		create(f->R.rdi, f->R.rsi);
		break;
	case SYS_REMOVE:
		break;
	case SYS_OPEN:
		int fd = open(f->R.rdi);
		f->R.rax = fd;
		break;
	case SYS_FILESIZE:
		int size = filesize(f->R.rdi);
		f->R.rax = size;
		break;
	case SYS_READ:
		break;
	case SYS_WRITE:
		write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_SEEK:
		break;
	case SYS_TELL:
		break;
	case SYS_CLOSE:
		break;
	default:
		break;
	}
	// check_address(&f);
	//  TODO: Your implementation goes here.
}

void halt()
{
	power_off();
}

void exit(int status)
{

	printf("%s: exit(%d)\n", thread_current()->name, status);
	thread_exit();
}

pid_t fork(const char *thread_name)
{
	// thread_create(thread_name, );
}
int exec(const char *file);
int wait(pid_t);
bool create(const char *file, unsigned initial_size)
{
	check_address(file);
	bool success;
	success = filesys_create(file, initial_size);
	return success;
}
bool remove(const char *file)
{
	check_address(file);
	bool success;
	success = filesys_remove(file);
	return success;
}

int open(const char *file)
{
	check_address(file);
	struct file *entry = filesys_open(file);
	struct file_entry *file_table;
	file_table->file = entry;
	file_table->refcnt = 1;
	if (entry == NULL)
		return -1;
	struct thread *cur = thread_current();
	int fd = cur->fdt_index++;
	cur->fdt[fd] = file_table;
	return fd;
}

int filesize(int fd)
{
	struct thread *cur = thread_current();
	int length;
	length = file_length(cur->fdt[fd]->file);
	return length;
}
int read(int fd, void *buffer, unsigned length);
int write(int fd, const void *buffer, unsigned length)
{
	/* fd == 0 => stdin
	   fd == 1 => stdout
	   fd == 2 => stderr */
	check_address(buffer);
	switch (fd)
	{
	case 0:
		ASSERT(fd != 0)
		break;

	case 1: // stdout
	case 2: // stderr
		putbuf(buffer, length);
		break;

	default:
		break;
	}

	// unsigned write_byte = 0;
	// write_byte = memcpy(thread_current()->tf.rsp, buffer, length);
	// if (write_byte <= 0)
	// {
	// 	printf(" ERROR!!!! WRITE FAIL");
	// }
	// else
	// {
	// 	printf(" 작성에 성공한 바이트 숫자 = %d\n", write_byte);
	// }
}
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
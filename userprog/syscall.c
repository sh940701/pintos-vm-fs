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
#include "lib/string.h"
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "devices/disk.h"

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
#define MAX_STDOUT (1 << 9)
#define MAX_FD 192
#define GET_FILE_ETY(fdt, fd) (*((fdt) + (fd)))

/* system call */
struct lock filesys_lock;

/* An open file. */
struct file
{
	struct inode *inode; /* File's inode. */
	off_t pos;			 /* Current position. */
	bool deny_write;	 /* Has file_deny_write() been called? */
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
void copy_register(struct intr_frame *target, struct intr_frame *source);

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
	lock_init(&filesys_lock);
}


/* The main system call interface */
void syscall_handler(struct intr_frame *f)
{	
	int syscall = f->R.rax;
	if ((5 <= syscall) && (syscall <= 13))
		lock_acquire(&filesys_lock);
	switch (syscall)
	{
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(f->R.rdi);
		break;
	case SYS_FORK:
		enum intr_level old_level;
		old_level = intr_disable();
		copy_register(&thread_current()->tf, f); 
		bool succ_fork = fork(f->R.rdi);
		f->R.rax = succ_fork;
		intr_set_level(old_level);	
		break;
	case SYS_EXEC:
		break;
	case SYS_WAIT:
		pid_t pid = wait(f->R.rdi);
		f->R.rax = pid;
		break;
	case SYS_CREATE:
		bool succ = create(f->R.rdi, f->R.rsi);
		f->R.rax = succ;
		break;
	case SYS_REMOVE:
		bool succ_remove = remove(f->R.rdi);
		f->R.rax = succ_remove;
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
		int byte_read = read(f->R.rdi, f->R.rsi, f->R.rdx);
		f->R.rax = byte_read;
		break;
	case SYS_WRITE:
		int byte_written = write(f->R.rdi, f->R.rsi, f->R.rdx);
		f->R.rax = byte_written;
		break;
	case SYS_SEEK:
		seek(f->R.rdi, f->R.rsi);
		break;
	case SYS_TELL:
		int next_pos = tell(f->R.rdi);
		f->R.rax = next_pos;
		break;
	case SYS_CLOSE:
		close(f->R.rdi);
		break;
	default:
		printf("We don't implemented yet.");
		break;
	}
	if ((5 <= syscall) && (syscall <= 13))
		lock_release(&filesys_lock);
}
/*
 * 요청된 user 가상주소값이 1.NULL이 아닌지 2. kernel영역을 참조하는지
 * 3. 물리주소내에 mapping하는지 확인하여 위반하는경우 종료
 */
void check_address(void *uaddr)
{
	struct thread *cur = thread_current();
	if (uaddr == NULL || is_kernel_vaddr(uaddr) || pml4_get_page(cur->pml4, uaddr) == NULL)
		exit(-1);
}

void copy_register(struct intr_frame *target, struct intr_frame *source) 
{
	memcpy(&target->R.r15, &source->R.r15, sizeof(uint64_t));
	memcpy(&target->R.r14, &source->R.r14, sizeof(uint64_t));
	memcpy(&target->R.r13, &source->R.r13, sizeof(uint64_t));
	memcpy(&target->R.r12, &source->R.r12, sizeof(uint64_t));
	memcpy(&target->R.rbx, &source->R.rbx, sizeof(uint64_t));
	memcpy(&target->R.rbp, &source->R.rbp, sizeof(uint64_t));
	memcpy(&target->rsp, &source->rsp, sizeof(uintptr_t));
	memcpy(&target->rip, &source->rip, sizeof(uintptr_t));
}

void halt()
{
	power_off();
}

void exit(int status)
{
	struct thread *curr = thread_current();
	curr->exit_status = status;
	if (strcmp(curr->name, "main"))
		printf("%s: exit(%d)\n", curr->name, status);
	thread_exit();
}

pid_t fork(const char *thread_name)
{	
	check_address(thread_name);
	struct thread *parent = thread_current();
	pid_t tid = process_fork(thread_name);
	sema_down(&parent->fork_sema);
		
	if (parent->exit_status != 123456789)
		return TID_ERROR;
	return tid;
}

int exec(const char *file)
{

}

int wait(pid_t pid) {
	struct thread *child, *parent = thread_current();
	struct list *fl = &parent->fork_list;
	struct list_elem *start_elem;
	if (parent->exit_status != 123456789)	// 자식이 먼저 죽은 경우
		return parent->exit_status;

	// 자식을 찾음
	for (start_elem = list_begin(fl); start_elem != list_end(fl); start_elem = list_next(start_elem)) {
		child = list_entry(start_elem, struct thread, fork_elem);
		if (child->tid == pid) 
			break;
		
		if (start_elem == list_tail(fl))	// pid가 자식이 아닌 경우
			return -1;
	}
	sema_down(&parent->wait_sema);
	int temp = parent->exit_status;
	parent->exit_status = 123456789;
	return temp;
}

bool create(const char *file, unsigned initial_size)
{
	check_address(file);
	return filesys_create(file, initial_size);
}

bool remove(const char *file)
{
	check_address(file);
	return filesys_remove(file);
}

/*
 * 잘못된 파일 이름을 가지거나 disk에 파일이 없는경우 -1 반환.
 * thread 내에 file_entry ptr을 저장한 뒤, 표준입출력을 제외한 3부터 증가하는 fd 값을 반환.
 */
int open(const char *file)
{
	check_address(file);
	struct file *file_entity = filesys_open(file);
	if (file_entity == NULL) // wrong file name or not in disk (initialized from arg -p)
		return -1;

	// initialize
	struct thread *cur = thread_current();
	int fd;
	for (fd = 3; fd < MAX_FD; fd++)
	{
		if (GET_FILE_ETY(cur->fdt, fd) == NULL)
		{
			GET_FILE_ETY(cur->fdt, fd) = file_entity;
			cur->fdt_maxi = (cur->fdt_maxi < fd) ? fd : cur->fdt_maxi;
			break;
		}
		ASSERT(fd < MAX_FD);
	}
	return fd;
}

int filesize(int fd)
{
	struct thread *cur = thread_current();
	ASSERT((3 <= fd) && (fd < MAX_FD));

	return file_length(GET_FILE_ETY(cur->fdt, fd));
}

/*
 * fd값에 따라 읽은 만큼 byte(<=length)값 반환, 못 읽는 경우 -1, 읽을 지점이 파일의 끝인경우 0 반환
 * 참고 : disk read(file_read)와 intq_getc(input_getc)에 lock이 걸려있음
 */
int read(int fd, void *buffer, unsigned length)
{
	if ((fd < 0) || (fd >= MAX_FD))
		return -1;

	if (length == 0) // not read
		return 0;

	check_address(buffer);
	struct thread *cur = thread_current();
	int bytes_read = length;
	switch (fd)
	{
	case 0:
		uint8_t byte;
		while (length--)
		{
			byte = input_getc();	  // console 입력을 받아
			*(char *)buffer++ = byte; // 1byte씩 저장
		}
		break;
	case 1:
	case 2:
		return -1; // wrong fd

	default:

		if (GET_FILE_ETY(cur->fdt,fd) == NULL) // wrong fd
			return -1;

		struct file *cur_file = GET_FILE_ETY(cur->fdt, fd);
		if (cur_file->pos == inode_length(cur_file->inode)) // end of file
			return 0;

		if ((bytes_read = file_read(cur_file, buffer, length)) == 0) // could not read
			return -1;
		break;
	}
	return bytes_read;
}

/*
 * fd값에 따라 적은 만큼 byte(<=length)값 반환, 못 적는 경우 -1 반환
 * 참고 : disk write에 lock이 걸려있음
 */
int write(int fd, const void *buffer, unsigned length)
{
	if ((fd <= 0) || (fd >= MAX_FD)) // no bytes could be written at all
		return 0;

	/* fd == 0 => stdin, fd == 1 => stdout, fd == 2 => stderr */
	check_address(buffer);
	struct thread *cur = thread_current();
	int bytes_write = length;
	switch (fd)
	{
	case 1: // stdout: lock을 걸고 buffer 전체를 입력
		int iter_cnt = length / MAX_STDOUT + 1;
		int less_size;
		while (iter_cnt--)
		{ // 입력 buffer가 512보다 큰경우 slicing 해서 출력 (for test)
			less_size = (length > MAX_STDOUT) ? MAX_STDOUT : length;
			putbuf(buffer, less_size);
			buffer += less_size;
			length -= MAX_STDOUT;
		}
		break;

	case 2: // stderr: (stdout과 다르게 어떻게 해야할지 모르겠음)한글자씩 작성할때마다 lock이 걸림
		while (length-- > 0)
			putchar(buffer++);
		break;

	default: // file growth is not implemented by the basic file system
		if (GET_FILE_ETY(cur->fdt, fd) == NULL)
			return 0;

		struct file *cur_file = GET_FILE_ETY(cur->fdt, fd);
		bytes_write = file_write(cur_file, buffer, length);
		break;
	}
	return bytes_write;
}

/* 파일 크기가 넘어가는 position인 경우 write할 때 자동으로 0으로 채워지는지 확인해야됨*/
void seek(int fd, unsigned position)
{
	struct thread *cur = thread_current();
	ASSERT((3 <= fd) && (fd < MAX_FD));

	struct file *cur_file = GET_FILE_ETY(cur->fdt, fd);
	file_seek(cur_file, position);
}

unsigned tell(int fd)
{
	struct thread *cur = thread_current();
	ASSERT((3 <= fd) && (fd < MAX_FD));

	struct file *cur_file = GET_FILE_ETY(cur->fdt, fd);
	return file_tell(cur_file);
}

void close(int fd)
{
	struct thread *cur = thread_current();
	ASSERT(3 <= fd);
	if ((fd < 0) || (fd >= MAX_FD))
		return;

	struct file *cur_file = GET_FILE_ETY(cur->fdt, fd);
	if (cur_file == NULL)
		return;

	file_close(cur_file);
	free(cur_file);
	GET_FILE_ETY(cur->fdt, fd) = NULL;
}
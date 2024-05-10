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
#include "threads/palloc.h"

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
#define MAX_FD (1 << 9)			/* PGSIZE / sizeof(struct file) */

/* An open file. */
struct file
{
	struct inode *inode; /* File's inode. */
	off_t pos;			 /* Current position. */
	bool deny_write;	 /* Has file_deny_write() been called? */
};

/* if access to filesys.c, should sync */
struct lock filesys_lock;

/* system call */
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
int process_exec(void *f_name);
void syscall_handler(struct intr_frame *);
struct thread *find_child(pid_t pid, struct list *fork_list);

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
			memcpy(&thread_current()->temp_tf, f, sizeof(struct intr_frame));
			f->R.rax = fork(f->R.rdi);
			break;
		case SYS_EXEC:
			f->R.rax = exec(f->R.rdi);
			break;
		case SYS_WAIT:
			f->R.rax = wait(f->R.rdi);
			break;
		case SYS_CREATE:
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = remove(f->R.rdi);
			break;
		case SYS_OPEN:
			f->R.rax = open(f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
			break;
		case SYS_READ:
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL:
			f->R.rax = tell(f->R.rdi);
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

/* power_off로 kenel process(qemu)종료 */
void halt()
{
	power_off();
}

/* kernel이 종료한 경우를 제외하고 종료 메시지 출력 후 thread_exit() */
void exit(int status)
{
	struct thread *curr = thread_current();
	curr->exit_status = status;
	if (strcmp(curr->name, "main"))
		printf("%s: exit(%d)\n", curr->name, status);
	//printf("%s max fd : %d\n", thread_current()->name, thread_current()->fdt_maxfd);	
	thread_exit();
}

/* parent process의 pml4, intr_frame, fd copy 후 return tid 실패 시 return TID_ERROR */
pid_t fork(const char *thread_name)
{	
	check_address(thread_name);
	pid_t tid = process_fork(thread_name);
	if (tid == TID_ERROR)
		return TID_ERROR;

	sema_down(&thread_current()->fork_sema);		// 자식 fork완료전 대기
	if (find_child(tid, &thread_current()->fork_list) == NULL)	// __do_fork 실패한 경우
		return TID_ERROR;
	return tid;
}

/* 
 * file name을 parsing하여 해당 code를 적재한 intr_frame, pml4를 만들고 해당 process로 변경 
 * process 생성에 실패한 경우만 exit(-1) 실행, 반환값 없음
 */
int exec(const char *file)
{	
	check_address(file);
	char *fn_copy = palloc_get_page(0);
	if (fn_copy == NULL)
		return -1;
	strlcpy(fn_copy, file, PGSIZE);

	int exec_status;
	if ((exec_status = process_exec(fn_copy)) == -1)
		exit(-1);
	NOT_REACHED();
	return -1;
}

/* 
 * fork한 pid를 대기, fork한 process 존재하지 않는 경우 -1 return
 * fork한 process의 exit의 status return
 */
int wait(pid_t pid) 
{
	struct thread *child, *parent = thread_current();
	if ((child = find_child(pid, &parent->fork_list)) == NULL)
		return -1;

	sema_down(&child->wait_sema);
	list_remove(&child->fork_elem);
	child->fork_elem.prev = NULL;		
	int temp = child->exit_status;		// preemption
	sema_up(&child->fork_sema);
	return temp;
}

/* list를 traverse하며 pid를 가지는 thread return, 못찾으면 NULL return */
struct thread *find_child(pid_t pid, struct list *fork_list)
{	
	struct thread *child;
	struct list_elem *start_elem = list_head(fork_list);
	while ((start_elem = list_next(start_elem)) != list_tail(fork_list)) {
		child = list_entry(start_elem, struct thread, fork_elem);
		if (child->tid == pid) 
			return child;
	}
	return NULL;
}

/* initial_size의 file을 생성 후 성공여부 return, 이미 존재하거나 메모리 부족 시 fail */
bool create(const char *file, unsigned initial_size)
{
	check_address(file);
	return filesys_create(file, initial_size);
}

/* file을 삭제 후 성공여부 return, file이 없거나 inode 생성에 실패시 fail */
bool remove(const char *file)
{
	check_address(file);
	return filesys_remove(file);
}

/*
 * 잘못된 파일 이름을 가지거나 disk에 파일이 없거나 MAX_FD(512) 넘어가는 경우 -1 반환.
 * thread 내에 file_entry ptr을 저장한 뒤, 표준입출력을 제외한 3부터 증가하는 fd 값을 반환.
 */
int open(const char *file)
{
	check_address(file);
	struct file *file_entity = filesys_open(file);
	if (file_entity == NULL) 	// wrong file name or not in disk (initialized from arg -p)
		return -1;

	// initialize
	struct thread *cur = thread_current();
	int fd;
	for (fd = 3; fd < MAX_FD; fd++)
	{
		if (cur->fdt[fd] == NULL)
		{
			cur->fdt[fd] = file_entity;
			cur->fdt_maxfd = (cur->fdt_maxfd < fd) ? fd : cur->fdt_maxfd;
			return fd;
		}
	}
	free(file_entity);
	return -1;
}

/* fd에 해당하는 file의 크기 return */
int filesize(int fd)
{
	struct thread *cur = thread_current();
	ASSERT((3 <= fd) && (fd <= cur->fdt_maxfd));

	return file_length(cur->fdt[fd]);
}

/*
 * fd값에 따라 읽은 만큼 byte(<=length)값 반환, 못 읽는 경우 -1, 읽을 지점이 파일의 끝인경우 0 반환
 * 참고 : disk read(file_read)와 intq_getc(input_getc)에 lock이 걸려있음
 */
int read(int fd, void *buffer, unsigned length)
{
	struct thread *cur = thread_current();
	if ((fd < 0) || (fd > cur->fdt_maxfd))
		return -1;

	if (length == 0) // not read
		return 0;

	check_address(buffer);
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
		struct file *cur_file = cur->fdt[fd];
		if (cur_file == NULL) // wrong fd
			return -1;

		if (cur_file->pos == inode_length(cur_file->inode)) // end of file
			return 0;

		if ((bytes_read = file_read(cur_file, buffer, length)) == 0)  // could not read
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
	struct thread *cur = thread_current();	
	if ((fd <= 0) || (fd > cur->fdt_maxfd)) // no bytes could be written at all
		return 0;

	/* fd == 0 => stdin, fd == 1 => stdout, fd == 2 => stderr */
	check_address(buffer);
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
		struct file *cur_file = cur->fdt[fd];
		if (cur_file == NULL)
			return 0;

		bytes_write = file_write(cur_file, buffer, length);
		break;
	}
	return bytes_write;
}

/* 
 * 현재 파일의 읽는 pos를 변경
 * 참고 (inode size < position인 경우 write할 때 자동으로 0으로 채워지는지 확인) 
 */
void seek(int fd, unsigned position)
{
	struct thread *cur = thread_current();
	ASSERT((3 <= fd) && (fd <= cur->fdt_maxfd));

	file_seek(cur->fdt[fd], position);
}

/* 현재 파일을 읽는 위치 return */
unsigned tell(int fd)
{
	struct thread *cur = thread_current();
	ASSERT((3 <= fd) && (fd <= cur->fdt_maxfd));

	return file_tell(cur->fdt[fd]);
}

/* fd에 해당하는 file을 close, 이 후 fdt_maxi도 갱신 */
void close(int fd)
{
	struct thread *cur = thread_current();
	if ((fd < 0) || (fd > cur->fdt_maxfd))
		return;

	if (cur->fdt[fd] == NULL)
		return;

	file_close(cur->fdt[fd]);
	cur->fdt[fd] = NULL;

	while (--fd >2) {
		if (cur->fdt[fd] != NULL)
			cur->fdt_maxfd = fd;
			break;
	}
}
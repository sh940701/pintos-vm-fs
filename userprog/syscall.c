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
#define MAX_STDOUT 1<<9

#define GET_FILE_ETY(fdt, fd) (*((fdt) + fd))

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

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED)
{
	int syscall = f->R.rax;
	switch (syscall)
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
		bool succ = create(f->R.rdi, f->R.rsi);
		f->R.rax = succ;
		break;
	case SYS_REMOVE:
		bool succ = remove(f->R.rdi);
		f->R.rax = succ;
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
	struct file_entry *file_object = calloc(1, sizeof(file_entry));
	file_object->file = file_entity;
	file_object->refcnt = 1;			// for fork  
	if (file_entity == NULL)			// wrong file name or not in disk (initialized from arg -p)
		return -1;

	// initialize
	struct thread *cur = thread_current();
	int fd = ++cur->fdt_index;
	GET_FILE_ETY(cur->fdt, fd) = file_object;
	return fd;
}

int filesize(int fd)
{
	struct thread *cur = thread_current();
	ASSERT(3 <= fd);

	return file_length(GET_FILE_ETY(cur->fdt, fd)->file);
}

/* 
 * fd값에 따라 읽은 만큼 byte(<=length)값 반환, 못 읽는 경우 -1, 읽을 지점이 파일의 끝인경우 0 반환
 * 참고 : disk read(file_read)와 intq_getc(input_getc)에 lock이 걸려있음 
 */
int read(int fd, void *buffer, unsigned length)
{	
	check_address(buffer);
	struct thread *cur = thread_current();
	int bytes_read = length;	
	switch (fd)
	{	
		case 0:
			uint8_t byte;
			while (length--){
				byte = input_getc();			// console 입력을 받아
				*(char *)buffer++ = byte;		// 1byte씩 저장
			}
			break;
		case 1:
		case 2:		
			return -1;	// wrong fd 

		default:
			if (fd > cur->fdt_index)	// wrong fd 
				return -1;

			struct file *cur_file = GET_FILE_ETY(cur->fdt, fd)->file;	
			if (cur_file->pos == inode_length(cur_file->inode))		// end of file
				return 0;

			if ((bytes_read = file_read(cur_file, buffer, length)) == 0)	// could not read
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
	/* fd == 0 => stdin, fd == 1 => stdout, fd == 2 => stderr */
	check_address(buffer);
	struct thread *cur = thread_current();
	if (0 == fd)	// no bytes could be written at all
		return 0;

	int bytes_write = length;	
	switch (fd)
	{
		case 1: // stdout: lock을 걸고 buffer 전체를 입력
			uint8_t iter_cnt = length / MAX_STDOUT + 1;
			uint16_t less_size;
			while (iter_cnt--){			// 입력 buffer가 512보다 큰경우 slicing 해서 출력 (for test)
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

		default:	// file growth is not implemented by the basic file system
			struct file *cur_file = GET_FILE_ETY(cur->fdt, fd)->file;	
			bytes_write = file_write(cur_file, buffer, length);
			break;
	}
	return bytes_write;
}

/* 파일 크기가 넘어가는 position인 경우 write할 때 자동으로 0으로 채워지는지 확인해야됨*/
void seek(int fd, unsigned position)
{	
	struct thread *cur = thread_current();
	ASSERT(3 <= fd);

	struct file *cur_file = GET_FILE_ETY(cur->fdt, fd)->file;	
	file_seek(cur_file, position);
}

unsigned tell(int fd)
{
	struct thread *cur = thread_current();
	ASSERT(3 <= fd);

	struct file *cur_file = GET_FILE_ETY(cur->fdt, fd)->file;	
	return file_tell(cur_file);
}

void close(int fd)
{
	struct thread *cur = thread_current();
	ASSERT(3 <= fd);

	struct file_entry *cur_file_entry = GET_FILE_ETY(cur->fdt, fd);
	if (cur_file_entry->refcnt > 0)				// if fork
		cur_file_entry->refcnt--;
	else{
		file_close(cur_file_entry->file);
		free(cur_file_entry);
	}
}
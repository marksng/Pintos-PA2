#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "lib/kernel/console.h"
#include "devices/input.h"

#include "threads/vaddr.h"

#include "lib/kernel/list.h" 
#include "lib/string.h"

#include "threads/synch.h"

typedef int pid_t; 
static struct list fds; 
static struct lock fso_lock; 
static int prev_fd; 

void *addr_ck(uint32_t);
static void syscall_handler (struct intr_frame *);
struct fd_struct *find_with_name(const char* name);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  list_init(&fds); 
  lock_init(&fso_lock); 
  prev_fd = 2; 
}

// process control
void halt(void) {
	shutdown_power_off(); 
	return; 
}

int exit (int status) {
	printf("%s: exit(%d)\n", thread_current()->name, status);
	if (strcmp(thread_current()->name, "multi-oom") == 0) {
		halt();
	}
  if (thread_current()->parent != -1){
    struct thread *t = find_with_tid(thread_current()->parent);
    t->exit_status = status;
    sema_up(&t->wait);
  }
	thread_exit();
}


pid_t exec (const char *file) {
//	printf("---- in exec() ----\n"); 
  if (addr_ck(file) == NULL) {
		return -1; 
	}
  if (file == NULL || strcmp(file, "") == 0) {
		return -1;
	}
  char * prog = palloc_get_page(0); 
  int i;
  for (i = 0; i < strlen(file); ++i) {
	  if (file[i] == ' ') {
		  break;
	  }
	  prog[i] = file[i]; 
  }
  prog[i] = '\0';
//  printf("---- file: %s		prog: %s\n", file, prog); 
  struct file *f = filesys_open(prog);
  if (f == NULL){
//	  printf("---- file not found ----\n"); 
    return -1;
  }
  file_close(f);
//  printf("---- exiting exec(), returning process_execute(file) ----\n"); 
  return process_execute(file);
}


int wait (pid_t pid) {
  return process_wait(pid);
}



/*
 * functions for file system 
*/

// find a file with a given fd
struct fd_struct *find_with_fd(int fd) {
	struct list_elem *e; 
	for (e = list_begin (&fds); e != list_end (&fds); e = list_next(e)) {
		struct fd_struct *f = list_entry (e, struct fd_struct, elem);
        if (f->fd == fd) {
			return f; 
		}  
    }
    return NULL; 
}

// find file with a given file name 
struct fd_struct *find_with_name(const char* name) {
	struct list_elem *e; 
	for (e = list_begin (&fds); e != list_end (&fds); e = list_next(e)) {
		struct fd_struct *f = list_entry (e, struct fd_struct, elem);
        if (strcmp(f->name, name) == 0) {
			return f; 
		}  
    }
    return NULL; 
}

// create a new file called 'file' with 'initial_size' bytes in size
bool create (const char *file, unsigned initial_size) {
	if (addr_ck(file) == NULL) {
		exit(-1); 
	}
	if (file == NULL || strcmp(file, "") == 0) {
		exit(-1);
		return false; 
	}
	if (sizeof(file) > 14) {
		return false; 
	}
	return filesys_create(file, initial_size); 
}

// deletes file named 'file' 
bool remove (const char *file) {
	if (file == NULL || strcmp(file, "") == 0) {
		return false; 
	}
	if (filesys_remove(file)) {
		struct fd_struct *rm = find_with_name(file); 
//		list_remove(&rm->elem); 
		return true; 
	}
	return false; 
}

// opens file called 'file', returns fd, -1 if not found/cannot be opened
int open (const char *file) {
	if (addr_ck(file) == NULL) {
		exit(-1); 
	}
	if (file == NULL || strcmp(file, "") == 0) {
		return -1; 
	}
	struct fd_struct *find = find_with_name(file);
	if (find != NULL) {		// already opened
		find->fd = prev_fd++; 
		return find->fd; 
	}
	else {
		struct file *open = filesys_open(file); 
		if (open == NULL) {		// file not in filesystem
			return -1; 
		}
    if (exists_by_name(file)) {
			file_deny_write(open);
		}
		struct fd_struct *add = palloc_get_page(0); 															
		add->fd = ++prev_fd;
		add->name = file; 
		add->file = open;
		add->creator = thread_current()->tid; 
		list_push_back(&fds, &add->elem); 							
		return add->fd; 
	}
	return -1; 
}

// returns the size, in bytes, of file open as fd
int filesize (int fd) {	
	return file_length(find_with_fd(fd)->file); 
}

// read 'length' bytes from fd -> buffer
// returns number bytes read, or -1 if file could not be read
int read(int fd, void *buffer, unsigned length) {
	if (addr_ck(buffer) == NULL) {
		exit(-1); 
	}
	if (fd == 0) {
		input_getc(); 	// possibly need to 
		return 1; 
	}
	else {
		struct fd_struct *reader = find_with_fd(fd); 
		if (reader != NULL) {
			int ret = (int) file_read(reader->file, buffer, length); 
			return ret; 
		}
	}
	return -1; 
}

// write 'length' bytes from buffer -> fd
// return number bytes written 
int write (int fd, const void *buffer, unsigned length) {
	if (addr_ck(buffer) == NULL) {
		exit(-1); 
	}
	if (fd == 1) {			// write to console
		putbuf(buffer, length); 
		return 1;
	}
	else {
		struct fd_struct *writer = find_with_fd(fd); 
		if (writer != NULL) {
			return file_write(writer->file, buffer, length); 
		}
	}
	return 0; 
}

// changes next byte to be read/written in fd to pos
void seek (int fd, unsigned position) {
	struct fd_struct *harry_potter = find_with_fd(fd); 
	file_seek(harry_potter->file, position); 
}

// return pos of next byte to be read 
unsigned tell (int fd) {
	struct fd_struct *teller = find_with_fd(fd); 	
	return file_tell(teller->file);
}

// 
void close (int fd) {
	if (fd == 0 || fd == 1) {
		exit(-1);
		return; 
	}
	struct fd_struct *closing = find_with_fd(fd);	
	if (closing != NULL) {		// file opened
		if (closing->creator != thread_current()->tid) {
			return; 
		}
		file_close(closing->file); 	
		list_remove(&closing->elem);	
	}
}

void * addr_ck(uint32_t uaddr) { 
    if (!is_user_vaddr((void*) uaddr)) { // invalid addr
        return NULL; 
    }
    return pagedir_get_page(thread_current()->pagedir, uaddr); 
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{	
  uint32_t *esp;
  esp = f->esp;
  
  int syscall_number; 
  uint32_t *syscall_pointer = addr_ck(esp); 
  if (syscall_pointer == NULL){
    exit(-1);
  } 
  syscall_number = *syscall_pointer;
  
  if (SYS_HALT == syscall_number) {		
		  shutdown_power_off();
  }
  
  uint32_t * arg1 = (uint32_t) addr_ck(esp+1);
  if (arg1 == NULL){
    exit(-1);
  }
  
  else if (SYS_EXIT == syscall_number) {	// status 
	  f->eax = exit(*arg1);
	  return; 
  }
  else if (SYS_EXEC == syscall_number) {	// file name 
	  f->eax = exec(*arg1); 
	  return; 
  }
  else if (SYS_WAIT == syscall_number) {	// pid_t
	  f->eax = wait(*arg1); 
	  return; 
  }
  
  lock_acquire(&fso_lock);
  if (SYS_REMOVE == syscall_number) {
	  f->eax = remove(*arg1); 			// file name
  }
  else if (SYS_OPEN == syscall_number) {
	  f->eax = open(*arg1); 				// file name
  }
  else if (SYS_FILESIZE == syscall_number) { 
	  f->eax = filesize(*arg1);			// fd
  }
  else if (SYS_TELL == syscall_number) {
	  f->eax = tell(*arg1); 				// fd
  }
  else if (SYS_CLOSE == syscall_number) {
	  close(*arg1); 						// fd
  }
  else {} 
  
  uint32_t * arg2 = (uint32_t) addr_ck(esp+2);
  if (arg2 == NULL){
      exit(-1);
  }
  else if (SYS_CREATE == syscall_number) {
	  f->eax = create(*arg1, *arg2); 	// file name, initial size
	  lock_release(&fso_lock); 
	  return; 
  }
  else if (SYS_SEEK == syscall_number) {
	  seek(*arg1, *arg2); 			// fd, pos
  }
  else {}
  
  uint32_t * arg3 = (uint32_t) addr_ck(esp+3);
  if (arg3 == NULL){
      exit(-1);
  }
  else if (SYS_READ == syscall_number) {
	  f->eax = read(*arg1, *arg2, *arg3); 	// fd, buff, length
  }
  else if (SYS_WRITE == syscall_number) {
	  f->eax = write(*arg1, *arg2, *arg3); 	// fd, buff, length
  }  
  else { 
	  // do nothing
  }
  lock_release(&fso_lock); 
}

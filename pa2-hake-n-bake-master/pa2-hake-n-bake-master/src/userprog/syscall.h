#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "../filesys/file.h"
#include "lib/kernel/list.h"

typedef int tid_t;
void syscall_init (void);
int exit(int);

struct fd_struct {
	int fd; 					// file descriptor for file
	char *name; 				// file
	struct file *file;
	struct list_elem elem; 		// list elem
	struct list threads; 
	tid_t creator; 
	
};

#endif /* userprog/syscall.h */

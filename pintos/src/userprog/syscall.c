#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "list.h"
#include "process.h"

static void syscall_handler (struct intr_frame *);
void* check_address(const void *);
struct proc_file * list_search(struct list * files, int fd);

extern bool running;

struct proc_file
{
  struct file * ptr;
  int fd;
  struct list_elem elem;
};

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f)
{

  int * stack_ptr = f->esp;

  check_address(stack_ptr);

  int system_call = *stack_ptr;
  stack_ptr++;
  switch(system_call)
  {
    case SYS_HALT:
      shutdown_power_off();
      break;

    case SYS_EXIT:
      check_address(stack_ptr);
      exit_proc(*(stack_ptr));
      break;

    case SYS_EXEC:
      // Check to make sure that address space is valid before executing
      check_address(stack_ptr);
      check_address(*(stack_ptr));
      f -> eax = exec_proc(*(stack_ptr));
      break;

    case SYS_WAIT:
      check_address(stack_ptr);
      f -> eax = process_wait(*(stack_ptr));
      break;

    case SYS_CREATE:
      check_address(stack_ptr + 5);
      check_address(*(stack_ptr + 4));
      acquire_filesys_lock();
      f -> eax = filesys_create(*(stack_ptr + 4), *(stack_ptr + 5));
      release_filesys_lock();
      break;

    SYS_REMOVE:
      check_address(stack_ptr);
      check_address(*(stack_ptr));
      acquire_filesys_lock();
      if(filesys_remove(*(stack_ptr)) == NULL)
      {
        f -> eax = false;
      }
      else
      {
        f -> eax = true;
      }
      release_filesys_lock();
      break;

    case SYS_OPEN:
      check_address(stack_ptr);
      check_address(*(stack_ptr));
      acquire_filesys_lock();
      struct file * file_ptr = filesys_open(*(stack_ptr));
      release_filesys_lock();
      if(file_ptr == NULL)
      {
        f -> eax = -1;
      }
      else
      {
        struct proc_file * proc_file = malloc(sizeof(*proc_file));
        proc_file -> ptr = file_ptr;
        proc_file -> fd = thread_current() -> fd_count;
        thread_current() -> fd_count++;
        list_push_back(&thread_current() -> files, &proc_file -> elem);
        f -> eax = proc_file -> fd;
      }
      break;

    case SYS_FILESIZE:
      check_address(stack_ptr);
      acquire_filesys_lock();
      f -> eax = file_length(list_search(&thread_current() -> files, *(stack_ptr)) -> ptr);
      release_filesys_lock();
      break;

    case SYS_READ:
      check_address(stack_ptr + 7);
      check_address(*(stack_ptr + 6));
      if(*(stack_ptr + 5) == 0)
      {
        uint8_t * buffer = *(stack_ptr + 6);
        for(int i = 0; i < *(stack_ptr + 7); i++)
        {
          buffer[i] = input_getc();
        }
        f -> eax = *(stack_ptr + 7);
      }
      else
      {
        struct proc_file * proc_file_ptr = list_search(&thread_current() -> files, *(stack_ptr + 5));
        if(proc_file_ptr == NULL)
        {
          f -> eax = -1;
        }
        else
        {
          acquire_filesys_lock();
          f -> eax = file_read(proc_file_ptr -> ptr, *(stack_ptr + 6), *(stack_ptr + 7));
          release_filesys_lock();
        }
      }
      break;

    case SYS_WRITE:
      check_address(stack_ptr + 7);
      check_address(*(stack_ptr + 6));
      if(*(stack_ptr + 5) == 1)
      {
        putbuf(*(stack_ptr + 6), *(stack_ptr + 7));
        f -> eax = *(stack_ptr + 7);
      }
      else
      {
        struct proc_file * proc_file_ptr = list_search(&thread_current() -> files, *(stack_ptr + 5));
        if(proc_file_ptr == NULL)
        {
          f -> eax = -1;
        }
        else
        {
          acquire_filesys_lock();
          f -> eax = file_write(proc_file_ptr -> ptr, *(stack_ptr + 6), *(stack_ptr + 7));
          release_filesys_lock();
        }
      }
      break;

    case SYS_SEEK:
      check_address(stack_ptr + 5);
      acquire_filesys_lock();
      file_seek(list_search(&thread_current() -> files, *(stack_ptr + 4)) -> ptr, *(stack_ptr + 5));
      release_filesys_lock();
      break;

    case SYS_TELL:
      check_address(stack_ptr);
      acquire_filesys_lock();
      f -> eax = file_tell(list_search(&thread_current() -> files, *(stack_ptr + 1)) -> ptr);
      release_filesys_lock();
      break;

    case SYS_CLOSE:
      check_address(stack_ptr);
      acquire_filesys_lock();
      close_file(&thread_current() -> files, *(stack_ptr));
      release_filesys_lock();
      break;

  }
}
void * check_address(const void * vaddr)
{
  // if address isn't valid in user memory
  if(!is_user_vaddr(vaddr))
  {
    exit_proc(-1);
    return 0;
  }
  void * page_ptr = pagedir_get_page(thread_current() -> pagedir, vaddr);
  // if address doesn't have a valid page
  if(!page_ptr)
  {
    exit_proc(-1);
    return 0;
  }
  return page_ptr;
}


int exec_proc(char * file_name)
{
  acquire_filesys_lock();
  char * file_name_cpy = malloc(strlen(file_name) + 1);
  strlcpy(file_name_cpy, file_name, strlen(file_name) + 1);

  char * token_ptr;
  file_name_cpy = strtok_r(file_name_cpy, " ", &token_ptr);
  struct file * file = filesys_open(file_name_cpy);

  // if the user process if not valid
  if(file == NULL)
  {
    release_filesys_lock();
    return -1;
  }
  else
  {
      file_close(file);
      release_filesys_lock();
      return process_execute(file_name);
  }
}

void exit_proc(int exit_code)
{
  struct list_elem *current_elem;

  for(current_elem = list_begin(&thread_current()->parent->child_proc); current_elem != list_end(&thread_current()->parent->child_proc); current_elem = list_next(current_elem))
  {
    struct child *child_procedure = list_entry(current_elem, struct child, elem);
    if(child_procedure->tid == thread_current()->tid)
    {
      child_procedure->used = true;
      child_procedure->exit_code = exit_code;
    }
  }

  thread_current()->exit_code = exit_code;

  if(thread_current()-> parent ->waiting_tid == thread_current()->tid)
  {
    sema_up(&thread_current()->parent->child_lock);
  }
  thread_exit();
}

struct proc_file* list_search(struct list* files, int fd)
{
    struct list_elem *current_elem;

    for(current_elem = list_begin(files); current_elem != list_end(files); current_elem = list_next(current_elem))
    {
      struct proc_file *file = list_entry(current_elem, struct proc_file, elem);
      if(file->fd == fd)
      {
        return file;
      }
    }
    return NULL;
}

void close_file (struct list* files, int fd)
{
    struct list_elem *current_elem;
    struct proc_file *file = NULL;

    for(current_elem = list_begin(files); current_elem != list_end(files); current_elem = list_next(current_elem))
    {
      file = list_entry(current_elem, struct proc_file, elem);
      if(file->fd == fd)
      {
         file_close(file->ptr);
         list_remove(current_elem);
      }
    }
    free(file);
}

void close_all_files(struct list* files)
{
   struct list_elem *current_elem;

   while(!list_empty(files))
   {
     current_elem = list_pop_front(files);

     struct proc_file *file = list_entry(current_elem, struct proc_file, elem);

     file_close(file->ptr);
     list_remove(current_elem);
     free(file);
   }
}

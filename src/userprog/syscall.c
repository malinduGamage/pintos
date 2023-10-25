#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "process.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "userprog/process.h"
#include "devices/input.h"

static void syscall_handler (struct intr_frame *);

static bool is_valid_pointer (const void *pointer);
//system call functions
static void halt(void);
static void exit(int status);
static pid_t exec(const char *cmd_line);
static int wait (pid_t pid);
static bool create (const char *file, unsigned initial_size);
static bool remove (const char *file);
static int open (const char *file);
static int filesize (int fd);
static int read (int fd, void *buffer, unsigned size);
static int write (int fd, const void *buffer, unsigned size);
static void seek (int fd, unsigned position);
static unsigned tell (int fd);
static void close (int fd);

static bool
is_valid_pointer (const void *pointer)
{
    struct thread *t = thread_current ();

    if (pointer == NULL)
        return false;
    if (is_kernel_vaddr (pointer))
        return false;
    if (pagedir_get_page (t->pagedir, pointer) == NULL)
        return false;

    return true;
}

/* for getting a thread's opened file by its descriptor */
static struct openfile *
getFile (int fd)
{
    struct thread *td = thread_current ();
    struct list_elem *e;
    for (e = list_begin (&td->openfiles); e != list_end (&td->openfiles);
         e = list_next (e))
    {
        struct openfile *opnfl = list_entry (e, struct openfile, elem);
        if(opnfl->fd == fd)
            return opnfl;
    }
    return NULL;
}

void
syscall_init (void) 
{
    lock_init (&filesys_lock);
    intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
    void *esp = f->esp;
    uint32_t *eax = &f->eax;
    int syscall_num;

    int status,fd;
    const char *cmd_line;
    pid_t pid;
    char *file;
    const void *buffer;
    unsigned size;

    if(!is_valid_pointer( ((int *) esp) ) || !is_valid_pointer( ((int *) esp)+1 ) || !is_valid_pointer( ((int *) esp)+2 ))
        exit (-1);

    int syscall_number = *((int *) esp);

    switch (syscall_number) {
        case SYS_HALT:
            halt();
            break;
        case SYS_EXIT:
            status = *(((int *) esp) + 1);
            exit (status);
            break;
        case SYS_EXEC:
            cmd_line = *(((char **) esp) + 1);
            *eax = (uint32_t) exec (cmd_line);
            break;
        case SYS_WAIT:
            pid = *(((pid_t *) esp) + 1);
            *eax = (uint32_t) wait (pid);
            break;
        case SYS_CREATE:
            file = *(((char **) esp) + 1);
            unsigned initial_size = *(((unsigned *) esp) + 2);
            *eax = (uint32_t) create (file, initial_size);
            break;
        case SYS_REMOVE:
            file = *(((char **) esp) + 1);
            *eax = (uint32_t) remove (file);
            break;
        case SYS_OPEN:
            file = *(((char **) esp) + 1);
            *eax = (uint32_t) open (file);
            break;
        case SYS_FILESIZE:
            fd = *(((int *) esp) + 1);
            *eax = (uint32_t) filesize (fd);
            break;
        case SYS_READ:
            fd = *(((int *) esp) + 1);
            void *buffer = (void *) *(((int **) esp) + 2);
            unsigned size = *(((unsigned *) esp) + 3);
            *eax = (uint32_t)read (fd, buffer, size);
            break;
        case SYS_WRITE:
            fd = *(((int *) esp) + 1);
            buffer = (void *) *(((int **) esp) + 2);
            size = *(((unsigned *) esp) + 3);
            *eax = (uint32_t) write (fd, buffer, size);
            break;
        case SYS_SEEK:
            fd = *(((int *) esp) + 1);
            unsigned position = *(((unsigned *) esp) + 2);
            seek (fd, position);
            break;
        case SYS_TELL:
            fd = *(((int *) esp) + 1);
            *eax = (uint32_t) tell (fd);
            break;
        case SYS_CLOSE:
            fd = *(((int *) esp) + 1);
            close (fd);
            return;
        default:
            break;
    }
    thread_exit ();
}


static void
halt(void)
{
    shutdown_power_off();
}

static void
exit(int status)
{
    struct thread *cur = thread_current ();
    cur->exit_status = status;
    thread_exit ();
}

static pid_t
exec(const char *cmd_line)
{
    tid_t child_tid = TID_ERROR;

    if(!is_valid_pointer(cmd_line))
        exit (-1);

    child_tid = process_execute (cmd_line);

    return child_tid;
}

static int
wait (pid_t pid)
{
    return process_wait(pid);
}

static bool
create (const char *file, unsigned initial_size)
{
    bool retval;
    if(is_valid_pointer(file)) {
        lock_acquire (&filesys_lock);
        retval = filesys_create (file, initial_size);
        lock_release (&filesys_lock);
        return retval;
    }
    else
        exit (-1);

    return false;
}

static bool
remove (const char *file)
{
    bool return_val;
    if(is_valid_pointer(file)) {
        lock_acquire (&filesys_lock);
        return_val = filesys_remove (file);
        lock_release (&filesys_lock);
        return return_val;
    }
    else
        exit (-1);

    return false;
}

static int
open (const char *file)
{
    if(is_valid_pointer((void *) file)) {
        struct openfile *new = palloc_get_page (0);
        new->fd = thread_current ()->next_fd;
        thread_current ()->next_fd++;
        lock_acquire (&filesys_lock);
        new->file = filesys_open(file);
        lock_release (&filesys_lock);
        if (new->file == NULL)
            return -1;
        list_push_back(&thread_current ()->openfiles, &new->elem);
        return new->fd;
    }
    else
        exit (-1);

    return -1;
}

static int
filesize (int fd)
{
    int retval;
    struct openfile *of = NULL;
    of = getFile (fd);
    if (of == NULL)
        return 0;
    lock_acquire (&filesys_lock);
    retval = file_length (of->file);
    lock_release (&filesys_lock);
    return retval;
}

static int
read (int fd, void *buffer, unsigned size)
{
    int bytes_read = 0;
    char *bufChar = NULL;
    struct openfile *of = NULL;
    if (!is_valid_pointer(buffer))
        exit (-1);
    bufChar = (char *)buffer;
    if(fd == 0) {
        while(size > 0) {
            input_getc();
            size--;
            bytes_read++;
        }
        return bytes_read;
    }
    else {
        of = getFile (fd);
        if (of == NULL)
            return -1;
        lock_acquire (&filesys_lock);
        bytes_read = file_read (of->file, buffer, size);
        lock_release (&filesys_lock);
        return bytes_read;
    }
}

static int
write (int fd, const void *buffer, unsigned size)
{
    int bytes_written = 0;
    char *bufChar = NULL;
    struct openfile *of = NULL;
    if (!is_valid_pointer(buffer))
        exit (-1);
    bufChar = (char *)buffer;
    if(fd == 1) {
        /* break up large buffers */
        while(size > 200) {
            putbuf(bufChar, 200);
            bufChar += 200;
            size -= 200;
            bytes_written += 200;
        }
        putbuf(bufChar, size);
        bytes_written += size;
        return bytes_written;
    }
    else {
        of = getFile (fd);
        if (of == NULL)
            return 0;
        lock_acquire (&filesys_lock);
        bytes_written = file_write (of->file, buffer, size);
        lock_release (&filesys_lock);
        return bytes_written;
    }
}

static void
seek (int fd, unsigned position)
{
    struct openfile *of = NULL;
    of = getFile (fd);
    if (of == NULL)
        return;
    lock_acquire (&filesys_lock);
    file_seek (of->file, position);
    lock_release (&filesys_lock);

}

static unsigned
tell (int fd)
{
    unsigned retval;
    struct openfile *of = NULL;
    of = getFile (fd);
    if (of == NULL)
        return 0;
    lock_acquire (&filesys_lock);
    retval = file_tell (of->file);
    lock_release (&filesys_lock);
    return retval;
}

static void
close (int fd)
{
    struct openfile *of = NULL;
    of = getFile (fd);
    if (of == NULL)
        return;
    lock_acquire (&filesys_lock);
    file_close (of->file);
    lock_release (&filesys_lock);
    list_remove (&of->elem);
    palloc_free_page (of);
}

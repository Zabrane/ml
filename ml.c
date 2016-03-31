#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/mach_init.h>
#include <mach/mach_error.h>
#include <mach/thread_status.h>
#include <mach/i386/thread_status.h>
#include <architecture/i386/table.h>
#include <i386/user_ldt.h>
#include <mach/vm_region.h>
#include <mach/exception.h>
#include <mach/task.h>
#include <sys/utsname.h>
#include <sys/event.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sandbox.h>
#include <pthread.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>

#define CHECK_MACH_ERROR(err,s) if(err!=KERN_SUCCESS){fputs(s,stderr);fputs(mach_error_string(err),stderr);fputc('\n',stderr);exit(1);}

vm_size_t page_size = 4096;
static char *argv_location;

static int setup_recv_port (mach_port_t *recv_port)
{
    kern_return_t       err;
    mach_port_t         port = MACH_PORT_NULL;
    err = mach_port_allocate (mach_task_self (),
                              MACH_PORT_RIGHT_RECEIVE, &port);
    CHECK_MACH_ERROR (err, "mach_port_allocate failed:");

    err = mach_port_insert_right (mach_task_self (),
                                  port,
                                  port,
                                  MACH_MSG_TYPE_MAKE_SEND);
    CHECK_MACH_ERROR (err, "mach_port_insert_right failed:");

    *recv_port = port;
    return 0;
}

static int send_port (mach_port_t remote_port, mach_port_t port)
{
    kern_return_t       err;

    struct {
        mach_msg_header_t          header;
        mach_msg_body_t            body;
        mach_msg_port_descriptor_t task_port;
    } msg;

    msg.header.msgh_remote_port = remote_port;
    msg.header.msgh_local_port = MACH_PORT_NULL;
    msg.header.msgh_bits = MACH_MSGH_BITS (MACH_MSG_TYPE_COPY_SEND, 0) |
        MACH_MSGH_BITS_COMPLEX;
    msg.header.msgh_size = sizeof msg;

    msg.body.msgh_descriptor_count = 1;
    msg.task_port.name = port;
    msg.task_port.disposition = MACH_MSG_TYPE_COPY_SEND;
    msg.task_port.type = MACH_MSG_PORT_DESCRIPTOR;

    err = mach_msg_send (&msg.header);
    CHECK_MACH_ERROR (err, "mach_msg_send failed:");

    return 0;
}

static int recv_port (mach_port_t recv_port, mach_port_t *port)
{
    kern_return_t       err;
    struct {
        mach_msg_header_t          header;
        mach_msg_body_t            body;
        mach_msg_port_descriptor_t task_port;
        mach_msg_trailer_t         trailer;
    } msg;

    err = mach_msg (&msg.header, MACH_RCV_MSG,
                    0, sizeof msg, recv_port,
                    MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    CHECK_MACH_ERROR (err, "mach_msg failed:");

    *port = msg.task_port.name;
    return 0;
}

static task_t       child_task = MACH_PORT_NULL;
static mach_port_t exception_port = MACH_PORT_NULL;

static pid_t fork_osx(void)
{
    kern_return_t       err;
    mach_port_t         parent_recv_port = MACH_PORT_NULL;
    mach_port_t         child_recv_port = MACH_PORT_NULL;
    char                *errmsg = 0;

    if (setup_recv_port (&parent_recv_port) != 0)
        return -1;
    err = task_set_bootstrap_port (mach_task_self (), parent_recv_port);
    CHECK_MACH_ERROR (err, "task_set_bootstrap_port failed:");

    pid_t               pid;
    switch (pid = fork ()) {
    case -1:
        err = mach_port_deallocate (mach_task_self(), parent_recv_port);
        CHECK_MACH_ERROR (err, "mach_port_deallocate failed:");
        break;
    case 0: /* child */
        err = task_get_bootstrap_port (mach_task_self (), &parent_recv_port);
        CHECK_MACH_ERROR (err, "task_get_bootstrap_port failed:");
        if (setup_recv_port (&child_recv_port) != 0) abort();
        if (send_port (parent_recv_port, mach_task_self ()) != 0) abort();
        if (send_port (parent_recv_port, child_recv_port) != 0) abort();
        if (recv_port (child_recv_port, &exception_port) != 0) abort(); /* in case we want to fork again */
        if (recv_port (child_recv_port, &bootstrap_port) != 0) abort();
        if (task_set_bootstrap_port (mach_task_self (), bootstrap_port) != MACH_MSG_SUCCESS) abort();
        break;
    default: /* parent */
        err = task_set_bootstrap_port (mach_task_self (), bootstrap_port);
        CHECK_MACH_ERROR (err, "task_set_bootstrap_port failed:");

        if (recv_port (parent_recv_port, &child_task) != 0) abort();
        if (recv_port (parent_recv_port, &child_recv_port) != 0) abort();

        err = task_set_exception_ports(child_task, EXC_MASK_SYSCALL | EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION, exception_port, EXCEPTION_STATE_IDENTITY, x86_THREAD_STATE);
        CHECK_MACH_ERROR (err, "task_set_exception_ports failed:");

        if (send_port (child_recv_port, exception_port) != 0) abort(); 
        if (send_port (child_recv_port, bootstrap_port) != 0) abort();

        err = mach_port_deallocate (mach_task_self(), parent_recv_port);
        CHECK_MACH_ERROR (err, "mach_port_deallocate failed:");
        break;
    }

    return pid;
}

void *get_untilzero_from_user(task_t task, long long vaddr, int extra, int width, int zeros, int steps)
{
    char              *laddr;
    mach_vm_address_t   addr = 0;
    char              *result;
    vm_prot_t          cur_prot;
    vm_prot_t          max_prot;

    if(KERN_SUCCESS != mach_vm_remap(mach_task_self(),&addr,page_size,0,TRUE,task,vaddr&~(page_size-1),1,&cur_prot,&max_prot,VM_INHERIT_NONE)) return 0;

    laddr = (char*)addr; /* because it's this process */

    int start = (vaddr & (page_size-1)), pos = start;

    for (;pos < page_size; ++pos) {
      if(!laddr[pos]) ++zeros; ++steps;
      if(zeros == width) {
        result = malloc(extra + 1 + (pos - start));
        if(!result) abort();
        memcpy(result + extra, laddr + start, 1+(pos - start));
        goto done;
      }
      if(steps == width) steps = zeros = 0;
    }
    /* overlaps page boundary */
    result = get_untilzero_from_user(task, page_size+(vaddr & ~(page_size-1)), extra + (page_size-start), width, zeros, steps);
    memcpy(result + extra, laddr + start, page_size - start);
done:
    if(KERN_SUCCESS != mach_vm_deallocate(mach_task_self(),addr,page_size)) abort();
    return result;
}

char *get_cstring_from_user(task_t task, long long vaddr)
{
    return get_untilzero_from_user(task, vaddr, 0, sizeof(char), 0,0);
}
char**get_argv_from_user(task_t task, long long vaddr, long long *argc)
{
    union {
        long long vaddr;
        char *result;
    } *d;
    int i;

    d = get_untilzero_from_user(task, vaddr, 0, sizeof(long long), 0,0);
    if(!d) return 0;

    for(i = 0; d[i].vaddr; ++i)
        d[i].result = get_cstring_from_user(task, d[i].vaddr);
    if(argc) *argc = i;

    return (char**)d;
}

struct extra_task_info {
    task_t t;
    struct extra_task_info *next;

    pthread_mutex_t lock;

    pid_t pid;
    pid_t fake_ppid;

    mach_vm_address_t brk_low;
    mach_vm_address_t brk_high;

    /* points at the TLS sections */
    mach_vm_address_t tls_base;
    mach_vm_size_t tls_size;
};

static struct extra_task_info *task_table[31] = {0};
static pthread_mutex_t task_table_lock = PTHREAD_MUTEX_INITIALIZER;


struct extra_task_info *get_extra_task_info(task_t t)
{
    struct extra_task_info *p, *lp;

    /* task_t is an integral type */
    unsigned char b[16];memcpy(b + (sizeof(t) > 16 ? sizeof(t)-16 : 0), &t, sizeof(t) > 16 ? 16 : sizeof(t));
    for(int i=1;i<sizeof(t);++i)*b ^= b[i];
    unsigned int hash = 31 & *b;

    pthread_mutex_lock(&task_table_lock);
    for(lp = 0, p=task_table[hash]; p; p = p->next) {
        if(p->t == t) {
            if(lp) lp->next = p->next;
            p->next = task_table[hash]; //move to head
            break;
        }
        lp = p;
    }
    if(!p) {
        p = task_table[hash] = valloc(sizeof(struct extra_task_info *));
        p->t = t; p->next = task_table[hash];
        pthread_mutex_init(&p->lock, NULL);
    }
    pthread_mutex_unlock(&task_table_lock);
    return p;
}


kern_return_t catch_exception_raise_state_identity(
        mach_port_name_t exception_port, mach_port_t thread, mach_port_t task,
        int exception, exception_data_t code, mach_msg_type_number_t codeCnt,
        int*flavor, thread_state_t state, int stateCnt, 
        thread_state_t new_state, int *new_stateCnt)
{
    static mach_vm_address_t original_rsp = 0;

    kern_return_t       err;
    x86_thread_state_t *r = (void*)state;
#define R(x)  (r->uts.ts64.__ ## x)
#define TC(n) do{R(rax)=0x2000000|SYS_ ## n;R(rip)-=2;}while(0)
#define PUSH(x,y) ({ mach_msg_type_number_t n=(y); vm_offset_t b=(vm_offset_t)(x);  R(rsp)-=n; err = mach_vm_write(task, R(rsp), b, n); CHECK_MACH_ERROR (err, "mach_vm_write: failed:"); R(rsp); })
#define PUSHCSTR(x) ({ void *s=(x); PUSH(s,strlen(s)+1); })
#define PUSHI(x) ({ long long a=(long long)(x); PUSH(&a,8); })
#define APUSHCSTR(a) for(long long i=0;a[i];++i) { long long x=(long long)PUSHCSTR(a[i]);free(a[i]);a[i] = (void*)x; }
#define APUSHI(a) for(long long i=0;a[i];++i)PUSHI(a[i])
#define PATCH(s) PUSH(s, sizeof(s)-1)

    if(exception != EXC_SYSCALL) {
        printf("* rip %p rdi %p rsi %p rdx %p || rsp %p\n",(void*)R(rip),(void*)R(rdi),(void*)R(rsi),(void*)R(rdx),(void*)R(rsp));
        printf(" cs = %p, fs = %p gs = %p\n", (void*)R(cs), (void*)R(fs), (void*)R(gs));
        printf("general exception at %x\n",code[1]);
        return KERN_SUCCESS;
    }

    if(!original_rsp) original_rsp = R(rsp);
//printf("syscall %d\n", (int)R(rax));

    thread_suspend(thread);
    switch(R(rax)) {
    default: printf("unimplemented syscall %d\n", (int)R(rax)); abort(); break;

//%rdi	%rsi	%rdx	%r10	%r8
    case 0:TC(read);  break;
    case 1:TC(write); break;
    case 2:TC(open);  break;
    case 3:TC(close); break;
    case 4: case 5: case 6: { /* stat, fstat, lstat */
        /* linux and OSX have the same stat struct size (144 bytes) but the fields are in slightly different orders */
        PUSHI(R(rip));

        long long save_rsp = R(rsp);

        R(rip) = PATCH("\x0f\x05\x48\x89\xc7\x48\xc7\xc0\xb1\x00\x00\x00\x5c\x0f\x05\xc3");
        PUSHI(save_rsp);

        if(R(rax) == 4) {
            R(rax)=0x2000000|SYS_stat;
        } else if (R(rax) == 5) {
            R(rax)=0x2000000|SYS_fstat;
        } else {
            R(rax)=0x2000000|SYS_lstat;
        }
    }; break;
        case 177: { /* bottom half of stat: rdi=return from stat(), rsi=stat_buf */
            long long retval = R(rdi);
            if(retval != 0) { R(rax)=R(rdi); break; }

            char ss[144]={0}; long long *sj=(long long*)ss;int *si=(int*)ss;short*sh=(short*)ss; mach_vm_size_t ss_buffer_size = sizeof(ss);
            err = mach_vm_read_overwrite(task, (long long)R(rsi), sizeof(ss), (mach_vm_address_t)&ss, &ss_buffer_size);
            CHECK_MACH_ERROR (err, "mach_vm_read_overwrite failed:");

            char ls[144] = {0}; long long *lj=(long long*)ls; int *li=(int*)ls;

            lj[6]=sj[9];/*size*/
            li[7]=si[3];/*uid*/li[8]=si[4];/*gid*/
            lj[9]=sj[3];lj[11]=sj[5];lj[13]=sj[7];/*atime,mtime,ctime*/
            lj[7]=sj[11];lj[8]=sj[10];/*blksize,blocks*/
            li[6]=sh[4];/*mode */
            lj[0]=si[0];lj[1]=si[1];/*dev,inode*/
            lj[8]=si[5];/*nlink: find uses this for optimising */

            err = mach_vm_write(task, (long long)R(rsi), (vm_offset_t)ls, 144);
            CHECK_MACH_ERROR (err, "mach_vm_write failed:");

            R(rax) = 0;
        }; break;
    case 9:
           R(r10) = ((R(r10) & 1)?MAP_SHARED :0)
                  | ((R(r10) & 2)?MAP_PRIVATE:0)
                  | ((R(r10) &16)?MAP_FIXED  :0)
                  | ((R(r10) &32)?MAP_ANONYMOUS:0);
           R(rdx) &= 3;
           TC(mmap); break;

    case 11:TC(munmap);break;
    case 12: { /*brk*/
           long long target = R(rdi) & ~(page_size-1);
           struct extra_task_info *p = get_extra_task_info(task);

           pthread_mutex_lock(&p->lock);

           if(target <= 0) target = p->brk_high;
           else if(target <= p->brk_low) target = p->brk_low + page_size;

           if(target < p->brk_high) {
               err = mach_vm_deallocate(task, target, p->brk_high - target);
               if(err == KERN_SUCCESS) p->brk_high = target;

           } else if(target > p->brk_high) {
               mach_vm_address_t base = p->brk_high;
               err = mach_vm_allocate(task, &base, target - p->brk_high, FALSE); // should link
               if(err == KERN_SUCCESS) p->brk_high = target;
           }
           R(rax) = p->brk_high;

           asm volatile("" ::: "memory");
           pthread_mutex_unlock(&p->lock);
      }; break;
    case 20:TC(writev);break;
    case 39:TC(getpid);break;
    case 53:TC(socketpair);break;
#if 0
    case 56: { /* clone */
printf("clone %p\n", (void*)R(rdi));
        pid_t child_pid;
        mach_port_t child_thread;
        struct extra_task_info *pp = get_extra_task_info(task);

        if((R(rdi) & 0x500) == 0x500) { /* create a thread */
            mach_port_t new_thread;
            err = thread_create(task, &new_thread);
            CHECK_MACH_ERROR (err, "thread_create failed:");

            child_pid = pp->pid;
            goto clone_continue;
        }
        if(R(rdi) & 0x400) {
            /* OSX cannot do this very easily: share files but not vm */
            R(rax) = -ENOSYS;
            break;
        }

        /* okay, fork not thread.
           forking is complicated, since we need linux working on the other side

           * we create the fork here,
           * we wipe out the interior pages
           * we remap all of the mappings from source-task to target-task
           * we build the thread state ourselves
        */
        child_pid = fork_osx();
        if(child_pid == -1) { R(rax) = -errno; break; }
        if(child_pid == 0) { /* inside child: put a dummy syscall so we'll block in mach; syscall 174 can be reused */
            asm volatile("syscall" : "=a" (err) : "0"(59 /*execve*/), "D"(174), "S"(0), "d"(0) : "cc", "rcx", "r11", "memory"); abort();
        }

        thread_act_port_array_t thread_list;
        mach_msg_type_number_t nthreads;
        err = task_threads(child_task,&thread_list,&nthreads);
        CHECK_MACH_ERROR (err, "task_threads failed:");
        for(int i = 1; i < nthreads; ++i) thread_terminate(thread_list[i]);
        child_thread = thread_list[0];

        /* fyi because mach() is single threaded, so we haven't actually hit 174 yet */
        thread_suspend(child_thread);

        /* discard the prototype memory */
        mach_vm_address_t ptr = page_size;
        for(;;) {
             mach_vm_size_t region_size = 0;
             vm_region_basic_info_data_t region_info[64];
             mach_msg_type_number_t region_info_count = VM_REGION_BASIC_INFO_COUNT_64;
             memory_object_name_t   region_object;

             err = mach_vm_region(child_task, &ptr, &region_size, VM_REGION_BASIC_INFO, (vm_region_info_t)region_info, &region_info_count, &region_object);
             CHECK_MACH_ERROR (err, "mach_vm_region failed:");

             err = mach_vm_deallocate(child_task, ptr, region_size);
             CHECK_MACH_ERROR (err, "mach_vm_deallocate failed:");
             ptr += region_size;
        }

        /* copy our child memory pages to the new prototype */
        for(ptr = page_size;;) {
            mach_vm_size_t region_size = 0;
            vm_region_basic_info_data_t region_info[64];
            mach_msg_type_number_t region_info_count = VM_REGION_BASIC_INFO_COUNT_64;
            memory_object_name_t   region_object;

            err = mach_vm_region(task, &ptr, &region_size, VM_REGION_BASIC_INFO, (vm_region_info_t)region_info, &region_info_count, &region_object);
            CHECK_MACH_ERROR (err, "mach_vm_region failed:");

            vm_prot_t prot, max;
            err = mach_vm_remap(child_task, &ptr, region_size, 0, FALSE, task, ptr, 
                (R(rdi) & 0x100 /*CLONE_VM but not CLONE_FS*/|| region_info[0].inheritance & VM_INHERIT_SHARE) ? FALSE : TRUE, //copy
                &prot, &max, 
                region_info[0].inheritance);
            CHECK_MACH_ERROR (err, "mach_vm_remap failed:");

            err = mach_vm_protect(child_task, ptr, region_size, FALSE, region_info[0].protection);
            CHECK_MACH_ERROR (err, "mach_vm_protect failed:");

            ptr += region_size;
        }
clone_continue:
        {
            struct extra_task_info *p  = get_extra_task_info(child_task);
            p->fake_ppid = pp->pid;
            p->pid       = child_pid;
            p->brk_low   = pp->brk_low;
            p->brk_high  = pp->brk_high;
        };

        if(R(rdi) & 0x00200000) { /* CLONE_CHILD_SETTID:  */
            pid_t tid = child_thread; /* use mach thread number as thread id */
            err = mach_vm_write(child_task, R(rdx), (mach_vm_address_t)&tid, sizeof(tid));
            CHECK_MACH_ERROR (err, "mach_vm_write failed:");
        }

        /* now child will resume (ideally inside the already loaded syscall) */
        R(rax) = 0;
        thread_set_state(child_thread, x86_THREAD_STATE, state, stateCnt);
        thread_resume(child_thread);

        R(rax) = child_pid;
        if(R(rdi) & 0x00100000) { /* CLONE_PARENT_SETTID:  */
            pid_t tid = child_thread; /* use mach thread number as thread id */
            err = mach_vm_write(task, R(rdx), (mach_vm_address_t)&tid, sizeof(tid));
            CHECK_MACH_ERROR (err, "mach_vm_write failed:");
        }
        break;
      };
#endif
    case 59: { /* execve */
        char *arg0  = get_cstring_from_user(task, R(rdi));

        int fd = open(arg0, O_RDONLY);
        free(arg0);

        if(fd == -1) { R(rax)=-errno; break; }

        long long size = lseek(fd, 0, SEEK_END);
        char *file_rx = mmap(0, size, PROT_READ | PROT_EXEC,  MAP_SHARED, fd, 0);
        char *file_rw = mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
        close(fd);

        if(file_rx == MAP_FAILED || file_rw == MAP_FAILED || size < 50) {
einval:     munmap(file_rx, size);
            munmap(file_rw, size);
            R(rax)=-EINVAL;
            break;
        }

        int *hi   = (int*)file_rw;
        short *hh = (short*)file_rw;
        long long *hj = (long long*)file_rw;
        if(hi[0] != 0x464c457f) { /* not elf; try macho or /bin/sh instead */
            munmap(file_rx, size);
            munmap(file_rw, size);
            TC(execve);
            break;
        }
        if(hi[4] != 4063234) { /* elf32 (not 64) NYI */
            goto einval; /* NYI */
        }

        long long argc, envc;
        char **argv = get_argv_from_user(task, R(rsi), &argc);
        char **envp = get_argv_from_user(task, R(rdx), &envc);
        mach_vm_address_t   brk_hint = page_size;

        /* shutdown/stop running */
        thread_act_port_array_t thread_list;
        mach_msg_type_number_t nthreads;
        err = task_threads(task,&thread_list,&nthreads);
        CHECK_MACH_ERROR (err, "task_threads failed:");
        for(int i = 0; i < nthreads; ++i) if(thread_list[i] != thread) thread_terminate(thread_list[i]);

        /* remove everything but the stack */
        mach_vm_address_t ptr = page_size;
        for(;;) {
            mach_vm_size_t region_size = 0;
            vm_region_basic_info_data_t region_info[64];
            mach_msg_type_number_t region_info_count = VM_REGION_BASIC_INFO_COUNT_64;
            memory_object_name_t   region_object;

            err = mach_vm_region(task, &ptr, &region_size, VM_REGION_BASIC_INFO, (vm_region_info_t)region_info, &region_info_count, &region_object);
            CHECK_MACH_ERROR (err, "mach_vm_region failed:");

            if(ptr <= original_rsp && (ptr+region_size) >= original_rsp) {
                /* stack at top of memory */
                R(rsp) = ptr + region_size - 128;

                err = mach_vm_protect(task, ptr, region_size, FALSE, VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXECUTE);
                CHECK_MACH_ERROR (err, "mach_vm_protect failed:");

                break;
            }

            err = mach_vm_deallocate(task, ptr, region_size);
            CHECK_MACH_ERROR (err, "mach_vm_deallocate failed:");
            ptr += region_size;
        }
        mach_vm_address_t tls_min = 0, tls_max = 0;
        for(int i = 0; i < hh[30]; ++i) {
            long long *sh = (void*)&file_rw[hj[5] + (64*i)];
            if(sh[1] & 0x400 /*SHF_TLS*/) {
                if(!tls_max || tls_min > sh[2]) tls_min = sh[2];
                if(tls_max < sh[2] + sh[4]) tls_max = sh[2] + sh[4];
            }
        }
        for(int i = 0; i < hh[28]; ++i) {
            long long *ph = (void*)&file_rw[hj[4] + (56*i)];
            mach_vm_address_t vstart = ph[2], vaddr = vstart, vend = ph[5] + vstart;
            vm_prot_t prot, max;

            if(vend & (page_size-1)) vend = (vend & ~(page_size-1)) + page_size;
            if(brk_hint < vend && vend < original_rsp) brk_hint = vend;

            switch(ph[0] & 0xffffffff) {
            case 0: /* PT_NULL */ continue;
            case 1: /* PT_LOAD */ {
                int flags = (ph[0] >> 32);
                if(!(flags & 3)) continue;

                mach_vm_address_t source = (mach_vm_address_t)(((flags & 1)?file_rx:file_rw) + ph[1]);

                //printf("PHY %p - %p  pfags=%d\n", vstart, vend,flags);
                err = mach_vm_remap(task, &vstart, ph[4], page_size-1, FALSE,
                        mach_task_self(), source, (flags & 2) ? TRUE : FALSE,
                        &prot, &max, VM_INHERIT_SHARE);
                CHECK_MACH_ERROR (err, "mach_vm_remap failed:");

                long long gap = (vaddr - vstart) & (page_size-1);
                vaddr += ph[4];

                if(vaddr & (page_size-1)) {
                    if(flags & 2) {
                        char *lastpage = valloc(page_size);
                        memcpy(lastpage + gap, (void*)(source + (ph[4] & ~(page_size-1))), ph[4] & (page_size-1));
                        err = mach_vm_write(task, vstart, (mach_vm_address_t)lastpage, page_size);
                        CHECK_MACH_ERROR (err, "mach_vm_write failed:");
                        free(lastpage);
                    }
                    vaddr = (vaddr & ~(page_size-1)) + page_size;
                }

                if (vaddr < vend) {
                    err = mach_vm_allocate(task, &vaddr, vend-vaddr, 0);
                    CHECK_MACH_ERROR (err, "mach_vm_allocate failed:");
                }

                err = mach_vm_protect(task, vstart, vend - vstart, FALSE,
                        ((flags & 4) ? VM_PROT_READ    : 0) |
                        ((flags & 2) ? VM_PROT_WRITE   : 0) |
                        ((flags & 1) ? VM_PROT_EXECUTE : 0));
                CHECK_MACH_ERROR (err, "mach_vm_protect failed:");
            };  break;
            case 4: /* PT_NOTE */ continue;
            default:
                //printf("unimplemented load type %p\n", (void*)ph[0]);
                continue;
            };
        }

        unsigned int initial_brk = 0x1000000;
        struct extra_task_info *p  = get_extra_task_info(task);
        p->brk_low = brk_hint; // OSX uses first fit

        err = mach_vm_allocate(task, &p->brk_low, initial_brk, TRUE);
        CHECK_MACH_ERROR (err, "mach_vm_allocate failed:");
        p->brk_high = p->brk_low + initial_brk;

        if(tls_max) {
            p->tls_base = tls_min;
            p->tls_size = tls_max - tls_min;
        } else {
            p->tls_base = 0;
            p->tls_size = 0;
        }

        /* initialisation vector: ask os to create a TLS segment for us and put it in %gs,
           we move it to %fs (which is where linux puts it) and then ret (which will fall into hj[3] the entrypoint)
         */
        R(rip) = PATCH("\x48\xc7\xc0\x03\x00\x00\x03\x0f\x05\x66\x8c\xe8\x8e\xe0\xc3");

        /* push arguments */
        APUSHCSTR(envp);
        APUSHCSTR(argv);
        if((envc+argc+5)&1) PUSHI(0); // p.30 amd64 abi draft
        PUSHI(0);PUSHI(0);
        PUSHI(0);
        APUSHI(envp);
        PUSHI(0);
        APUSHI(argv);
        PUSHI(argc);

        PUSHI(hj[3]); // retq from patch
        R(rdi) = p->tls_base; // set %gs

        R(rbp) = 0;
        R(rax) = R(rdx) = 0;
        R(rflags) = 0;

        /* no more access to these pages */
        munmap(file_rx, size);
        munmap(file_rw, size);

        break;
      };
    case 60:TC(exit);break;
    case 63: { /* utsname */
          struct linux_utsname {
              char sysname[65];
              char nodename[65];
              char release[65];
              char version[65];
              char machine[65];
          } u;
          struct utsname uts;
          uname(&uts);
          strcpy(u.sysname, "Linux");
          strncpy(u.nodename, uts.nodename, 64); u.nodename[64]=0;
          strcpy(u.release, "3.0.0-ml"); /* glibc actually looks at this... */
          strcpy(u.version, "#1 ml");
          strcpy(u.machine, "x86_64");

          err = mach_vm_write(task, R(rdi), (mach_vm_address_t)&u, sizeof(u));
          CHECK_MACH_ERROR (err, "mach_vm_write failed:");
          R(rax) = 0;
          break;
      };
    case 77:TC(ftruncate);break;
    case 87:TC(unlink);break;
    case 96: { /* gettimeofday() reads local memory; not a syscall; normally would look at 0x7fffffe00000 but we're in linux there */
        struct timeval  tv[1];
        struct timezone tz[1];
        gettimeofday(tv, R(rdx) ? tz : NULL);
        mach_vm_write(task, R(rdi), (mach_vm_address_t)tv, sizeof(tv));
        if(R(rdx)) mach_vm_write(task, R(rdx), (mach_vm_address_t)tz, sizeof(tz));
        R(rax) = 0;
        break;
      };
    case 110: { /* getppid() */
        struct extra_task_info *p = get_extra_task_info(task);
        R(rax) = p->fake_ppid;
        break;
      };
    case 232: { /* epoll_wait(): convert to kevent() */
      PUSHI(R(rip));
      long long save_rsp = R(rsp);
      long long events_ptr = R(rsi);
      int timeout = R(r10);

      if(timeout < 0) {
          R(r9) = 0;
      } else {
          struct timespec spec; // linux uses milliseconds
          spec.tv_sec  = R(r10) / 1000;
          spec.tv_nsec = (R(r10) % 1000) * 1000000;
          R(r9) = PUSH(&spec, sizeof(spec));
      }

      if(R(rdx) < 8) {
        // for small numbers, we can just push them onto the stack
        R(rsp) -= sizeof(struct kevent) * R(rdx);
        R(r10) = R(rsp);
        R(r8)  = R(rdx);
      } else {
        // for larger numbers, we'll reuse the guest buffer
        R(r10) = R(rsi);
        R(r8) = (R(rdx) * 12) / sizeof(struct kevent);
      }
      
      long long read_kevents = R(r10);

      R(rax)=0x2000000|SYS_kevent;
      R(rsi)=R(rdx)=0;

      // call kevent, then transfer control to syscall 174
      R(rip) = PATCH("\x0f\x05\x48\x89\xc7\x48\xc7\xc0\xae\x00\x00\x00\x5e\x5a\x5c\x0f\x05\xc3");

      PUSHI(save_rsp);
      PUSHI(read_kevents);
      PUSHI(events_ptr);

      }; break;
      case 174://bottom half of epoll_wait and (fork return 0) ( rdi=kevent's rax,  rdx=kevent buffer rsi=linux buffer
      {
          int nevents = R(rdi);
          if(nevents <= 0) { R(rax) = nevents; break; } /* no change */
          for(int i = 0; i < nevents; ++i) {
              struct kevent kv[1]; mach_vm_size_t kv_buffer_size = sizeof(kv);
              err = mach_vm_read_overwrite(task, ((long long)R(rdx)) + (i*sizeof(kv)), sizeof(kv), (mach_vm_address_t)&kv, &kv_buffer_size);
              CHECK_MACH_ERROR (err, "mach_vm_read_overwrite failed:");

              unsigned int *epoll_result = valloc(12);
              memcpy(epoll_result+1, &kv->udata, 8); /* identity */
              epoll_result[0] = kv->filter==EVFILT_READ?1:kv->filter==EVFILT_WRITE?4: 0;
              if(kv->flags & EV_EOF) epoll_result[0] |= 16;

              err = mach_vm_write(task, ((long long)R(rsi)) + (i*12), (mach_vm_address_t)epoll_result, 12);
              CHECK_MACH_ERROR (err, "mach_vm_write failed:");
              free(epoll_result);
          }
          R(rax) = nevents;
      }; break;
    case 233: {/*epoll_ctl*/
      PUSHI(R(rip));
      long long save_rsp = R(rsp);

      char epoll_buffer[12]; mach_vm_size_t epoll_buffer_size=12;
      err = mach_vm_read_overwrite(task, R(r10), 12, (mach_vm_address_t)&epoll_buffer, &epoll_buffer_size);
      CHECK_MACH_ERROR (err, "mach_vm_read_overwrite failed:");

      unsigned int events = *(unsigned int *)epoll_buffer;
      void*ident = *((void**)(&epoll_buffer[4]));
      int fd = R(rdx);

      struct kevent ev[2];int nev = 0;
      int ev_flags = (events&(1 << 30)?EV_ONESHOT:0)|EV_CLEAR|(R(rsi)==2?EV_DELETE:EV_ADD);
      if(events & 3) {
          EV_SET(ev+nev,fd,EVFILT_READ,ev_flags,0,0,ident);++nev;
      }
      if(events & 4) {
          EV_SET(ev+nev,fd,EVFILT_WRITE,ev_flags,0,0,ident);++nev;
      }

      R(rsi) = PUSH(ev,nev*sizeof(ev));
      R(rdx) = 1;
      R(r10) = 0; R(r8) = 0; R(r9) = 0;

      //pop the original rsp after kevent()
      R(rax)=0x2000000|SYS_kevent;
      R(rip) = PATCH("\x0f\x05\x5c\xc3");
      PUSHI(save_rsp);

      }; break;
    case 291:TC(kqueue);break; /* convert epoll_create -> kqueue */
    };
    thread_set_state(thread, x86_THREAD_STATE, state, stateCnt);
    thread_resume(thread);
    return(KERN_SUCCESS);
}

static void lost_child(int no)
{
    int st;

    wait(&st);

    if(WIFEXITED(st)) exit(WEXITSTATUS(st));
    if(WIFSIGNALED(st)) raise(WTERMSIG(st));
    abort();
}

/* unnecessary if -no-pie is supplied */
static int check_no_pie(void)
{
    char *x = mmap((char*)page_size,page_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(x < (char*)0x100000) return 1; /* heuristic: the error report will be "ml starts up slow" or "ml takes a long time to start up" */
    return 0;
}

int main(int argc, char *argv[], char **envp)
{
    kern_return_t       err;

    argv_location = argv[0];

    err = host_page_size(mach_host_self(), &page_size);
    CHECK_MACH_ERROR (err, "host_page_size failed:");

    struct rlimit rlim;
    rlim.rlim_cur = rlim.rlim_max = page_size;
    setrlimit(RLIMIT_DATA, &rlim);

    if(!check_no_pie()) execve(*argv,argv,envp);

    if (setup_recv_port (&exception_port) != 0)
        return -1;

    pid_t child_pid;
    switch(child_pid = fork_osx()) {
    case 0:
        asm volatile("syscall" : "=a" (err) : "0"(59 /*execve*/), "D"(argv[1]), "S"(argv+1), "d"(envp) : "cc", "rcx", "r11", "memory");
        perror(argv[0]);exit(1);
    case -1:perror("fork"); exit(1);
    };

    struct extra_task_info *p = get_extra_task_info(child_task);
    p->fake_ppid = getppid();
    p->pid       = child_pid;
    p->brk_high  = p->brk_low = 0; // set by exec

    signal(SIGCHLD, lost_child);
    close(0);

    struct { mach_msg_header_t head; char data[256]; } reply;
    struct { mach_msg_header_t head; mach_msg_body_t msgh_body; char data[1024]; } msg;

    extern boolean_t exc_server(mach_msg_header_t *,mach_msg_header_t *);

    for(;;) {
        err = mach_msg(
            &msg.head,
            MACH_RCV_MSG|MACH_RCV_LARGE,
            0,
            sizeof(msg),
            exception_port,
            MACH_MSG_TIMEOUT_NONE,
            MACH_PORT_NULL);
        CHECK_MACH_ERROR (err, "mach_msg failed:");

        if(!exc_server(&msg.head,&reply.head)) abort();

        err = mach_msg(
            &reply.head,
            MACH_SEND_MSG,
            reply.head.msgh_size,
            0,
            MACH_PORT_NULL,
            MACH_MSG_TIMEOUT_NONE,
            MACH_PORT_NULL);
        CHECK_MACH_ERROR (err, "mach_msg failed:");
    }
}

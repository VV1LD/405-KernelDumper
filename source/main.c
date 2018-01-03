/*****************************************************************
*
* ============== Kernel Dumper for 4.05 - WildCard ===============
*
*	Thanks to:
*	-Specter for his kernel exploit / Code Execution method
*	-IDC for helping to understand things
*	-Shadow for the copyout trick ;)
*
******************************************************************/
#include "ps4.h"

#define IP(a, b, c, d) (((a) << 0) + ((b) << 8) + ((c) << 16) + ((d) << 24))


#define	CTL_KERN	1	/* "high kernel": proc, limits */
#define	KERN_PROC	14	/* struct: process entries */
#define	KERN_PROC_VMMAP	32	/* VM map entries for process */
#define	KERN_PROC_PID	1	/* by process id */

struct auditinfo_addr {
    /*
    4    ai_auid;
    8    ai_mask;
    24    ai_termid;
    4    ai_asid;
    8    ai_flags;r
    */
    char useless[184];
};

#define printfsocket(format, ...)\
	do {\
		char buffer[512];\
		int size = sprintf(buffer, format, ##__VA_ARGS__);\
		sceNetSend(sock, buffer, size, 0);\
	} while(0)


unsigned int long long __readmsr(unsigned long __register) {
	// Loads the contents of a 64-bit model specific register (MSR) specified in
	// the ECX register into registers EDX:EAX. The EDX register is loaded with
	// the high-order 32 bits of the MSR and the EAX register is loaded with the
	// low-order 32 bits. If less than 64 bits are implemented in the MSR being
	// read, the values returned to EDX:EAX in unimplemented bit locations are
	// undefined.
	unsigned long __edx;
	unsigned long __eax;
	__asm__ ("rdmsr" : "=d"(__edx), "=a"(__eax) : "c"(__register));
	return (((unsigned int long long)__edx) << 32) | (unsigned int long long)__eax;
}

#define X86_CR0_WP (1 << 16)

static inline __attribute__((always_inline)) uint64_t readCr0(void) {
	uint64_t cr0;
	
	asm volatile (
		"movq %0, %%cr0"
		: "=r" (cr0)
		: : "memory"
 	);
	
	return cr0;
}

static inline __attribute__((always_inline)) void writeCr0(uint64_t cr0) {
	asm volatile (
		"movq %%cr0, %0"
		: : "r" (cr0)
		: "memory"
	);
}


struct ucred {
	uint32_t useless1;
	uint32_t cr_uid;     // effective user id
	uint32_t cr_ruid;    // real user id
 	uint32_t useless2;
    	uint32_t useless3;
    	uint32_t cr_rgid;    // real group id
    	uint32_t useless4;
    	void *useless5;
    	void *useless6;
    	void *cr_prison;     // jail(2)
    	void *useless7;
    	uint32_t useless8;
    	void *useless9[2];
    	void *useless10;
    	struct auditinfo_addr useless11;
    	uint32_t *cr_groups; // groups
    	uint32_t useless12;
};

struct filedesc {
	void *useless1[3];
    	void *fd_rdir;
    	void *fd_jdir;
};

struct proc {
    	char useless[64];
    	struct ucred *p_ucred;
    	struct filedesc *p_fd;
};

struct thread {
    	void *useless;
    	struct proc *td_proc;
};

struct kpayload_args{
	uint64_t user_arg;
};

struct kdump_args{
    	uint64_t argArrayPtr;
};


int kdump(struct thread *td, struct kdump_args* args){

	// hook our kernel functions
	void* kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-0x30EB30];

	int (*printfkernel)(const char *fmt, ...) = (void *)(kernel_base + 0x347580);
	int (*copyout)(const void *kaddr, void *uaddr, size_t len) = (void *)(kernel_base + 0x286d70);
	void (*bzero)(void *b, size_t len) = (void *)(kernel_base + 0x286c30);
	int (*copyin)(const void *uaddr, void *kaddr, size_t len) = (void *)(kernel_base + 0x286df0);


	//printfkernel("\n\n\nHELLO FROM YOUR dumper =)\n\n\n");

	uint64_t ubuf;
	memcpy(&ubuf,&args[2],8);
	printfkernel("kdump ubuf is:0x%016llx\n", ubuf);

	uint64_t kaddr;
	copyin(ubuf,&kaddr,8);
	printfkernel("kdump kernel address is:0x%016llx\n", kaddr);

	uint64_t uaddr;
	copyin(ubuf + 8,&uaddr,8);
	printfkernel("kdump userland buffer is at:0x%016llx\n", uaddr);


	// run copyout into userland memory for the kaddr we specify
	int cpRet = copyout(kaddr, uaddr , 0x1000);

	// if mapping doesnt exist zero out that mem
	if(cpRet == -1){
		printfkernel("bzero at 0x%016llx\n", kaddr);
		bzero(uaddr, 0x1000);
		return cpRet;
	}
	
	return cpRet;
}


int kpayload(struct thread *td, struct kpayload_args* args){

	struct ucred* cred;
	struct filedesc* fd;

	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;

	void* kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-0x30EB30];
	uint8_t* kernel_ptr = (uint8_t*)kernel_base;
	void** got_prison0 =   (void**)&kernel_ptr[0xF26010];
	void** got_rootvnode = (void**)&kernel_ptr[0x206D250];

	// resolve kernel functions

	int (*copyout)(const void *kaddr, void *uaddr, size_t len) = (void *)(kernel_base + 0x286d70);
	int (*printfkernel)(const char *fmt, ...) = (void *)(kernel_base + 0x347580);

	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;

	cred->cr_prison = *got_prison0;
	fd->fd_rdir = fd->fd_jdir = *got_rootvnode;
	
	// uart enabler
	*(char *)(kernel_base + 0x186b0a0) = 0; // set the console disable console output bool

	// specters debug settings patchs

	*(char *)(kernel_base + 0x2001516) |= 0x14;
	*(char *)(kernel_base + 0x2001539) |= 1;
	*(char *)(kernel_base + 0x2001539) |= 2;
	*(char *)(kernel_base + 0x200153A) |= 1;
	*(char *)(kernel_base + 0x2001558) |= 1;	

	// Disable write protection

	uint64_t cr0 = readCr0();
	writeCr0(cr0 & ~X86_CR0_WP);

	// debug menu full patches thanks to sealab

	*(uint32_t *)(kernel_base + 0x4CECB7) = 0;
	*(uint32_t *)(kernel_base + 0x4CFB9B) = 0;

	// Target ID Patches :)

	*(uint16_t *)(kernel_base + 0x1FE59E4) = 0x8101;
	*(uint16_t *)(kernel_base + 0X1FE5A2C) = 0x8101;
	*(uint16_t *)(kernel_base + 0x200151C) = 0x8101;

	// Say hello and put the kernel base in userland to we can use later

	printfkernel("\n\n\nHELLO FROM YOUR KERN DUDE =)\n\n\n");

	printfkernel("kernel base is:0x%016llx\n", kernel_base);

	uint64_t uaddr;
	memcpy(&uaddr,&args[2],8);

	printfkernel("uaddr is:0x%016llx\n", uaddr);

	copyout(&kernel_base, uaddr, 8);

	return 0;
}

// props to Hitodama for his hexdump function always nice to have near
int hexDumpKern(const void *data, size_t size, uint64_t kernel_base){

	unsigned char *d = (unsigned char *)data;
	size_t consoleSize = 16;
	char b[consoleSize + 3];
	size_t i;

	// hook kernel print for uart hex dumping
	int (*printf)(const char *fmt, ...) = (void *)(kernel_base + 0x347580);

	if(data == NULL){
		return -1;
		}
	b[0] = '|';
	b[consoleSize + 1] = '|';
	b[consoleSize + 2] = '\0';
	
	printf("\n-------HEX DUMP------\n");
	for (i = 0; i < size; i++)
	{
		if ((i % consoleSize) == 0)
		{
			if (i != 0){
				printf("  %s\n", b);
				}
			printf("%016lx ", (unsigned char *)data + i);
		}

		if(i % consoleSize == 8)
			printf(" ");
		printf(" %02x", d[i]);

		if (d[i] >= ' ' && d[i] <= '~')
			b[i % consoleSize + 1] = d[i];

		else
			b[i % consoleSize + 1] = '.';
		}

		while((i % consoleSize) != 0)
		{

		if(i % consoleSize == 8)
			printf("    ");
	
		else
			printf("   ");
			b[i % consoleSize + 1] = '.';
			i++;
		}

		printf("  %s\n", b);
		return 0;
}

// userland hexdump over socket
int hexDump(const void *data, size_t size,int sock)
{
	unsigned char *d = (unsigned char *)data;
	size_t consoleSize = 16;
	char b[consoleSize + 3];
	size_t i;

	if(data == NULL){
		return -1;
		}
	b[0] = '|';
	b[consoleSize + 1] = '|';
	b[consoleSize + 2] = '\0';
	
	printfsocket("\n-------HEX DUMP------\n");
	for (i = 0; i < size; i++)
	{
		if ((i % consoleSize) == 0)
		{
			if (i != 0){
				printfsocket("  %s\n", b);
				}
			printfsocket("%016lx ", (unsigned char *)data + i);
		}

		if(i % consoleSize == 8)
			printfsocket(" ");
		printfsocket(" %02x", d[i]);

		if (d[i] >= ' ' && d[i] <= '~')
			b[i % consoleSize + 1] = d[i];
		else
			b[i % consoleSize + 1] = '.';
	}
	while((i % consoleSize) != 0)
	{
		if(i % consoleSize == 8)
			printfsocket("    ");
		else
			printfsocket("   ");
		b[i % consoleSize + 1] = '.';
		i++;
	}
	printfsocket("  %s\n", b);
	return 0;
}



int _main(struct thread *td){

	// Init and resolve libraries
	initKernel();
	initLibc();
	initNetwork();
	initPthread();

	// create our server
	struct sockaddr_in server;

	server.sin_len = sizeof(server);
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = IP(192, 168, 1, 65);
	server.sin_port = sceNetHtons(9023);
	memset(server.sin_zero, 0, sizeof(server.sin_zero));
	int sock = sceNetSocket("debug", AF_INET, SOCK_STREAM, 0);
	sceNetConnect(sock, (struct sockaddr *)&server, sizeof(server));
	
	int flag = 1;
	sceNetSetsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));

	
	uint64_t* dump = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);


	printfsocket("connected\n");

	// patch some things in the kernel (sandbox, prison, debug settings etc..)
	int sRet = syscall(11,kpayload,td,dump);

	printfsocket("kernel patched!\n");

		
	// retreive the kernel base copied into userland memory and set it
	uint64_t kbase;

	memcpy(&kbase,dump,8);

	printfsocket("kernBase is:0x%016llx\n",kbase);
	printfsocket("dump is:0x%016llx\n",dump);

	// loop on our kdump payload 
	
	uint64_t pos = 0;

	for(int i = 0; i < 26564; i++){
		// dont ask
		uint64_t array[2] = {kbase + pos, dump, 0xAA};
	
		// call our copyout wrapper and send the userland buffer over socket
   		syscall(11,kdump,NULL,&array);
		sceNetSend(sock,dump,0x1000,0);
		pos = pos + 0x1000;
	}



	free(dump);
	sceNetSocketClose(sock);
    return 0;
}



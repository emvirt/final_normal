#include <linux/kernel.h>
#include <linux/io.h>
#include <asm/hardware/gic.h>
#include <linux/delay.h>
#include <linux/spinlock.h>

static DEFINE_SPINLOCK(crash_lock);

asmlinkage int sys_newcall(void){
        asm volatile("mov r0, #8\n;");         //HJPARK: NT_SMC_IPI
        asm volatile(".word 0xE1600070\n");

        return 0;
}


/* 
 * cylee: generate a kernel crash by access for address zero
 */
asmlinkage long sys_go_crash(void)
{
	spin_lock(&crash_lock);

	asm volatile(".word 0x0\n");
	panic("force-panic");

	spin_unlock(&crash_lock);

	return 0;
}

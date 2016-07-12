///////////////////////////////////////////
//MWJ                                    //
// MooWoong Jeon (Korea Univ. OS Lab)    //
///////////////////////////////////////////

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>          
#include <linux/errno.h>       
#include <linux/types.h>       
#include <linux/fcntl.h>       
#include <asm/uaccess.h>
#include <asm/io.h>
#include <linux/stat.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <mach/io.h>
#include <linux/time.h>
#include <linux/unistd.h>
#include <linux/delay.h>

#include "tzipc_poll.h"

#define CALL_DEV_NAME "mydev"
#define CALL_DEV_MAJOR 240 

#define TZIPC_NORMAL_WORLD

// cylee : shared buffer
struct tzipc_mem *secure_buf = (struct tzipc_mem*)TZIPC_SECURE_HDR_ADDR;
struct tzipc_mem *normal_buf = (struct tzipc_mem*)TZIPC_NORMAL_HDR_ADDR;
// cylee : ipi flag
int ready_to_read = 0;
//unsigned int send_now = 0;
unsigned int set_ldata = FLAG_OFF;
unsigned int get_ldata = FLAG_OFF;

long ipi_ioctl(struct file *filp, unsigned int cmd, unsigned long arg){
	printk(KERN_DEBUG "cmd = %d\n",cmd);

	switch (cmd) {
/*	case IMMEDIATE_SEND_START: 
		send_now = FLAG_ON;
		break;
	case IMMEDIATE_SEND_STOP: 
		send_now = FLAG_OFF;
		break;
*/
	case SET_LARGE_DATA_START:
		set_ldata = FLAG_ON;
		break;
	case SET_LARGE_DATA_STOP:
		set_ldata = FLAG_OFF;
		break;
	case GET_LARGE_DATA_START:
		get_ldata = FLAG_ON;
		break;
	case GET_LARGE_DATA_STOP:
		get_ldata = FLAG_OFF;
		break;
	}
	
	return 0;
}

void set_ready_to_read(void)
{
	ready_to_read = 1;
}
EXPORT_SYMBOL(set_ready_to_read);

ssize_t ipi_read(struct file *filp, char *buf, size_t count, loff_t *f_pos){
	void *addr = NULL;
	int ret = -1;
	unsigned int size = count;
	struct tzipc_mem *read_buf = NULL;
//	unsigned int read_count = 0;

#ifdef TZIPC_NORMAL_WORLD
	unsigned int funcid = 0;
	unsigned int read_funcid = 0;
#endif

#ifdef TZIPC_NORMAL_WORLD
	memcpy(&funcid, buf, sizeof(int));
	read_buf = secure_buf;
#else
	read_buf = normal_buf;
#endif

	if(get_ldata == FLAG_ON){
		while(read_buf->ldata_len <= 0)
			msleep(1);
		
		// copy large parameter data into the large data buffer
		ret = copy_to_user(buf, read_buf->ldata_addr, size);
		if(ret != 0) {
			printk(KERN_ERR "copy_to_user is failed: %d\n", ret);
			return 0;
		}
		read_buf->ldata_len = 0;

		return size;
	}
	else {
		// cylee: check whether an ipi was completed
//		if (ready_to_read == 0)
//			return 0;

		//polling
		if(read_buf->next_rd_idx >= read_buf->next_wr_idx) {
			if(read_buf->full == IS_FULL)
				goto read_data;
			else
				return 0;
		}

read_data:
//		read_count = read_buf->next_wr_idx - read_buf->next_rd_idx;
//		if(read_count < 0)
//			read_count = 0;
//		else if(read_count > TZIPC_BUF_ELEM_COUNT)
//			read_count = TZIPC_BUF_ELEM_COUNT;

		addr = TZIPC_NEXT_ADDR(read_buf->buf_addr, read_buf->next_rd_idx);
		if(addr == NULL || buf == NULL) {
			printk("addr is NULL\n");
			return 0;
		}

		ret = copy_to_user(buf, addr, size);
		if(ret != 0) {
			printk(KERN_ERR "copy_to_user is failed: %d\n", ret);
			return 0;
		}
		else {
			ret = size;
			read_buf->next_rd_idx = (read_buf->next_rd_idx + 1) % TZIPC_BUF_ELEM_COUNT;
			read_count--;

#ifdef TZIPC_NORMAL_WORLD
			read_funcid = *((unsigned int*)addr);
			if(funcid != read_funcid) {
				printk("wrong function id: 0x%x\n", read_funcid);
				printk("address: 0x%x\n", (unsigned int)addr);
				return 0;
			}
#endif
		}

//		if(read_count <= 0)
//			ready_to_read = 0;	// cylee: reset the flag
	}

	return ret;
}

ssize_t ipi_write(struct file *filp, const char *buf, size_t count, loff_t *f_pos){
	void *addr = NULL;
	int ret = -1;
	unsigned int size = count;
	struct tzipc_mem *write_buf = NULL;
	unsigned int retflag = 0;

#ifdef TZIPC_NORMAL_WORLD
	write_buf = normal_buf;
#else
	write_buf = secure_buf;
#endif

	if(set_ldata == FLAG_ON) {
		// copy large parameter data into the large data buffer
		ret = copy_from_user(write_buf->ldata_addr, buf, size);
		if(ret != 0) {
			printk(KERN_ERR "copy_from_user is failed: %d\n", ret);
			return 0;
		}
		write_buf->ldata_len = size;

		__asm volatile("push {r0,r1}\n");
		__asm volatile("mov r0, #6\n");
		__asm volatile("movw r1, #0x0007\n");
		__asm volatile("movt r1, #0x0001\n");
		__asm volatile(".word 0xE1600070\n");
		__asm volatile("pop {r0,r1}\n");

		return size;
	}
	else {
		if(write_buf->full == IS_FULL) {
			if(write_buf->next_rd_idx == write_buf->next_wr_idx)
				return 0;
			else
				write_buf->full = IS_NOT_FULL;
		}

		addr = TZIPC_NEXT_ADDR(write_buf->buf_addr, write_buf->next_wr_idx);
		if(addr == NULL || buf == NULL)
			return 0;

		ret = copy_from_user(addr, buf, size);
		if(ret != 0) {
			printk(KERN_ERR "copy_from_user is failed: %d\n", ret);
			return 0;
		}

		ret = size;
		retflag = *(((unsigned int*)addr) + 1);
		
		write_buf->next_wr_idx = (write_buf->next_wr_idx + 1) % TZIPC_BUF_ELEM_COUNT;
		if(write_buf->next_wr_idx == write_buf->next_rd_idx)
			write_buf->full = IS_FULL;
		
		if(retflag == RT_REQUEST || retflag == RT_RESPONSE) {
			// smc to send ipi
			__asm volatile("push {r0,r1}\n");
			__asm volatile("mov r0, #6\n");
			__asm volatile("movw r1, #0x0007\n");
			__asm volatile("movt r1, #0x0002\n");
			__asm volatile(".word 0xE1600070\n");
			__asm volatile("pop {r0,r1}\n");
		}
	}

	return ret;
}

//device open call
int ipi_open(struct inode *inode, struct file *filp){
	return 0;
}

//device release call
int ipi_release(struct inode *inode, struct file *filp){
	return 0;
}

//connect each device call to specific function
struct file_operations ipi_fops = {
	.owner			= THIS_MODULE,
	.unlocked_ioctl	= ipi_ioctl,
	.read			= ipi_read,
	.write			= ipi_write,
//	.open			= ipi_open,
//	.release			= ipi_release,
};

int ipi_init(void){
	int result = 0;
	printk(KERN_DEBUG "IPIDEV: ipi_init called!\n");

	//register char device
	result = register_chrdev(CALL_DEV_MAJOR, CALL_DEV_NAME, &ipi_fops);
	if (result < 0){
		printk("fail to init module: %d\n", result);
		return result;
	}

#ifdef TZIPC_NORMAL_WORLD
	memset(normal_buf, 0, TZIPC_HDR_SIZE);
	normal_buf->buf_addr = (void*)TZIPC_NORMAL_BUF_ADDR;
	memset(normal_buf->buf_addr, 0, TZIPC_BUF_SIZE);

	normal_buf->ldata_addr = (void*)TZIPC_LDATA_BUF_ADDR;
#else
	memset(secure_buf, 0, TZIPC_HDR_SIZE);
	secure_buf->buf_addr = (void*)TZIPC_SECURE_BUF_ADDR;
	memset(secure_buf->buf_addr, 0, TZIPC_BUF_SIZE);

	secure_buf->ldata_addr = (void*)TZIPC_LDATA_BUF_ADDR;
	memset(secure_buf->ldata_addr, 0, TZIPC_LDATA_BUF_SIZE);
#endif

	return 0;
}

void ipi_exit(void){
	printk(KERN_EMERG "IPIDEV: ipi_exit called!\n");
	unregister_chrdev(CALL_DEV_MAJOR, CALL_DEV_NAME);
}

module_init(ipi_init);
module_exit(ipi_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("MWJEON");
MODULE_DESCRIPTION("IPI Driver");

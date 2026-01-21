// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved.
 *
 * Multikernel TTY driver (PTY-style)
 *
 * Host kernel:
 *   /dev/mktty - open, write instance ID, then read/write
 *
 * Spawn kernel:
 *   /dev/mktty0 - console TTY device
 *
 * Usage on host:
 *   fd = open("/dev/mktty", O_RDWR);
 *   write(fd, "1\n", 2);    // connect to instance 1
 *   read(fd, buf, len);     // read console output
 *   write(fd, cmd, len);    // send input
 *
 * Boot spawn with: console=mktty0
 */

#include <linux/console.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>
#include <linux/multikernel.h>

#define MKTTY_IPI_TYPE		0x4D4B5459U	/* "MKTY" */
#define MKTTY_MAX_DATA		(MK_MAX_DATA_SIZE - 16)
#define MKTTY_RX_BUF_SIZE	16384

/* Message types */
#define MKTTY_MSG_INPUT		1	/* host -> spawn */
#define MKTTY_MSG_OUTPUT	2	/* spawn -> host */

struct mktty_message {
	u32 type;
	u32 console_id;
	u32 len;
	u32 reserved;
	char data[MKTTY_MAX_DATA];
};

/*
 * =============================================================================
 * Host-side implementation (PTY-style misc device)
 * =============================================================================
 */

struct mktty_host_conn {
	int instance_id;		/* -1 = not connected */
	struct list_head list;
	wait_queue_head_t wait;
	spinlock_t rx_lock;
	char *rx_buf;
	int rx_head;
	int rx_tail;
};

static LIST_HEAD(mktty_host_conns);
static DEFINE_SPINLOCK(mktty_host_conns_lock);
static struct mk_ipi_handler *mktty_host_handler;

static struct mktty_host_conn *mktty_find_conn(int instance_id)
{
	struct mktty_host_conn *conn;

	list_for_each_entry(conn, &mktty_host_conns, list) {
		if (conn->instance_id == instance_id)
			return conn;
	}
	return NULL;
}

static int mktty_host_open(struct inode *inode, struct file *filp)
{
	struct mktty_host_conn *conn;

	conn = kzalloc(sizeof(*conn), GFP_KERNEL);
	if (!conn)
		return -ENOMEM;

	conn->rx_buf = kmalloc(MKTTY_RX_BUF_SIZE, GFP_KERNEL);
	if (!conn->rx_buf) {
		kfree(conn);
		return -ENOMEM;
	}

	conn->instance_id = -1;
	init_waitqueue_head(&conn->wait);
	spin_lock_init(&conn->rx_lock);
	conn->rx_head = 0;
	conn->rx_tail = 0;

	spin_lock(&mktty_host_conns_lock);
	list_add(&conn->list, &mktty_host_conns);
	spin_unlock(&mktty_host_conns_lock);

	filp->private_data = conn;
	return 0;
}

static int mktty_host_release(struct inode *inode, struct file *filp)
{
	struct mktty_host_conn *conn = filp->private_data;

	spin_lock(&mktty_host_conns_lock);
	list_del(&conn->list);
	spin_unlock(&mktty_host_conns_lock);

	kfree(conn->rx_buf);
	kfree(conn);
	return 0;
}

static ssize_t mktty_host_read(struct file *filp, char __user *buf,
			       size_t count, loff_t *ppos)
{
	struct mktty_host_conn *conn = filp->private_data;
	size_t copied = 0;
	unsigned long flags;
	int ret;

	if (conn->instance_id < 0)
		return -ENOTCONN;

	while (copied == 0) {
		spin_lock_irqsave(&conn->rx_lock, flags);

		while (copied < count && conn->rx_head != conn->rx_tail) {
			char c = conn->rx_buf[conn->rx_tail];
			conn->rx_tail = (conn->rx_tail + 1) % MKTTY_RX_BUF_SIZE;
			spin_unlock_irqrestore(&conn->rx_lock, flags);

			if (put_user(c, buf + copied)) {
				return copied > 0 ? copied : -EFAULT;
			}
			copied++;

			spin_lock_irqsave(&conn->rx_lock, flags);
		}

		spin_unlock_irqrestore(&conn->rx_lock, flags);

		if (copied > 0)
			break;

		if (filp->f_flags & O_NONBLOCK)
			return -EAGAIN;

		ret = wait_event_interruptible(conn->wait,
				conn->rx_head != conn->rx_tail);
		if (ret)
			return ret;
	}

	return copied;
}

static ssize_t mktty_host_write(struct file *filp, const char __user *buf,
				size_t count, loff_t *ppos)
{
	struct mktty_host_conn *conn = filp->private_data;
	struct mktty_message *msg;
	struct mk_instance *instance;
	char numbuf[16];
	size_t sent = 0;
	size_t chunk;
	int ret;

	/* First write selects instance */
	if (conn->instance_id < 0) {
		size_t len = min(count, sizeof(numbuf) - 1);
		int id;

		if (copy_from_user(numbuf, buf, len))
			return -EFAULT;
		numbuf[len] = '\0';

		ret = kstrtoint(numbuf, 10, &id);
		if (ret < 0)
			return ret;
		if (id < 1)
			return -EINVAL;

		instance = mk_instance_find(id);
		if (!instance)
			return -ENODEV;
		mk_instance_put(instance);

		conn->instance_id = id;
		pr_info("mktty: fd connected to instance %d\n", id);
		return count;
	}

	/* Subsequent writes send data */
	msg = kmalloc(sizeof(*msg), GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	while (sent < count) {
		chunk = min(count - sent, (size_t)MKTTY_MAX_DATA);

		if (copy_from_user(msg->data, buf + sent, chunk)) {
			kfree(msg);
			return sent > 0 ? sent : -EFAULT;
		}

		msg->type = MKTTY_MSG_INPUT;
		msg->console_id = 0;
		msg->len = chunk;
		msg->reserved = 0;

		ret = multikernel_send_ipi_data(conn->instance_id, msg,
						sizeof(*msg) - MKTTY_MAX_DATA + chunk,
						MKTTY_IPI_TYPE);
		if (ret < 0) {
			kfree(msg);
			return sent > 0 ? sent : ret;
		}

		sent += chunk;
	}

	kfree(msg);
	return sent;
}

static __poll_t mktty_host_poll(struct file *filp, poll_table *wait)
{
	struct mktty_host_conn *conn = filp->private_data;
	__poll_t mask = 0;
	unsigned long flags;

	if (conn->instance_id < 0)
		return EPOLLOUT | EPOLLWRNORM;  /* can write instance ID */

	poll_wait(filp, &conn->wait, wait);

	spin_lock_irqsave(&conn->rx_lock, flags);
	if (conn->rx_head != conn->rx_tail)
		mask |= EPOLLIN | EPOLLRDNORM;
	spin_unlock_irqrestore(&conn->rx_lock, flags);

	mask |= EPOLLOUT | EPOLLWRNORM;
	return mask;
}

static const struct file_operations mktty_host_fops = {
	.owner		= THIS_MODULE,
	.open		= mktty_host_open,
	.release	= mktty_host_release,
	.read		= mktty_host_read,
	.write		= mktty_host_write,
	.poll		= mktty_host_poll,
};

static struct miscdevice mktty_host_miscdev = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= "mktty",
	.fops	= &mktty_host_fops,
};

static void mktty_host_ipi_handler(struct mk_ipi_data *data, void *ctx)
{
	struct mktty_message *msg = (struct mktty_message *)data->buffer;
	struct mktty_host_conn *conn;
	unsigned long flags;
	size_t i, space;

	if (data->data_size < sizeof(*msg) - MKTTY_MAX_DATA)
		return;
	if (msg->type != MKTTY_MSG_OUTPUT)
		return;
	if (msg->len > MKTTY_MAX_DATA)
		return;

	spin_lock_irqsave(&mktty_host_conns_lock, flags);
	conn = mktty_find_conn(msg->console_id);
	if (conn) {
		spin_lock(&conn->rx_lock);
		for (i = 0; i < msg->len; i++) {
			space = (conn->rx_tail - conn->rx_head - 1 + MKTTY_RX_BUF_SIZE) % MKTTY_RX_BUF_SIZE;
			if (space == 0)
				break;
			conn->rx_buf[conn->rx_head] = msg->data[i];
			conn->rx_head = (conn->rx_head + 1) % MKTTY_RX_BUF_SIZE;
		}
		spin_unlock(&conn->rx_lock);
		wake_up_interruptible(&conn->wait);
	}
	spin_unlock_irqrestore(&mktty_host_conns_lock, flags);
}

static int mktty_host_init(void)
{
	int ret;

	pr_info("mktty: initializing host driver (PTY-style)\n");

	ret = misc_register(&mktty_host_miscdev);
	if (ret < 0)
		return ret;

	mktty_host_handler = multikernel_register_handler(mktty_host_ipi_handler,
							  NULL, MKTTY_IPI_TYPE);
	if (!mktty_host_handler)
		pr_warn("mktty: failed to register IPI handler\n");

	pr_info("mktty: host ready - open /dev/mktty, write instance ID, then read/write\n");
	return 0;
}

static void mktty_host_cleanup(void)
{
	if (mktty_host_handler)
		multikernel_unregister_handler(mktty_host_handler);
	misc_deregister(&mktty_host_miscdev);
}

/*
 * =============================================================================
 * Spawn-side implementation (TTY for console)
 * =============================================================================
 */

struct mktty_spawn_state {
	struct tty_port port;
	spinlock_t lock;
	int instance_id;
};

static struct tty_driver *mktty_spawn_driver;
static struct mktty_spawn_state mktty_spawn;
static struct mk_ipi_handler *mktty_spawn_handler;
static struct console mktty_spawn_console;
static bool mktty_console_registered;

static int mktty_spawn_activate(struct tty_port *port, struct tty_struct *tty)
{
	return 0;
}

static void mktty_spawn_shutdown(struct tty_port *port)
{
}

static const struct tty_port_operations mktty_spawn_port_ops = {
	.activate = mktty_spawn_activate,
	.shutdown = mktty_spawn_shutdown,
};

static int mktty_spawn_open(struct tty_struct *tty, struct file *filp)
{
	if (tty->index != 0)
		return -ENODEV;
	return tty_port_open(&mktty_spawn.port, tty, filp);
}

static void mktty_spawn_close(struct tty_struct *tty, struct file *filp)
{
	if (tty->index == 0)
		tty_port_close(&mktty_spawn.port, tty, filp);
}

static void mktty_spawn_hangup(struct tty_struct *tty)
{
	if (tty->index == 0)
		tty_port_hangup(&mktty_spawn.port);
}

static ssize_t mktty_spawn_write(struct tty_struct *tty, const u8 *buf,
				 size_t count)
{
	struct mktty_message *msg;
	size_t sent = 0, chunk;
	int ret;

	if (tty->index != 0)
		return -ENODEV;

	msg = kmalloc(sizeof(*msg), GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	while (sent < count) {
		chunk = min(count - sent, (size_t)MKTTY_MAX_DATA);
		msg->type = MKTTY_MSG_OUTPUT;
		msg->console_id = mktty_spawn.instance_id;
		msg->len = chunk;
		msg->reserved = 0;
		memcpy(msg->data, buf + sent, chunk);

		ret = multikernel_send_ipi_data(0, msg,
				sizeof(*msg) - MKTTY_MAX_DATA + chunk,
				MKTTY_IPI_TYPE);
		if (ret < 0) {
			kfree(msg);
			return sent > 0 ? sent : ret;
		}
		sent += chunk;
	}

	kfree(msg);
	return sent;
}

static unsigned int mktty_spawn_write_room(struct tty_struct *tty)
{
	return MKTTY_MAX_DATA;
}

static const struct tty_operations mktty_spawn_ops = {
	.open		= mktty_spawn_open,
	.close		= mktty_spawn_close,
	.hangup		= mktty_spawn_hangup,
	.write		= mktty_spawn_write,
	.write_room	= mktty_spawn_write_room,
};

static void mktty_spawn_ipi_handler(struct mk_ipi_data *data, void *ctx)
{
	struct mktty_message *msg = (struct mktty_message *)data->buffer;
	struct tty_struct *tty;

	if (data->data_size < sizeof(*msg) - MKTTY_MAX_DATA)
		return;
	if (msg->type != MKTTY_MSG_INPUT)
		return;
	if (msg->len > MKTTY_MAX_DATA)
		return;

	tty = tty_port_tty_get(&mktty_spawn.port);
	if (tty) {
		tty_insert_flip_string(&mktty_spawn.port, msg->data, msg->len);
		tty_flip_buffer_push(&mktty_spawn.port);
		tty_kref_put(tty);
	}
}

static struct mktty_message mktty_console_msg;
static DEFINE_SPINLOCK(mktty_console_lock);

static void mktty_spawn_console_write(struct console *con, const char *s,
				      unsigned int count)
{
	unsigned long flags;
	size_t chunk;

	spin_lock_irqsave(&mktty_console_lock, flags);
	while (count > 0) {
		chunk = min_t(size_t, count, MKTTY_MAX_DATA);
		mktty_console_msg.type = MKTTY_MSG_OUTPUT;
		mktty_console_msg.console_id = mktty_spawn.instance_id;
		mktty_console_msg.len = chunk;
		mktty_console_msg.reserved = 0;
		memcpy(mktty_console_msg.data, s, chunk);

		multikernel_send_ipi_data(0, &mktty_console_msg,
				sizeof(mktty_console_msg) - MKTTY_MAX_DATA + chunk,
				MKTTY_IPI_TYPE);
		s += chunk;
		count -= chunk;
	}
	spin_unlock_irqrestore(&mktty_console_lock, flags);
}

static struct tty_driver *mktty_console_device(struct console *c, int *index)
{
	*index = 0;
	return mktty_spawn_driver;
}

static int mktty_console_setup(struct console *co, char *options)
{
	return (co->index == 0) ? 0 : -ENODEV;
}

static struct console mktty_spawn_console = {
	.name	= "mktty",
	.write	= mktty_spawn_console_write,
	.device	= mktty_console_device,
	.setup	= mktty_console_setup,
	.flags	= CON_PRINTBUFFER,
	.index	= 0,
};

static int __init mktty_spawn_console_init(void)
{
	if (!root_instance || root_instance->id == 0)
		return 0;

	mktty_spawn.instance_id = root_instance->id;
	register_console(&mktty_spawn_console);
	mktty_console_registered = true;
	pr_info("mktty: early console for instance %d\n", mktty_spawn.instance_id);
	return 0;
}
console_initcall(mktty_spawn_console_init);

static int mktty_spawn_init(void)
{
	struct tty_driver *driver;
	int ret;

	if (!root_instance)
		return -ENODEV;

	mktty_spawn.instance_id = root_instance->id;
	spin_lock_init(&mktty_spawn.lock);

	pr_info("mktty: initializing spawn (instance %d)\n", mktty_spawn.instance_id);

	driver = tty_alloc_driver(1, TTY_DRIVER_RESET_TERMIOS |
				     TTY_DRIVER_REAL_RAW);
	if (IS_ERR(driver))
		return PTR_ERR(driver);

	tty_port_init(&mktty_spawn.port);
	mktty_spawn.port.ops = &mktty_spawn_port_ops;

	driver->driver_name = "mktty";
	driver->name = "mktty";
	driver->type = TTY_DRIVER_TYPE_CONSOLE;
	driver->init_termios = tty_std_termios;
	driver->init_termios.c_iflag = 0;
	driver->init_termios.c_oflag = 0;
	driver->init_termios.c_lflag = 0;
	driver->init_termios.c_cflag = B115200 | CS8 | CREAD | HUPCL | CLOCAL;
	tty_set_operations(driver, &mktty_spawn_ops);
	tty_port_link_device(&mktty_spawn.port, driver, 0);

	ret = tty_register_driver(driver);
	if (ret < 0) {
		tty_driver_kref_put(driver);
		tty_port_destroy(&mktty_spawn.port);
		return ret;
	}

	mktty_spawn_driver = driver;

	mktty_spawn_handler = multikernel_register_handler(mktty_spawn_ipi_handler,
							   NULL, MKTTY_IPI_TYPE);
	if (!mktty_spawn_handler)
		pr_warn("mktty: failed to register IPI handler\n");

	if (!mktty_console_registered) {
		register_console(&mktty_spawn_console);
		mktty_console_registered = true;
	}

	pr_info("mktty: spawn ready (/dev/mktty0)\n");
	return 0;
}

static void mktty_spawn_cleanup(void)
{
	if (mktty_spawn_handler)
		multikernel_unregister_handler(mktty_spawn_handler);

	if (mktty_console_registered) {
		unregister_console(&mktty_spawn_console);
		mktty_console_registered = false;
	}

	if (mktty_spawn_driver) {
		tty_unregister_driver(mktty_spawn_driver);
		tty_driver_kref_put(mktty_spawn_driver);
		tty_port_destroy(&mktty_spawn.port);
	}
}

/*
 * =============================================================================
 * Module init/exit
 * =============================================================================
 */

static int __init mktty_init(void)
{
	int id = root_instance ? root_instance->id : 0;
	return (id == 0) ? mktty_host_init() : mktty_spawn_init();
}

static void __exit mktty_exit(void)
{
	int id = root_instance ? root_instance->id : 0;
	if (id == 0)
		mktty_host_cleanup();
	else
		mktty_spawn_cleanup();
}

module_init(mktty_init);
module_exit(mktty_exit);

MODULE_DESCRIPTION("Multikernel TTY driver");
MODULE_LICENSE("GPL");

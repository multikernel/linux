// SPDX-License-Identifier: GPL-2.0-only
/* Production kernfs callbacks; DT generation and kernfs I/O are boundaries. */
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

struct mk_instance { const char *name; };
struct kernfs_node { void *priv; };
struct kernfs_open_file { struct kernfs_node *kn; };
struct seq_file { char data[32]; size_t count; };

static struct mk_instance root = { "root" }, child = { "child" };
static struct mk_instance *mk_self = &root;
static struct mk_instance *expected_instance;
static pthread_mutex_t mk_overlay_mutex = PTHREAD_MUTEX_INITIALIZER;
static _Thread_local bool snapshot_locked;
static const char snapshot[] = "dtb-snapshot";
static unsigned int failures, generated, allocated, freed;
static int generation_error;

#define CHECK(condition) do { \
	if (!(condition)) { \
		fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); \
		failures++; \
	} \
} while (0)
#define pr_err(...) do { } while (0)
#define min(a, b) ((a) < (b) ? (a) : (b))

static inline int mutex_trylock(pthread_mutex_t *mutex)
{
	int ret = pthread_mutex_trylock(mutex);

	CHECK(ret == 0 || ret == EBUSY);
	if (!ret)
		snapshot_locked = true;
	return !ret;
}

/* Keep a blocking-lock regression runnable: the runner bounds its lifetime. */
static inline __attribute__((unused)) void mutex_lock(pthread_mutex_t *mutex)
{
	CHECK(pthread_mutex_lock(mutex) == 0);
	snapshot_locked = true;
}

static inline void mutex_unlock(pthread_mutex_t *mutex)
{
	CHECK(snapshot_locked);
	snapshot_locked = false;
	CHECK(pthread_mutex_unlock(mutex) == 0);
}

static int mk_dt_generate_instance_dtb(struct mk_instance *instance,
				     void **data, size_t *size)
{
	int ret;

	generated++;
	CHECK(instance == expected_instance);
	/* Assert exclusion without touching mutable kernel resource containers. */
	CHECK(snapshot_locked);
	ret = pthread_mutex_trylock(&mk_overlay_mutex);
	CHECK(ret == EBUSY);
	if (!ret)
		pthread_mutex_unlock(&mk_overlay_mutex);
	if (generation_error)
		return generation_error;
	*data = malloc(sizeof(snapshot) - 1);
	if (!*data) {
		perror("malloc");
		exit(2);
	}
	allocated++;
	memcpy(*data, snapshot, sizeof(snapshot) - 1);
	*size = sizeof(snapshot) - 1;
	return 0;
}

static void kfree(void *data)
{
	if (data)
		freed++;
	free(data);
}

static void seq_write(struct seq_file *sf, const void *data, size_t size)
{
	CHECK(size <= sizeof(sf->data));
	if (size <= sizeof(sf->data)) {
		memcpy(sf->data, data, size);
		sf->count = size;
	}
}

#include "kernfs-snapshot-production.h"

static void check_released(void)
{
	int ret = pthread_mutex_trylock(&mk_overlay_mutex);

	CHECK(!snapshot_locked);
	CHECK(ret == 0);
	if (!ret)
		pthread_mutex_unlock(&mk_overlay_mutex);
	CHECK(allocated == freed);
}

static void check_reads(void)
{
	struct kernfs_node kn = { &child };
	struct kernfs_open_file of = { &kn };
	struct seq_file sf = { 0 };
	char buf[32] = { 0 };

	expected_instance = &root;
	CHECK(root_device_tree_seq_show(&sf, NULL) == 0);
	CHECK(sf.count == sizeof(snapshot) - 1);
	CHECK(!memcmp(sf.data, snapshot, sizeof(snapshot) - 1));
	check_released();
	expected_instance = &child;
	CHECK(instance_device_tree_read(&of, buf, sizeof(buf), 0) ==
	      sizeof(snapshot) - 1);
	CHECK(!memcmp(buf, snapshot, sizeof(snapshot) - 1));
	check_released();
	CHECK(instance_device_tree_read(&of, buf, 4, 3) == 4);
	CHECK(!memcmp(buf, snapshot + 3, 4));
	check_released();
	CHECK(instance_device_tree_read(&of, buf, sizeof(buf), sizeof(snapshot) - 1) == 0);
	check_released();
	CHECK(instance_device_tree_read(&of, buf, sizeof(buf), sizeof(snapshot) + 5) == 0);
	check_released();
	CHECK(instance_device_tree_read(&of, buf, 0, 0) == 0);
	check_released();
}

static void check_errors(void)
{
	struct kernfs_node kn = { &child };
	struct kernfs_open_file of = { &kn };
	struct seq_file sf = { 0 };
	char buf[32] = "unchanged";
	const int errors[] = { -ENOMEM, -EINVAL };
	size_t i;

	for (i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
		generation_error = errors[i];
		expected_instance = &root;
		CHECK(root_device_tree_seq_show(&sf, NULL) == errors[i]);
		CHECK(sf.count == 0);
		check_released();
		expected_instance = &child;
		CHECK(instance_device_tree_read(&of, buf, sizeof(buf), 0) == errors[i]);
		CHECK(!strcmp(buf, "unchanged"));
		check_released();
	}
	generation_error = 0;
}

static void *check_busy_reads(void *unused)
{
	struct kernfs_node kn = { &child };
	struct kernfs_open_file of = { &kn };
	struct seq_file sf = { 0 };
	char buf[32] = "unchanged";
	unsigned int before = generated;

	expected_instance = &root;
	CHECK(root_device_tree_seq_show(&sf, NULL) == -EAGAIN);
	CHECK(sf.count == 0);
	CHECK(generated == before);
	expected_instance = &child;
	CHECK(instance_device_tree_read(&of, buf, sizeof(buf), 0) == -EAGAIN);
	CHECK(!strcmp(buf, "unchanged"));
	CHECK(generated == before);
	CHECK(!snapshot_locked);
	return NULL;
}

int main(void)
{
	pthread_t reader;
	int ret;

	check_reads();
	check_errors();
	/* Model a controller holding the resource lock while kernfs drains. */
	CHECK(pthread_mutex_lock(&mk_overlay_mutex) == 0);
	ret = pthread_create(&reader, NULL, check_busy_reads, NULL);
	if (ret) {
		fprintf(stderr, "pthread_create: %s\n", strerror(ret));
		return 2;
	}
	ret = pthread_join(reader, NULL);
	if (ret) {
		fprintf(stderr, "pthread_join: %s\n", strerror(ret));
		return 2;
	}
	CHECK(pthread_mutex_unlock(&mk_overlay_mutex) == 0);
	check_released();
	/* Retry the same callbacks after the controller lets go. */
	check_reads();
	if (failures) {
		fprintf(stderr, "%u kernfs snapshot assertion(s) failed\n", failures);
		return 1;
	}
	puts("PASS: production kernfs snapshot exclusion, contention, retry, errors and reads");
	return 0;
}

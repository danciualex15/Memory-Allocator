// SPDX-License-Identifier: BSD-3-Clause

#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include "osmem.h"
#include "block_meta.h"


#define ALIGMENT 8
#define MMAP_THRESHOLD 131072
#define PAGE_SIZE 4096

struct block_meta *header;
struct block_meta *tail;
int prealloc = 8;

size_t alignning(size_t size)
{
	return (size + ALIGMENT - 1) & ~(ALIGMENT - 1);
}

void add_to_list(struct block_meta *new_block)
{
	if (new_block == NULL)
		return;
	if (header == NULL) {
		header = new_block;
		tail = new_block;
		new_block->next = NULL;
		new_block->prev = NULL;
		return;
	}
	if (header == new_block || tail == new_block)
		return;
	tail->next = new_block;
	new_block->prev = tail;
	tail = new_block;
}

struct block_meta *find_best_block(size_t size)
{
	struct block_meta *iter = header;
	struct block_meta *best_block = NULL;

	// find best memory block (the one with the closest size to the requested one)
	while (iter != NULL) {
		if (iter->status == STATUS_FREE && iter->size >= size) {
			if (best_block == NULL)
				best_block = iter;
			if (best_block->size > iter->size - size)
				best_block = iter;
		}
		iter = iter->next;
	}

	return best_block;
}

void merge_free_blocks(void)
{
	struct block_meta *iter = header;
	struct block_meta *iter_next = NULL;

	if (iter == NULL)
		return;
	if (iter->next == NULL)
		return;
	iter_next = iter->next;
	while (iter != NULL) {
		iter_next = iter->next;
		if (iter_next != NULL) {
			if (iter->status == STATUS_FREE && iter_next->status == STATUS_FREE) {
				iter->size += iter_next->size + alignning(sizeof(struct block_meta));
				if (iter_next != tail) {
					iter->next = iter_next->next;
					iter_next->next->prev = iter;
				} else {
					iter->next = NULL;
					tail = iter;
				}
				continue;
			}
		}
		iter = iter_next;
	}
}

// do split on a block with the desired/ necessary size
void split_big_mem_block(struct block_meta *mem_block, size_t size)
{
	// don't want to split a block bigger or equal with it's size or if it is FREE or MMAPED
	if (mem_block->size <= alignning(size) + alignning(sizeof(struct block_meta))
		|| (mem_block->status == STATUS_FREE || mem_block->status == STATUS_MAPPED))
		return;
	struct block_meta *new_block = (struct block_meta *)((char *)mem_block
							+ sizeof(struct block_meta) + alignning(size));
	new_block->size = mem_block->size - alignning(size) - sizeof(struct block_meta);
	new_block->status = STATUS_FREE;
	new_block->next = mem_block->next;
	new_block->prev = mem_block;

	if (mem_block->next != NULL)
		mem_block->next->prev = new_block;
	mem_block->next = new_block;
	mem_block->size = size;

	if (tail == mem_block)
		tail = new_block;
}


void *cs_malloc(size_t size)
{
	// always make sure to merge all continuous free blocks before working on the list
	merge_free_blocks();

	if (size <= 0)
		return NULL;

	size = alignning(size);

	struct block_meta *new_mem_block = NULL;

	new_mem_block = find_best_block(size);

	if (size >= MMAP_THRESHOLD) {
		size_t acctual_size = alignning(size) + alignning(sizeof(struct block_meta));

		new_mem_block = mmap(NULL, acctual_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		DIE(new_mem_block == MAP_FAILED, "mmap");
		new_mem_block->size = size;
		new_mem_block->status = STATUS_MAPPED;

		new_mem_block->next = NULL;
		new_mem_block->prev = NULL;

		add_to_list(new_mem_block);
		return (void *)(new_mem_block + 1);
	}

	if (new_mem_block != NULL) {
		new_mem_block->status = STATUS_ALLOC;
		if (new_mem_block->size <= size)
			return (void *)(new_mem_block + 1);
		split_big_mem_block(new_mem_block, size);
		merge_free_blocks();
		return (void *)(new_mem_block + 1);
	}

	if (tail != NULL) {
		if (tail->status == STATUS_FREE && new_mem_block == NULL) {
			size_t last_free_size = alignning(size) - alignning(tail->size);

			new_mem_block = sbrk(last_free_size);
			DIE(new_mem_block == (void *)-1, "sbrk");
			tail->status = STATUS_ALLOC;
			tail->size = size;
			return (void *)(tail + 1);
		}
	}

	new_mem_block = NULL;

	// if pre-allocating didn't take place and size of allocation is smaller than MMAP_TRESHOLD
	if (size < MMAP_THRESHOLD && prealloc == 8) {
		prealloc = 1;
		new_mem_block = sbrk(0);
		new_mem_block = sbrk(MMAP_THRESHOLD);
		DIE(new_mem_block == (void *)-1, "sbrk");
		new_mem_block->size = MMAP_THRESHOLD - sizeof(struct block_meta); // acctual size
		new_mem_block->status = STATUS_ALLOC;
		new_mem_block->next = NULL;
		new_mem_block->prev = NULL;
		add_to_list(new_mem_block);
		new_mem_block->status = STATUS_ALLOC;
		return (void *)(new_mem_block + 1);
	} else if (size >= MMAP_THRESHOLD) {
		size_t acctual_size = alignning(size) + alignning(sizeof(struct block_meta));

		new_mem_block = mmap(NULL, acctual_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		DIE(new_mem_block == MAP_FAILED, "mmap");
		new_mem_block->size = size;
		new_mem_block->status = STATUS_MAPPED;

		new_mem_block->next = NULL;
		new_mem_block->prev = NULL;

		add_to_list(new_mem_block);
		return (void *)(new_mem_block + 1);
		// if pre-allocation happened but the size is smaller than MMAP_TRESHOLD
	} else if (size < MMAP_THRESHOLD) {
		size_t actual_size = alignning(size) + alignning(sizeof(struct block_meta));

		new_mem_block = sbrk(actual_size);
		DIE(new_mem_block == (void *)-1, "sbrk");
		new_mem_block->status = STATUS_ALLOC;
		new_mem_block->size = size;

		new_mem_block->next = NULL;
		new_mem_block->prev = NULL;

		add_to_list(new_mem_block);
		return (void *)(new_mem_block + 1);
	}

	return NULL;
}

void cs_free(void *ptr)
{
	if (ptr == NULL)
		return;

	struct block_meta *del_block = ptr - alignning(sizeof(struct block_meta));

	// based on the allocation type, it will free the desired memory
	if (del_block->status == STATUS_ALLOC) {
		del_block->status = STATUS_FREE;
	} else if (del_block->status == STATUS_MAPPED) {
		size_t total_size = alignning(del_block->size) + alignning(sizeof(struct block_meta));

		int mun_res = munmap(del_block, total_size);

		DIE(mun_res == -1, "munmap");
		if (header == tail) {
			header = NULL;
			tail = NULL;
		}
	}
}

void *cs_calloc(size_t nmemb, size_t size)
{
	struct block_meta *new_mem_block = NULL;

	merge_free_blocks();

	if (nmemb * size <= 0)
		return NULL;

	size = alignning(size * nmemb);

	new_mem_block = find_best_block(size);

	if (new_mem_block != NULL) {
		new_mem_block->status = STATUS_ALLOC;
		if (new_mem_block->size <= size)
			return memset((void *)(new_mem_block + 1), 0, alignning(size));
		split_big_mem_block(new_mem_block, size);
		merge_free_blocks();
		return memset((void *)(new_mem_block + 1), 0, alignning(size));
	}

	if (tail != NULL) {
		if (tail->status == STATUS_FREE && new_mem_block == NULL) {
			size_t last_free_size = alignning(alignning(size) - alignning(tail->size));

			new_mem_block = sbrk(last_free_size);
			DIE(new_mem_block == (void *)-1, "sbrk");
			tail->status = STATUS_ALLOC;
			tail->size = size;
			split_big_mem_block(tail, size);
			return memset((void *)(tail + 1), 0, alignning(size));
		}
	}

	new_mem_block = NULL;

	if (size < PAGE_SIZE - alignning(sizeof(struct block_meta)) && prealloc == 8) {
		prealloc = 1;
		new_mem_block = sbrk(0);
		new_mem_block = sbrk(MMAP_THRESHOLD);
		DIE(new_mem_block == (void *)-1, "sbrk");
		new_mem_block->size = MMAP_THRESHOLD - sizeof(struct block_meta); // acctual size
		new_mem_block->status = STATUS_ALLOC;
		new_mem_block->next = NULL;
		new_mem_block->prev = NULL;
		add_to_list(new_mem_block);
		new_mem_block->status = STATUS_ALLOC;
		return memset((void *)(new_mem_block + 1), 0, alignning(size));
	} else if (size >= PAGE_SIZE - alignning(sizeof(struct block_meta))) {
		size_t acctual_size = alignning(size) + alignning(sizeof(struct block_meta));

		new_mem_block = mmap(NULL, acctual_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		DIE(new_mem_block == MAP_FAILED, "mmap");
		new_mem_block->size = size;
		new_mem_block->status = STATUS_MAPPED;

		new_mem_block->next = NULL;
		new_mem_block->prev = NULL;

		add_to_list(new_mem_block);
		return memset((void *)(new_mem_block + 1), 0, alignning(size));
	} else if (size < PAGE_SIZE - alignning(sizeof(struct block_meta))) {
		size_t actual_size = alignning(size) + alignning(sizeof(struct block_meta));

		new_mem_block = sbrk(actual_size);
		DIE(new_mem_block == (void *)-1, "sbrk");
		new_mem_block->status = STATUS_ALLOC;
		new_mem_block->size = size;

		new_mem_block->next = NULL;
		new_mem_block->prev = NULL;

		add_to_list(new_mem_block);
		return memset((void *)(new_mem_block + 1), 0, alignning(size));
	}

	return NULL;
}

void *cs_realloc(void *ptr, size_t size)
{
	// checking if we don't have STATUS_FREE blocks next to each other
	merge_free_blocks();
	if (size <= 0) {
		if (ptr != NULL) {
			cs_free(ptr);
			return NULL;
		} else {
			return NULL;
		}
	} else if (ptr == NULL) {
		return cs_malloc(size);
	}
	size = alignning(size);
	struct block_meta *mem_block = (struct block_meta *)ptr - 1;

	size_t min_size = size;

	if (mem_block->size < size)
		min_size = mem_block->size;

	// if there is no difference between sizes then we return the memory block unchanged
	if (mem_block->size == size)
		return ptr;

	// case in which the required space is smaller than the given memory block
	if (size < mem_block->size) {
		if (mem_block->status == STATUS_ALLOC) {
			// if new size < org size and is allocated with sbrk => do split
			split_big_mem_block(mem_block, size);
		} else {
			void *new_location = cs_malloc(size);

			memcpy(new_location, ptr, min_size);
			cs_free(ptr);
			return new_location;
		}
	} else {
		// case in which required space is bigger than the given memory block
		if (mem_block->status == STATUS_ALLOC) {
			// if memory block is the one from the back of the list
			if (mem_block == tail) {
				size_t last_free_size = alignning(size) - alignning(tail->size);

				struct block_meta *new_mem_block = sbrk(last_free_size);

				DIE(new_mem_block == (void *)-1, "sbrk");
				tail->status = STATUS_ALLOC;
				tail->size = size;
				return (void *)(tail + 1);
				// if next block is free then try to extend to it
			} else if (mem_block->next->status == STATUS_FREE) {
				merge_free_blocks();
				if (mem_block->next->size + mem_block->size  + alignning(sizeof(struct block_meta)) > size) {
					mem_block->size += mem_block->next->size;
					mem_block->next = mem_block->next->next;
					if (mem_block->next != NULL)
						mem_block->next->prev = mem_block;
					split_big_mem_block(mem_block, size);
					// last resort do malloc
				} else {
					void *new_location = cs_malloc(size);

					memcpy(new_location, ptr, min_size);
					cs_free(ptr);
					return new_location;
				}
			} else {
				void *new_location = cs_malloc(size);

				memcpy(new_location, ptr, min_size);
				cs_free(ptr);
				return new_location;
			}
		} else {
			void *new_location = cs_malloc(size);

			memcpy(new_location, ptr, min_size);
			cs_free(ptr);
			return new_location;
		}
	}
	return ptr;
}

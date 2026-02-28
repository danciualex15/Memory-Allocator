# Memory Allocator

A custom memory allocator for Linux that provides `malloc`-like functionality with optimized memory management.

## Features

- **Dynamic Memory Allocation**: Allocates memory blocks with `cs_malloc()`
- **Memory Deallocation**: Frees allocated memory with `cs_free()`
- **Bulk Allocation**: Allocates and zero-initialize memory with `cs_calloc()`
- **Memory Resizing**: Resizes existing allocations with `cs_realloc()`

## Architecture

### Core Components

#### Block Metadata
Each allocated block is prefixed with metadata (`struct block_meta`) containing:
- `size`: Size of the usable memory (bytes)
- `status`: Block state (FREE, ALLOCATED, or MAPPED)
- `prev`: Pointer to previous block
- `next`: Pointer to next block

#### Block Status
- `STATUS_FREE(0)`: Block is free and available for reallocation
- `STATUS_ALLOC(1)`: Block is allocated via `sbrk()`
- `STATUS_MAPPED(2)`: Block is allocated via `mmap()`

## Allocation Strategy

| Allocation Size | Method | Threshold |
|---|---|---|
| < 128 KB (first time) | `sbrk()` with 128KB pre-allocation | PAGE_SIZE |
| < 128 KB (subsequent) | Reuse from heap or `sbrk()` | MMAP_THRESHOLD |
| ≥ 128 KB | `mmap()` | MMAP_THRESHOLD |

## API Reference

### `cs_malloc(size_t size)`
Allocates a block of memory of at least `size` bytes.
- **Returns**: Pointer to allocated memory, or NULL on failure
- **Alignment**: 8-byte aligned
- **Behavior**: Uses best-fit block selection from heap or allocates new memory

### `cs_free(void *ptr)`
Deallocates previously allocated memory.
- **Parameter**: Pointer to memory block (from `cs_malloc`, `cs_calloc`, or `cs_realloc`)
- **Behavior**: Marks block as free for reuse or unmaps if allocated via `mmap()`

### `cs_calloc(size_t nmemb, size_t size)`
Allocates memory for `nmemb` elements of `size` bytes each and initializes to zero.
- **Returns**: Pointer to allocated and zeroed memory, or NULL on failure
- **Alignment**: 8-byte aligned
- **Behavior**: Same as `cs_malloc()` but with `memset()` to zero

### `cs_realloc(void *ptr, size_t size)`
Resizes an existing memory allocation.
- **Parameter**: Pointer to previously allocated memory
- **Returns**: Pointer to resized memory, or NULL on failure
- **Behavior**: 
  - If `ptr` is NULL: behaves like `cs_malloc()`
  - If `size` is 0: behaves like `cs_free()` and returns NULL
  - If new size equals old size: returns unchanged
  - If shrinking: splits block if allocated with `sbrk()`
  - If growing: extends in-place if possible, otherwise allocates new block

## Implementation Details

### Internal Functions

- `alignning(size_t size)`: Aligns size to 8-byte boundary
- `add_to_list(struct block_meta *block)`: Adds block to linked list
- `find_best_block(size_t size)`: Finds best-fit free block
- `split_big_mem_block(struct block_meta *block, size_t size)`: Splits oversized block
- `merge_free_blocks(void)`: Coalesces adjacent free blocks
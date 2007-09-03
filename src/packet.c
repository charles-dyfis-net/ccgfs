/*
 *	CC Network Filesystem (ccgfs)
 *
 *	© Jan Engelhardt <jengelh@computergmbh.de>, 2007
 *
 *	This file is part of CCGFS. CCGFS is free software; you can
 *	redistribute it and/or modify it under the terms of the GNU
 *	General Public License as published by the Free Software
 *	Foundation; either version 2 or 3 of the License.
 */
#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "packet.h"

/*
 * @type:	type
 * @length:	desired initial length (without header)
 */
struct lo_packet *pkt_init(unsigned int type, unsigned int length)
{
	struct ccgfs_pkt_header *hdr;
	struct lo_packet *pkt;

	length += sizeof(*hdr);
	if ((pkt = malloc(sizeof(*pkt))) == NULL) {
		fprintf(stderr, "%s: malloc(): %s\n",
		        __func__, strerror(errno));
		abort();
	}
	if ((hdr = pkt->data = malloc(length)) == NULL) {
		fprintf(stderr, "%s: malloc(): %s\n",
		        __func__, strerror(errno));
		abort();
	}
	pkt->alloc  = length;
	pkt->length = sizeof(*hdr);
	pkt->shift  = sizeof(*hdr);
	hdr->opcode = cpu_to_le32(type);
	return pkt;
}

/*
 * @size:	new size, including header
 */
void *pkt_resize(struct lo_packet *pkt, unsigned int size)
{
	void *nu = realloc(pkt->data, size);
	if (nu == NULL) {
		fprintf(stderr, "%s: realloc(): %s\n",
		        __func__, strerror(errno));
		abort();
	}
	pkt->alloc = size;
	pkt->data  = nu;
	return nu;
}

static inline void pkt_resize_plus(struct lo_packet *pkt, unsigned int size)
{
	pkt_resize(pkt, pkt->length + size + size / 4);
	return;
}

static inline uint32_t deref_get_32(const void *ptr)
{
	uint32_t ret;
	memcpy(&ret, ptr, sizeof(ret));
	return ret;
}

static inline uint64_t deref_get_64(const void *ptr)
{
	uint64_t ret;
	memcpy(&ret, ptr, sizeof(ret));
	return ret;
}

static inline void deref_put_32(void *ptr, uint32_t value)
{
	memcpy(ptr, &value, sizeof(value));
	return;
}

/*
 * pkt_push - push an object into the buffer
 * @pkt:	packet buffer to operate on
 *
 */
void pkt_push(struct lo_packet *pkt, const void *input_data,
    unsigned int input_length, unsigned int type)
{
	unsigned int nsz;
	void *dest;

	nsz = input_length + sizeof(uint32_t);

	if (input_length >= 0x7F000000) {
		fprintf(stderr, "%s: length too big\n", __func__);
		abort();
	}

	if (pkt->length + nsz > pkt->alloc)
		pkt_resize_plus(pkt, nsz);

	dest = pkt->data + pkt->length;
	switch (type) {
		case PT_DATA:
			deref_put_32(dest,
				cpu_to_le32(input_length | (1 << 31)));
			memcpy(dest + sizeof(uint32_t), input_data, input_length);
			break;
		default:
			deref_put_32(dest, cpu_to_le32(type));
			memcpy(dest + sizeof(uint32_t), input_data, input_length);
			break;
	}
	pkt->length += nsz;
	return;
}

/*
 * pkt_shift_32 - get the next object
 * @pkt:	packet buffer to operate on
 *
 * Verifies that the next object is a 32-bit integer object
 * and returns the value.
 */
uint32_t pkt_shift_32(struct lo_packet *pkt)
{
	uint32_t *ptr = pkt->data + pkt->shift;
	if (le32_to_cpu(deref_get_32(ptr)) != PT_32) {
		fprintf(stderr, "%s: protocol mismatch\n", __func__);
		abort();
	}
	++ptr;
	pkt->shift += 2 * sizeof(uint32_t);
	return le32_to_cpu(deref_get_32(ptr));
}

/*
 * pkt_shift_64 - get the next object
 * @pkt:	packet buffer to operate on
 *
 * Verifies that the next object is a 64-bit integer object
 * and returns the value.
 */
uint64_t pkt_shift_64(struct lo_packet *pkt)
{
	uint32_t *ptr = pkt->data + pkt->shift;

	if (le32_to_cpu(deref_get_32(ptr)) != PT_64) {
		fprintf(stderr, "%s: protocol mismatch\n", __func__);
		abort();
	}

	++ptr;
	pkt->shift += sizeof(uint32_t) + sizeof(uint64_t);
	return le64_to_cpu(deref_get_64(ptr));
}

/*
 * pkt_shift_s - get the next object
 * @pkt:	packet buffer to operate on
 *
 * Verifies that the next object is a binary blob object and returns a pointer
 * to it in the transmission buffer. Do not free it.
 */
const void *pkt_shift_s(struct lo_packet *pkt)
{
	uint32_t *ptr = pkt->data + pkt->shift;
	uint32_t data = le32_to_cpu(deref_get_32(ptr));
	uint32_t len  = data & ~PT_DATA_BIT;

	if (!(data & PT_DATA_BIT)) {
		fprintf(stderr, "%s: protocol mismatch\n", __func__);
		abort();
	}
	++ptr;
	pkt->shift += sizeof(uint32_t) + len;
	return ptr;
}

/*
 * pkt_recv - receive packet
 * @fd:	file descriptor to read
 *
 * Reads the next packet from @fd. A new lo_packet is created and returned.
 * On error, %NULL is returned, in which case the stream (@fd) will be in
 * an undefined state.
 */
struct lo_packet *pkt_recv(int fd)
{
	struct ccgfs_pkt_header *hdr;
	struct lo_packet *pkt;
	ssize_t ret;
	int err;

	pkt = pkt_init(0, 0);
	hdr = pkt->data;
	ret = read(fd, hdr, sizeof(*hdr));
	if (ret != sizeof(*hdr)) {
		err = errno;
		pkt_destroy(pkt);
		errno = err;
		return NULL;
	}

	hdr->opcode = le32_to_cpu(hdr->opcode);
	hdr->length = le32_to_cpu(hdr->length);
	hdr         = pkt_resize(pkt, hdr->length);
	pkt->length = hdr->length;

	ret = read(fd, pkt->data + sizeof(*hdr),
	      pkt->length - sizeof(*hdr));
	if (ret != pkt->length - sizeof(*hdr)) {
		err = errno;
		pkt_destroy(pkt);
		errno = err;
		return NULL;
	}
	return pkt;
}

static void __pkt_destroy(struct lo_packet *pkt)
{
	free(pkt->data);
	free(pkt);
	return;
}

/*
 * pkt_send - send packet and destroy
 * @fd:		file descriptor to write it to
 * @pkt:	packet structure
 *
 * Writes the packet length into the actual transmission buffer, sends the
 * packet out to @fd and then destroys it.
 */
void pkt_send(int fd, struct lo_packet *pkt)
{
	struct ccgfs_pkt_header *hdr = pkt->data;
	hdr->length = cpu_to_le32(pkt->length);
	write(fd, hdr, pkt->length);
	__pkt_destroy(pkt);
	return;
}

void pkt_destroy(struct lo_packet *pkt)
{
	if (pkt->shift != pkt->length) {
		fprintf(stderr, "packet %p[%u,%u] has not been "
		        "properly consumed\n",
			pkt, pkt->shift, pkt->length);
	}
	__pkt_destroy(pkt);
	return;
}

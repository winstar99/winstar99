#include <net/tcp_fec.h>

/* Codes for incoming FEC packet processing */
#define FEC_NO_LOSS		1
#define FEC_LOSS_UNRECOVERED	2
#define FEC_LOSS_RECOVERED	3

/* Receiver routines */
static int tcp_fec_process_xor(struct sock *sk, const struct sk_buff *skb,
			unsigned int block_skip);
static int tcp_fec_recover(struct sock *sk, const struct sk_buff *skb,
			unsigned char *data, u32 seq, int len);
static void tcp_fec_send_ack(struct sock *sk, const struct sk_buff *skb,
			int recovery_status);
static void tcp_fec_reduce_window(struct sock *sk);
static void tcp_fec_mark_skbs_lost(struct sock *sk);
static bool tcp_fec_update_decoded_option(struct sk_buff *skb);
static struct sk_buff *tcp_fec_make_decoded_pkt(struct sock *sk,
			const struct sk_buff *skb, unsigned char *dec_data,
			u32 seq, unsigned int len);

/* Sender routines */
static int tcp_fec_create(struct sock *sk, struct sk_buff_head *list);
static int tcp_fec_create_xor(struct sock *sk, struct sk_buff_head *list,
			unsigned int first_seq, unsigned int block_len,
			unsigned int block_skip,
			unsigned int max_encoded_per_pkt);
static struct sk_buff *tcp_fec_make_encoded_pkt(struct sock *sk,
			struct tcp_fec *fec, unsigned char *enc_data,
			u32 seq);
static int tcp_fec_xmit_all(struct sock *sk, struct sk_buff_head *list);
static int tcp_fec_xmit(struct sock *sk, struct sk_buff *skb);

/* Buffer access routine */
static unsigned int tcp_fec_get_next_block(struct sock *sk,
			struct sk_buff **skb, struct sk_buff_head *queue,
			u32 seq, unsigned int block_len,
			unsigned char *block);

/* Have to define this signature here since the actual function was static
 * and tcp_output.c has no corresponding header file
 */
extern int tcp_transmit_skb(struct sock *sk, struct sk_buff *skb, int clone_it,
			gfp_t gfp_mask);

/* Decodes FEC parameters and stores them in the FEC struct
 * @seq - sequence number of the packet
 * @ack_seq - ACKed sequence number
 * @is_syn - true, if option was attached to a packet with a SYN flag
 * @ptr - points to the first byte of the FEC option after kind, length,
 *	  and possible magic bytes
 * @len - option length (without kind, length, magic bytes)
 */
int  tcp_fec_decode_option(struct tcp_fec *fec, u32 seq, u32 ack_seq,
				bool is_syn, const unsigned char *ptr,
				unsigned int len)
{
	/* reset / initialize option values which should be evaluated
	 * with EVERY incoming packet
	 */
	fec->flags = 0;
	fec->saw_fec = 1;

	if (len == 1) {
		/* Short option */
		u8 val = *((u8 *) ptr);
		if (is_syn) {
			/* Negotiation */
			fec->type = val;
		} else {
			/* Regular packet */
			fec->flags = val;
		}

		return 0;
	}

	if (len == 4) {
		/* Long option */
		u32 val = get_unaligned_be32(ptr);
		fec->flags = val >> 24;

		if (fec->flags & TCP_FEC_ENCODED) {
			fec->enc_seq = seq;
			fec->enc_len = val & 0xFFFFFF;
		} else if (fec->flags & TCP_FEC_RECOVERY_FAILED) {
			fec->lost_seq = ack_seq;
			fec->lost_len = val & 0xFFFFFF;
		} else {
			return -EINVAL;
		}

		return 0;
	}

	/* Invalid option length */
	return -EINVAL;
}

/* Encodes FEC parameters to wire format
 * @ptr - Encoded option is written to this memory location (and the pointer
 *        is advanced to the next unoccupied byte, 4-byte aligned)
 * Returns the length of the encoded option (including alignment)
 */
int tcp_fec_encode_option(struct tcp_sock *tp, struct tcp_fec *fec,
			__be32 **ptr)
{
	int len;

	fec->flags |= tp->fec.flags;
	fec->lost_len = tp->fec.lost_len;
	tp->fec.flags &= ~TCP_FEC_RECOVERY_CWR;
	tp->fec.flags &= ~TCP_FEC_RECOVERY_FAILED;

	/* Encode fixed option part (option kind, length, and magic bytes) */
	if (fec->flags & (TCP_FEC_ENCODED | TCP_FEC_RECOVERY_FAILED))
		len = 4 + TCPOLEN_EXP_FEC_BASE; /* Long option */
	else
		len = 1 + TCPOLEN_EXP_FEC_BASE; /* Short option */

	**ptr = htonl((TCPOPT_EXP << 24) | (len << 16) | TCPOPT_FEC_MAGIC);
	(*ptr)++;

	if ((fec->flags & TCP_FEC_ENCODED) &&
	    (fec->flags & TCP_FEC_RECOVERY_FAILED)) {
		/* TODO Special case: need to separate loss indication
		 * from encoding or make option 12 bytes long
		 * This can only happen if a node receives and sends FEC
		 * data
		 */
		fec->flags &= ~TCP_FEC_RECOVERY_FAILED;
	}

	if (fec->flags & TCP_FEC_ENCODED) {
		/* FEC-encoded packets carry:
		 * <Flags:8, Encoding length:24>
		 */
		**ptr = htonl((fec->flags << 24) |
			      (fec->enc_len));
		(*ptr)++;
		return 8;
	} else if (fec->flags & TCP_FEC_RECOVERY_FAILED) {
		/* Packets with failed recovery indication carry:
		 * <Flags:8, Bytes after ACKed seq lost:24>
		 */
		**ptr = htonl((fec->flags << 24) |
			      (fec->lost_len));
		(*ptr)++;
		return 8;
	} else if (fec->type) {
		/* Negotiation packets carry: <Encoding type:8> */
		**ptr = htonl((fec->type << 24) |
			      (TCPOPT_NOP << 16) |
			      (TCPOPT_NOP << 8) |
			      TCPOPT_NOP);
		(*ptr)++;
		return 8;
	} else {
		/* All other packets carry: <Flags:8> */
		**ptr = htonl((fec->flags << 24) |
			      (TCPOPT_NOP << 16) |
			      (TCPOPT_NOP << 8) |
			      TCPOPT_NOP);
		(*ptr)++;
		return 8;
	}
}

/* Processes the current packet in the buffer, treated as an FEC packet
 * (assumes that options were already processed)
 */
int tcp_fec_process(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp;
	struct tcphdr *th;
	int recovery_status, err;
	u32 end_seq;

	tp = tcp_sk(sk);
	th = tcp_hdr(skb);
	recovery_status = 0;

	/* drop packet if packet is not encoded */
	if (!(tp->rx_opt.fec.flags & TCP_FEC_ENCODED))
		return -1;

	/* check if all encoded packets were already received */
	end_seq = tp->rx_opt.fec.enc_seq + tp->rx_opt.fec.enc_len;
	if (!after(end_seq, tp->rcv_nxt)) {
		tcp_fec_send_ack(sk, skb, FEC_NO_LOSS);
		return 0;
	}

	/* linearize the SKB (for easier payload access) */
	err = skb_linearize(skb);
	if (err)
		return err;

	/* data recovery */
	switch (tp->fec.type) {
	case TCP_FEC_TYPE_NONE:
		return -1;
	case TCP_FEC_TYPE_XOR_ALL:
		recovery_status = tcp_fec_process_xor(sk, skb, 0);
		break;
	case TCP_FEC_TYPE_XOR_SKIP_1:
		recovery_status = tcp_fec_process_xor(sk, skb, 1);
		break;
	}

	/* TODO error handling; -ENOMEM, etc. - disable FEC? */
	if (recovery_status < 0)
		return recovery_status;

	/* Send an explicit ACK if recovery failed */
	if (recovery_status == FEC_LOSS_UNRECOVERED)
		tcp_fec_send_ack(sk, skb, recovery_status);

	return 0;
}

/* Checks the received options for loss indicators and acts upon them.
 * In particular, the function handles recovery flags (indicators for
 * successful and failed recoveries, tail losses)
 * Returns: 1, if ACK contains a loss indicator
 */
int tcp_fec_check_ack(struct sock *sk, u32 ack_seq)
{
	struct tcp_sock *tp;

	tp = tcp_sk(sk);

	/* Clear local recovery indication (and ECN CWR demand)
	 * if it was ACKED by the other node
	 */
	if (tp->rx_opt.fec.flags & TCP_FEC_RECOVERY_CWR) {
		tp->fec.flags &= ~TCP_FEC_RECOVERY_SUCCESSFUL;
		tp->ecn_flags &= ~TCP_ECN_DEMAND_CWR;
	}

	/* Check for tail loss indicators
	 * This happens when FEC was unable to recover the lost data and
	 * thus only sends an ACK with the loss range back. Everything not
	 * ACKed/SACKed now, is considered lost now.
	 */
	if (tp->rx_opt.fec.flags & TCP_FEC_RECOVERY_FAILED) {
		tcp_fec_mark_skbs_lost(sk);
		return 1;
	}

	/* Check if the remote endpoint successfully recovered data,
	 * if so we trigger a window reduction
	 */
	if (tp->rx_opt.fec.flags & TCP_FEC_RECOVERY_SUCCESSFUL) {
		/* Ignore flag if window was already reduced for the current
		 * loss episode or if previous reduction was not signaled
		 * yet (no outgoing packets)
		 */
		if (after(ack_seq, tp->high_seq) &&
				!(tp->fec.flags & TCP_FEC_RECOVERY_CWR)) {
			/* tcp_fec_reduce_window(sk); */
			tp->fec.flags |= TCP_FEC_RECOVERY_CWR;
		}

		return 1;
	}

	return 0;
}

/* Since data in the socket's receive queue can get consumed by other parties
 * we need to clone these SKBs until they are no longer required for possible
 * future recoveries. This function is called after the TCP header has been
 * removed from the SKB already. All parameters required for recovery are
 * stored in the SKB's control buffer.
 * @skb - buffer which is moved to the receive queue
 */
int tcp_fec_update_queue(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp;
	struct sk_buff *cskb;
	u32 data_len;
	int extra_bytes, err;
	tp = tcp_sk(sk);

	/* clone the SKB and add it to the FEC receive queue
	 * (a simple extra reference to the SKB is not sufficient since
	 * since SKBs can only be queued on one list at a time)
	 */
	cskb = skb_clone(skb, GFP_ATOMIC);
	if (cskb == NULL)
		return -ENOMEM;

	/* linearize the SKB (for easier payload access) */
	err = skb_linearize(cskb);
	if (err)
		return err;

	data_len = skb->len;
	if (!data_len) {
		kfree_skb(cskb);
		return 0;
	}

	skb_queue_tail(&tp->fec.rcv_queue, cskb);
	tp->fec.bytes_rcv_queue += data_len;

	/* check if we can dereference old SKBs (as long as we have enough
	 * data for future recoveries)
	 */
	extra_bytes = tp->fec.bytes_rcv_queue - FEC_RCV_QUEUE_LIMIT;
	while (extra_bytes > 0) {
		cskb = skb_peek(&tp->fec.rcv_queue);
		if (cskb == NULL)
			return -EINVAL;

		data_len = TCP_SKB_CB(cskb)->end_seq - TCP_SKB_CB(cskb)->seq;
		if (data_len > extra_bytes) {
			break;
		} else {
			extra_bytes -= data_len;
			tp->fec.bytes_rcv_queue -= data_len;
			skb_unlink(cskb, &tp->fec.rcv_queue);
			kfree_skb(cskb);
		}
	}

	return 0;
}

/* Disables FEC for this connection (includes clearing references
 * to buffers in receive queue)
 */
void tcp_fec_disable(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (!tcp_fec_is_enabled(tp))
		return;

	tp->fec.type = 0;
	tp->fec.bytes_rcv_queue = 0;
	skb_queue_purge(&tp->fec.rcv_queue);
}

/* Processes the current packet in the buffer, treated as an FEC packet
 * with XOR-encoded payload (assumes that options were already processed)
 * Returns: negative code, if an error occurred;
 *	positive code, otherwise (recovery status)
 * @block_skip - Number of unencoded blocks between two encoded blocks
 */
static int tcp_fec_process_xor(struct sock *sk, const struct sk_buff *skb,
			unsigned int block_skip)
{
	struct sk_buff *pskb;
	struct tcp_sock *tp;
	struct tcphdr *th;
	u32 next_seq, end_seq, rec_seq;
	unsigned char *data, *block;
	unsigned int i, offset, data_len, block_len, rec_len;
	bool seen_loss;
	int ret;

	pskb = NULL;
	tp = tcp_sk(sk);
	th = tcp_hdr(skb);
	next_seq = tp->rx_opt.fec.enc_seq;
	end_seq = next_seq + tp->rx_opt.fec.enc_len;
	block_len = skb->len - tcp_hdrlen(skb);
	seen_loss = false;
	offset = 0;

	/* memory allocation for decoding / recovered SKB data */
	data = kmalloc(2 * block_len, GFP_ATOMIC);
	if (data == NULL)
		return -ENOMEM;

	block = data + block_len;

	/* copy FEC payload (skip TCP header) */
	memcpy(data, skb->data + tcp_hdrlen(skb), block_len);

	/* process in-sequence data */
	while ((data_len = tcp_fec_get_next_block(sk, &pskb,
				&tp->fec.rcv_queue, next_seq,
				min(block_len, end_seq - next_seq),
				block))) {
		next_seq += data_len;

		/* XOR with existing payload */
		for (i = 0; i < data_len; i++)
			data[i] ^= block[i];

		/* we could no read a whole MSS block, which means we
		 * reached the end of the queue or end of range which the
		 * FEC packet covers
		 */
		if (data_len < block_len)
			break;

		/* skip unencoded blocks if there is more data encoded */
		if (end_seq - next_seq > 0)
			next_seq += block_len * block_skip;
	}

	/* check if all encoded bytes were already received */
	if (next_seq == end_seq) {
		kfree(data);
		return FEC_NO_LOSS;
	}

	/* we always recover one whole MSS block (otherwise slicing
	 * would introduce a lot of additional complexity here) and handle
	 * cut out already received sequences later
	 */
	rec_seq = next_seq;
	rec_len = min(block_len, end_seq - rec_seq);
	offset  = data_len;
	if ((rec_seq + rec_len) == end_seq)
		goto recover;

	next_seq += block_len * (block_skip + 1);
	pskb = NULL;

	/* read a possibly partial (smaller than MSS) block to fill up the
	 * previously unfilled block and achieve alignment again
	 */
	data_len = tcp_fec_get_next_block(sk, &pskb, &tp->out_of_order_queue,
				next_seq, block_len - offset, block);

	next_seq += data_len;

	/* check if we could not read as much data as requested */
	if ((next_seq != end_seq) && (data_len < (block_len - offset)))
		goto clean;

	/* XOR with existing payload */
	for (i = 0; i < data_len; i++)
		data[i+offset] ^= block[i];

	/* skip unencoded blocks if there is more data encoded */
	if (end_seq - next_seq > 0)
		next_seq += block_len * block_skip;

	/* read all necessary blocks to finish decoding */
	while ((data_len = tcp_fec_get_next_block(sk, &pskb,
				&tp->out_of_order_queue, next_seq,
				min(block_len, end_seq - next_seq),
				block))) {
		next_seq += data_len;

		/* XOR with existing payload */
		for (i = 0; i < data_len; i++)
			data[i] ^= block[i];

		/* we could not read a whole MSS block, which means we reached
		 * the end of the queue or end of range which the FEC packet
		 * covers
		 */
		if (data_len < block_len)
			break;

		/* skip unencoded blocks if there is more data encoded */
		if (end_seq - next_seq > 0)
			next_seq += block_len * block_skip;
	}

	/* check if additional losses were observed (cannot recover) */
	if (next_seq != end_seq)
		goto clean;

recover:
	/* create and process recovered packets */
	for (i = 0; i < rec_len; i++)
		block[i] = data[(offset + i) % block_len];

	if (block_skip && ((block_len - offset) < rec_len)) {
		/* recover non-consecutive sequence ranges (only when
		 * slicing is used)
		 */
		u32 second_seq;
		unsigned int second_seq_len, first_seq_len;

		first_seq_len = block_len - offset;
		second_seq = rec_seq + first_seq_len + block_len * block_skip;
		second_seq_len = rec_len - first_seq_len;

		ret = tcp_fec_recover(sk, skb, block, rec_seq, first_seq_len);
		if (ret >= 0) {
			int second_ret = tcp_fec_recover(sk, skb,
						block + first_seq_len,
						second_seq, second_seq_len);
			if (second_ret < 0 || !ret)
				ret = second_ret;
		}
	} else {
		ret = tcp_fec_recover(sk, skb, block, rec_seq, rec_len);
	}

	kfree(data);
	return ret ? ret : FEC_LOSS_RECOVERED;

clean:
        kfree(data);
        return FEC_LOSS_UNRECOVERED;
}

/* Create a recovered packet and forward it to the reception routine */
static int tcp_fec_recover(struct sock *sk, const struct sk_buff *skb,
		unsigned char *data, u32 seq, int len)
{
	struct sk_buff *rskb;
	struct tcp_sock *tp;

	tp = tcp_sk(sk);

	/* We will notify the remote node that recovery was successful */
	tp->fec.flags |= TCP_FEC_RECOVERY_SUCCESSFUL;

	/* Check if we received some tail of the recovered sequence already
	 * by looking at the current SACK blocks (we don't want to recover
	 * more data than necessary to prevent DSACKS)
	 */
	if (tcp_is_sack(tp)) {
		int i;
		for (i = 0; i < tp->rx_opt.num_sacks; i++) {
			if (before(tp->selective_acks[i].start_seq,
				   seq + len) &&
			   !before(tp->selective_acks[i].end_seq,
				   seq + len)) {
				len = tp->selective_acks[i].start_seq - seq;
				break;
			}
		}
	}

	/* We might have prematurely asked for a recovery in the case where the
	 * whole recovery sequence is already covered by SACKs
	 */
	if (len <= 0)
		return FEC_NO_LOSS;

	/* Create decoded packet and forward to reception routine */
	rskb = tcp_fec_make_decoded_pkt(sk, skb, data, seq, len);
	if (rskb == NULL)
		return -EINVAL;

	return tcp_rcv_established(sk, rskb, tcp_hdr(rskb), rskb->len);
}

/* Sends an ACK for the FEC packet and encodes any congestion or
 * and/or recovery information
 */
static void tcp_fec_send_ack(struct sock *sk, const struct sk_buff *skb,
				int recovery_status)
{
	struct tcp_sock *tp;
	u32 end_seq;

	tp = tcp_sk(sk);

	/* Right now we only need an outgoing ACK if FEC recovery failed,
	 * in all other cases ACKs are implicitly generated
	 */
	switch (recovery_status) {
	case FEC_LOSS_UNRECOVERED:
		end_seq = tp->rx_opt.fec.enc_seq + tp->rx_opt.fec.enc_len;
		tp->fec.flags |= TCP_FEC_RECOVERY_FAILED;
		tp->fec.lost_len = end_seq - tp->rcv_nxt;
		tcp_send_ack(sk);
		break;
	}
}

/* Reduces the congestion window (similar to completed fast recovery)
 * If the node is already in recovery mode, undo is disabled to enforce
 * the window reduction upon completion
 */
static void tcp_fec_reduce_window(struct sock *sk)
{
	struct tcp_sock *tp;
	const struct inet_connection_sock *icsk;

	tp = tcp_sk(sk);
	icsk = inet_csk(sk);

	if (icsk->icsk_ca_state < TCP_CA_CWR) {
		tp->snd_ssthresh = icsk->icsk_ca_ops->ssthresh(sk);
		if (tp->snd_ssthresh < TCP_INFINITE_SSTHRESH) {
			tp->snd_cwnd = min(tp->snd_cwnd, tp->snd_ssthresh);
			tp->snd_cwnd_stamp = tcp_time_stamp;
		}

		/* Any future window reduction requests are ignored until
		 * snd_nxt is ACKed
		 */
		tp->high_seq = tp->snd_nxt;
		tp->undo_marker = 0;
	} else {
		/* Socket is in some congestion mode and we only need to make
		 * sure that window reduction is executed when recovery
		 * is finished
		 */
		tp->undo_marker = 0;
	}
}

/* The incoming ACK indicates a failed recovery.
 * Mark all unacked SKBs in the loss range as lost.
 * TODO With interleaved coding, we have the additional constraint
 * that the SKBs in the loss range also must have been encoded the
 * triggering FEC packet, and for that we need to keep some info
 * about FEC packets on the sender side
 */
static void tcp_fec_mark_skbs_lost(struct sock *sk)
{
	struct tcp_sock *tp;
	struct sk_buff *skb;
	u32 start_seq, end_seq;

	tp = tcp_sk(sk);
	skb = tp->lost_skb_hint ? tp->lost_skb_hint : tcp_write_queue_head(sk);

	/* All SKBs falling completely in the range are marked */
	start_seq = tp->rx_opt.fec.lost_seq;
	end_seq = tp->rx_opt.fec.lost_seq + tp->rx_opt.fec.lost_len;

	tcp_for_write_queue_from(skb, sk) {
		if (skb == tcp_send_head(sk))
			break;

		/* Past loss range */
		if (!before(TCP_SKB_CB(skb)->seq, end_seq))
			break;

		/* SKB not (fully) within range */
		if (before(TCP_SKB_CB(skb)->seq, start_seq) ||
		    after(TCP_SKB_CB(skb)->end_seq, end_seq))
			continue;

		/* SKB already marked */
		if (TCP_SKB_CB(skb)->sacked & (TCPCB_LOST|TCPCB_SACKED_ACKED))
			continue;

		/* Verify retransmit hint before marking
		 * (see tcp_verify_retransmit_hint(),
		 * copied since method defined static in tcp_input.c)
		 */
		if ((tp->retransmit_skb_hint == NULL) ||
		    before(TCP_SKB_CB(skb)->seq,
			   TCP_SKB_CB(tp->retransmit_skb_hint)->seq))
			tp->retransmit_skb_hint = skb;

		if (!tp->lost_out ||
		    after(TCP_SKB_CB(skb)->end_seq, tp->retransmit_high))
			tp->retransmit_high = TCP_SKB_CB(skb)->end_seq;

		/* Mark SKB as lost (see tcp_skb_mark_lost()) */
		tp->lost_out += tcp_skb_pcount(skb);
		TCP_SKB_CB(skb)->sacked |= TCPCB_LOST;
	}

	tcp_verify_left_out(tp);
}

/* Searches for the FEC option in the packet header and replaces
 * the long option with a short one padded by NOPs.
 * This is done to convert the option used by an encoded packet
 * to the option used by a recovered packet.
 */
static bool tcp_fec_update_decoded_option(struct sk_buff *skb)
{
	struct tcphdr *th;
	unsigned char *ptr;
	int length;

	th = tcp_hdr(skb);
	ptr = (unsigned char *) (th + 1);
	length = (th->doff * 4) - sizeof(struct tcphdr);

	while (length > 0) {
		int opcode = *ptr++;
		int opsize;

		switch (opcode) {
		case TCPOPT_EOL:
			return 0;
		case TCPOPT_NOP:
			length--;
			continue;
		default:
			opsize = *ptr++;
			if (opsize < 2 || opsize > length)
				return 0;

			if (opcode == TCPOPT_EXP &&
				get_unaligned_be16(ptr) == TCPOPT_FEC_MAGIC) {
				/* Update FEC option:
				 * 1. Convert long option into short option
				 * 2. Clear ENCODED flag (keep other flags)
				 * 3. Replace option value (long option) by NOPs
				 */
				u32 *fec_opt_start = (u32 *) (ptr - 2);
				*fec_opt_start = htonl((
					get_unaligned_be32(fec_opt_start) &
					0xFF00FFFF) | 0x00050000);
				*(fec_opt_start + 1) = htonl((
					get_unaligned_be32(fec_opt_start + 1) &
					0xEF000000) | 0x00010101);

				return 1;
			}

			ptr += opsize - 2;
			length -= opsize;
		}
	}

	return 0;
}

/* Allocates an SKB for data we want to forward to reception routines
 * (recovered data) by making a copy of the FEC SKB and replacing the data
 * part, all other segments (options, etc.) are preserved
 */
static struct sk_buff *tcp_fec_make_decoded_pkt(struct sock *sk,
				const struct sk_buff *skb,
				unsigned char *dec_data,
				u32 seq, unsigned int len)
{
	struct tcp_sock *tp;
	struct sk_buff *nskb;

	tp = tcp_sk(sk);
	nskb = skb_copy(skb, GFP_ATOMIC);
	if (nskb == NULL)
		return NULL;

	/* Update FEC option for the new packet */
	if (!tcp_fec_update_decoded_option(nskb)) {
		/* TODO Do we need this catch? Technically we don't reach this
		 * method if there is no FEC option in the header.
		 */
		return NULL;
	}

	/* check if we received some tail of the recovered sequence already
	 * by looking at the current SACK blocks (we don't want to recover
	 * more data than necessary to prevent DSACKS)
	 */
	if (tcp_is_sack(tp)) {
		int i;
		for (i = 0; i < tp->rx_opt.num_sacks; i++) {
			if (before(tp->selective_acks[i].start_seq,
				   seq + len) &&
				   !before(tp->selective_acks[i].end_seq,
				   seq + len)) {
				len = tp->selective_acks[i].start_seq - seq;
				break;
			}
		}
	}

	/* trim data section to fit recovered sequence if necessary */
	if (len < (TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq))
		skb_trim(nskb, len + tcp_hdrlen(nskb));

	/* fix the sequence numbers */
	tcp_hdr(nskb)->seq = htonl(seq);
	tcp_hdr(nskb)->ack_seq = htonl(tp->snd_una);
	TCP_SKB_CB(nskb)->seq = seq;
	TCP_SKB_CB(nskb)->end_seq = seq + len;

	/* replace SKB payload with recovered data */
	memcpy(nskb->data + tcp_hdrlen(nskb), dec_data, len);

	/* packets used for recovery had their checksums checked already */
	nskb->ip_summed = CHECKSUM_UNNECESSARY;

	return nskb;
}

/* Gets the next byte block from an SKB queue (any SKB which is touched
 * in this procedure will be linearized to simplify payload access)
 * @skb - Points to SKB from which previous block was extracted (useful
 *	  for successive calls to this function, which avoids moving through
 *	  the whole queue again)
 * @queue - SKB queue to read from (SKB has to point to an element on this
 *	  queue)
 * @seq - Sequence number of first byte in the block
 * @block_len
 * @block
 *
 * Returns the bytes written to the block memory
 */
static unsigned int tcp_fec_get_next_block(struct sock *sk,
				struct sk_buff **skb,
				struct sk_buff_head *queue, u32 seq,
				unsigned int block_len, unsigned char *block)
{
	unsigned int cur_len, offset, num_bytes;
	int err;
	u32 end_seq;

	cur_len = 0;

	/* Get first SKB of the write queue and specify next sequence to
	 * encode
	 */
	if (*skb == NULL) {
		*skb = skb_peek(queue);
		if (*skb == NULL)
			return 0;
	}

	/* move to SKB which stores the next sequence to encode */
	while (*skb) {
		/* If we observe an RST/SYN, we stop here to avoid
		 * handling corner cases
		 */
		if (TCP_SKB_CB(*skb)->tcp_flags &
					(TCPHDR_RST |
					 TCPHDR_SYN))
			return 0;
		if (!before(seq, TCP_SKB_CB(*skb)->seq) &&
					before(seq, TCP_SKB_CB(*skb)->end_seq))
			break;
		if (*skb == skb_peek_tail(queue)) {
			*skb = NULL;
			break;
		}

		*skb = skb_queue_next(queue, *skb);
	}

	if (*skb == NULL)
		return 0;

	/* copy bytes from SKBs (connected sequences) */
	while (*skb && (cur_len < block_len)) {
		err = skb_linearize(*skb);
		if (err)
			return err;

		/* Deal with the end seq number being incremented by
		 * one if the FIN flag is set (we don't want to encode this)
		 */
		end_seq = TCP_SKB_CB(*skb)->end_seq;
		if (TCP_SKB_CB(*skb)->tcp_flags & TCPHDR_FIN)
			end_seq--;

		if ((seq >= TCP_SKB_CB(*skb)->seq) && (seq < end_seq)) {
			/* Copy data depending on:
			 * - remaining space in the block
			 * - remaining data in the SKB
			 */
			offset = seq - TCP_SKB_CB(*skb)->seq;
			num_bytes = min(block_len - cur_len,
					end_seq - seq);

			memcpy(block + cur_len, (*skb)->data + offset,
			       num_bytes);
			cur_len += num_bytes;
			seq += num_bytes;
		}

		if (*skb == skb_peek_tail(queue) || cur_len >= block_len)
			break;

		*skb = skb_queue_next(queue, *skb);
	}

	return cur_len;
}

/* Arms the timer for a delayed FEC transmission if there is
 * no earlier timeout defined (i.e. retransmission timeout)
 */
void tcp_fec_arm_timer(struct sock *sk)
{
	struct inet_connection_sock *icsk;
	struct tcp_sock *tp;
	u32 delta, timeout, rtt;

	icsk = inet_csk(sk);
	tp = tcp_sk(sk);

	/* Only arm a timer if connection is established */
	if (sk->sk_state != TCP_ESTABLISHED)
		return;

	/* Forward next sequence to be encoded if unencoded data was acked */
	if (after(tp->snd_una, tp->fec.next_seq))
		tp->fec.next_seq = tp->snd_una;

	/* Don't arm the timer if there is no unencoded data left */
	if (!before(tp->fec.next_seq, tp->snd_nxt))
		return;

	/* TODO handle other timers which might be armed;
	 * EARLY_RETRANS? LOSS_PROBE?
	 */

	/* Compute timeout (currently 0.25 * RTT) */
	rtt = tp->srtt >> 3;
	timeout = rtt >> 2;

	/* Compute delay between transmission of original packet and this call
	 * (difference is subtracted from timeout value)
	 */
	delta = 0;
	if (delta > timeout) {
		tcp_fec_invoke_nodelay(sk);
		return;
	} else if (delta > 0) {
tcp_fec_invoke_nodelay(sk);
		timeout -= delta;
	}

	/* Do not replace a timeout occurring earlier */
	if (jiffies + timeout >= icsk->icsk_timeout)
		return;

	inet_csk_reset_xmit_timer(sk, ICSK_TIME_FEC, timeout, TCP_RTO_MAX);
}

/* The FEC timer fired. Force an FEC transmission for the
 * last unencoded burst. Rearm the RTO timer (which was switched
 * out when setting the FEC timer). Set a new FEC timer if there
 * is pending unencoded data.
 */
void tcp_fec_timer(struct sock *sk)
{
	struct inet_connection_sock *icsk;
	struct tcp_sock *tp;

	icsk = inet_csk(sk);
	tp = tcp_sk(sk);

	tcp_fec_invoke_nodelay(sk);

	icsk->icsk_pending = 0;
	tcp_rearm_rto(sk);

	tcp_fec_arm_timer(sk);
}

/* If FEC packet transmissions are delayed set a timer
 * (if not already set), otherwise invoke the FEC mechanism
 * immediately
 */
int tcp_fec_invoke(struct sock *sk)
{
	struct inet_connection_sock *icsk;
	struct tcp_sock *tp;

	icsk = inet_csk(sk);
	tp = tcp_sk(sk);

#ifndef TCP_FEC_DELAYED_SEND
	return tcp_fec_invoke_nodelay(sk);
#else
	/* Set the timer for sending an FEC packet if no FEC
	 * timer is active yet
	 */
	if (!icsk->icsk_pending || icsk->icsk_pending != ICSK_TIME_FEC)
		tcp_fec_arm_timer(sk);
#endif

	return 0;
}

/* Invokes the FEC mechanism set for the connection;
 * Creates and sends out FEC packets
 */
int tcp_fec_invoke_nodelay(struct sock *sk)
{
	int err;
	struct sk_buff_head *list;
	struct sk_buff *skb;
	struct tcp_fec *fec;

	list = kmalloc(sizeof(struct sk_buff_head), GFP_ATOMIC);
	if (list == NULL)
		return -ENOMEM;

	skb_queue_head_init(list);
	err = tcp_fec_create(sk, list);
	if (err)
		goto clean;

	err = tcp_fec_xmit_all(sk, list);
	if (err)
		goto clean;

clean:
	/* Purge all SKBs (purge FEC structs first) */
	skb = (struct sk_buff *) list;
	while (!skb_queue_is_last(list, skb)) {
		skb = skb_queue_next(list, skb);
		fec = TCP_SKB_CB(skb)->fec;
		if (fec != NULL) {
			kfree(fec);
			TCP_SKB_CB(skb)->fec = NULL;
		}
	}

	skb_queue_purge(list);
	kfree(list);

	/* TODO error handling; -ENOMEM, etc. - disable FEC? */

	return err;
}

/* Creates one or more FEC packets (can depend on the FEC type used)
 * and puts them in a queue
 * @list: queue head
 */
static int tcp_fec_create(struct sock *sk, struct sk_buff_head *list)
{
	struct tcp_sock *tp;
	unsigned int first_seq, block_len;
	int err;

	tp = tcp_sk(sk);

	/* Update the pointer to the first byte to be encoded next
	 * (this only matters when a packet was ACKed before it was
	 * encoded)
	 */
	if (after(tp->snd_una, tp->fec.next_seq))
		tp->fec.next_seq = tp->snd_una;

	first_seq = tp->fec.next_seq;
	block_len = tcp_current_mss(sk);

	switch (tp->fec.type) {
	case TCP_FEC_TYPE_NONE:
		return 0;
	case TCP_FEC_TYPE_XOR_ALL:
		return tcp_fec_create_xor(sk, list, first_seq,
					  block_len, 0,
					  FEC_RCV_QUEUE_LIMIT - block_len);
	case TCP_FEC_TYPE_XOR_SKIP_1:
		err = tcp_fec_create_xor(sk, list, first_seq, block_len, 1,
					  FEC_RCV_QUEUE_LIMIT - block_len);
		if (err)
			return err;

		return tcp_fec_create_xor(sk, list, first_seq + block_len,
					  block_len, 1,
					  FEC_RCV_QUEUE_LIMIT - block_len);
	}

	return 0;
}

/* Creates FEC packet(s) using XOR encoding
 * (allocates memory for the FEC structs)
 * @first_seq - Sequence number of first byte to be encoded
 * @block_len - Block length (typically MSS)
 * @block_skip - Number of unencoded blocks between two encoded blocks
 * @max_encoded_per_pkt - maximum number of blocks encoded per packet
 *	(0, if unlimited)
 */
static int tcp_fec_create_xor(struct sock *sk, struct sk_buff_head *list,
				unsigned int first_seq, unsigned int block_len,
				unsigned int block_skip,
				unsigned int max_encoded_per_pkt)
{
	struct tcp_sock *tp;
	struct sk_buff *skb, *fskb;
	struct tcp_fec *fec;
	unsigned int c_encoded;		/* Number of currently encoded blocks
					   not yet added to an FEC packet */
        unsigned int next_seq;          /* Next byte to encode */
        unsigned int i;
	unsigned char *data, *block;
	u16 data_len;

	tp = tcp_sk(sk);
	skb = NULL;
	c_encoded = 0;
	next_seq = first_seq;

	/* memory allocation
	 * data - used temporarily to obtain byte blocks and store the payload
		  (is freed before returning; we need two blocks here to store
                   the previously XORed data that has not been added to an FEC
                   packet yet, and the new to-be XORed data extracted from one
                   or more existing buffers)

	 * fec	- used to store the FEC parameters
		  (is freed after the corresponding packet is forwarded to the
		  transmission routine)
	 */
	data = kmalloc(2 * block_len, GFP_ATOMIC);
	if (data == NULL)
		return -ENOMEM;

	fec = kmalloc(sizeof(struct tcp_fec), GFP_ATOMIC);
	if (fec == NULL) {
		kfree(data);
		return -ENOMEM;
	}

	memset(data, 0, 2 * block_len);
	memset(fec, 0, sizeof(struct tcp_fec));

	block = data + block_len;

	/* encode data blocks
	 * XXX atomicity check?
	 */
	fec->enc_seq = next_seq;
	while ((data_len = tcp_fec_get_next_block(sk, &skb,
				&sk->sk_write_queue, next_seq,
				min(block_len, tp->snd_nxt - next_seq),
				block))) {
		/* Check if we reached the encoding limit; then create packet
		 * with current payload and add it to the queue
		 */
		if (max_encoded_per_pkt > 0 &&
					c_encoded >= max_encoded_per_pkt) {
			fskb = tcp_fec_make_encoded_pkt(sk, fec, data,
						block_len);
			if (fskb == NULL) {
				kfree(data);
				kfree(fec);
				return -EINVAL;
			}

			skb_queue_tail(list, fskb);
			memset(data, 0, block_len);
			c_encoded = 0;

			/* memory allocation for the FEC struct of the next
			 * packet
			 */
			fec = kmalloc(sizeof(struct tcp_fec), GFP_ATOMIC);
			if (fec == NULL) {
				kfree(data);
				return -ENOMEM;
			}

			memset(fec, 0, sizeof(struct tcp_fec));
			fec->enc_seq = next_seq;
		}

		next_seq += data_len;
		fec->enc_len = next_seq - fec->enc_seq;

		/* encode block into existing payload (XOR) */
		for (i = 0; i < data_len; i++)
			data[i] ^= block[i];

		c_encoded++;

		/* skip over blocks which are not requested for encoding */
		next_seq += block_len * block_skip;
	}

	/* create final packet if some data was selected for encoding */
	if (c_encoded > 0) {
		fskb = tcp_fec_make_encoded_pkt(sk, fec, data, block_len);
		if (fskb == NULL) {
			kfree(data);
			kfree(fec);
			return -EINVAL;
		}

		skb_queue_tail(list, fskb);
	} else {
		kfree(fec);
	}

	tp->fec.next_seq = next_seq;
	kfree(data);

	return 0;
}

/* Allocates an SKB for data we want to send and assigns
 * the necessary options and fields
 */
static struct sk_buff *tcp_fec_make_encoded_pkt(struct sock *sk,
				struct tcp_fec *fec,
				unsigned char *enc_data,
				unsigned int len)
{
	struct sk_buff *skb;
	unsigned char *data;

	/* See tcp_make_synack(); 15 probably for tail pointer etc.? */
	len = min(len, fec->enc_len);
	skb = alloc_skb(MAX_TCP_HEADER + 15 + len, GFP_ATOMIC);
	if (skb == NULL)
		return NULL;

	/* Reserve space for headers */
	skb_reserve(skb, MAX_TCP_HEADER);

	/* Specify sequence number and FEC struct address in control buffer */
	fec->flags |= TCP_FEC_ENCODED;
	TCP_SKB_CB(skb)->seq = fec->enc_seq;
	TCP_SKB_CB(skb)->fec = fec;

	/* Enable ACK flag (required for all data packets) */
	TCP_SKB_CB(skb)->tcp_flags = TCPHDR_ACK;

	/* Set GSO parameters */
	skb_shinfo(skb)->gso_segs = 1;
	skb_shinfo(skb)->gso_size = 0;
	skb_shinfo(skb)->gso_type = 0;

	/* Append payload to SKB */
	data = skb_put(skb, len);
	memcpy(data, enc_data, len);

	skb->ip_summed = CHECKSUM_PARTIAL;

	return skb;
}

/* Transmit all FEC packets in a list */
static int tcp_fec_xmit_all(struct sock *sk, struct sk_buff_head *list)
{
	struct sk_buff *skb;
	int err;

	if (list == NULL || skb_queue_empty(list))
		return 0;

	skb = (struct sk_buff *) list;
	while (!skb_queue_is_last(list, skb)) {
		skb = skb_queue_next(list, skb);
		err = tcp_fec_xmit(sk, skb);
		if (err)
			return err;
	}

	return 0;
}

/* Transmits an FEC packet */
static int tcp_fec_xmit(struct sock *sk, struct sk_buff *skb)
{
	/* TODO timers? no retransmissions, but want to deactivate FEC
	 * if we never get any FEC ACKs back
	 */
	return tcp_transmit_skb(sk, skb, 1, GFP_ATOMIC);
}

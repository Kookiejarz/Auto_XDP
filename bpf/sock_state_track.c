/* bpf/sock_state_track.c — Tracepoint program for real-time port detection.
 * Hooks inet_sock_set_state to emit events when TCP sockets enter/leave LISTEN. */

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

/* Tracepoint context structure matching /sys/kernel/tracing/events/sock/inet_sock_set_state/format */
struct inet_sock_set_state_args {
    /* Common tracepoint fields */
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __s32 common_pid;

    /* inet_sock_set_state specific fields */
    __u64 skaddr;
    __s32 oldstate;
    __s32 newstate;
    __u16 sport;        /* local port, host byte order */
    __u16 dport;
    __u16 family;
    __u16 protocol;
    __u8  saddr[4];
    __u8  daddr[4];
    __u8  saddr_v6[16];
    __u8  daddr_v6[16];
};

/* Event to emit on port transitions */
struct sock_state_event {
    __u64 ts_ns;    /* bpf_ktime_get_ns() */
    __u16 port;     /* local port, host byte order */
    __u8  proto;    /* IPPROTO_TCP = 6 */
    __u8  action;   /* 1 = entering LISTEN, 0 = leaving LISTEN */
    __u8  family;
    __u8  _pad[3];  /* zeroed padding — avoids leaking kernel memory via ringbuf */
};

#define TCP_LISTEN      10
#define IPPROTO_TCP     6

/* Ring buffer map for sock_state_event emissions */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);  /* 64 KiB */
} sock_state_rb SEC(".maps");

SEC("tp/sock/inet_sock_set_state")
int trace_inet_sock_set_state(struct inet_sock_set_state_args *args)
{
    /* Fast path: reject non-TCP traffic immediately */
    if (args->protocol != IPPROTO_TCP)
        return 0;

    /* Reject if neither oldstate nor newstate is TCP_LISTEN */
    if (args->oldstate != TCP_LISTEN && args->newstate != TCP_LISTEN)
        return 0;

    /* Reject no-op transitions */
    if (args->oldstate == args->newstate)
        return 0;

    /* Reserve space in ringbuf */
    struct sock_state_event *e = bpf_ringbuf_reserve(&sock_state_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    /* Fill event fields */
    e->ts_ns   = bpf_ktime_get_ns();
    e->port    = args->sport;
    e->proto   = IPPROTO_TCP;
    e->action  = (args->newstate == TCP_LISTEN) ? 1 : 0;
    e->family  = args->family;
    e->_pad[0] = 0;
    e->_pad[1] = 0;
    e->_pad[2] = 0;

    /* Submit event */
    bpf_ringbuf_submit(e, 0);

    return 0;
}

char _license[] SEC("license") = "GPL";

#include "atalk.h"
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>

int atalk_getname(atptr sock, atptr uaddr, int peer){
/*
    atptr sock:  low input
    int peer: low input
    atptr uaddr: low output
    secret: is the machine information
*/
    struct atalk_sock sat;
	int err = -ENOBUF;
	if (sock_flag(sock))
		goto out;

	if (peer)
	{
		err = -ENOTCON;
		if (sock->sk_state != TCP_ESTABLISHED)
			goto out;
		sat.src_node  	= sock->dst_node;
		sat.src_port	= sock->dst_port;
		sat.dst_node 	= sock->src_node;
		sat.dst_port	= sock->src_port;
	} else {
		sat.src_node  	= sock->src_node;
		sat.src_port	= sock->src_port;
		sat.dst_node 	= sock->dst_node;
		sat.dst_port	= sock->dst_port;
	}

    sat.sk_state = sock->sk_state;
	memcpy(uaddr, &sat, sizeof(sat));
	err = sizeof(struct atalk_sock);

out:
	return err;
}


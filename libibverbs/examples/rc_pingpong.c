/*
 * An example RDMA client side code. 
 * Author: Animesh Trivedi 
 *         atrivedi@apache.org
 */
/* These are basic RDMA resources */
/* These are RDMA connection related resources */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <malloc.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>
#include <getopt.h>
#include <rdma/rdma_cma.h>
#include <infiniband/verbs.h>
static struct ibv_device	*ib_dev = NULL;
static struct ibv_context *context = NULL;
static struct ibv_device      **dev_list = NULL;

static struct ibv_pd *pd = NULL;
static struct ibv_comp_channel *io_completion_channel = NULL;
static struct ibv_cq *client_cq = NULL;
static struct ibv_qp_init_attr qp_init_attr;
static struct ibv_qp *client_qp;

/* These are memory buffers related resources */
static struct ibv_mr  *client_mr = NULL;
static struct ibv_mr  *server_mr = NULL;
static struct ibv_port_attr     portinfo;
struct server_metadata local_metadata,remote_metadata;

static struct ibv_send_wr client_send_wr, client_send_wr1,client_send_wr2,client_send_wr3,client_send_wr4,*bad_client_send_wr = NULL;
static struct ibv_recv_wr server_recv_wr, *bad_server_recv_wr = NULL;
static struct ibv_sge  client_send_sge, server_recv_sge,client_send_sge1,client_send_sge2,client_send_sge3,client_send_sge4;
/* Source and Destination buffers, where RDMA operations source and sink */
char *src = NULL, *dst = NULL; 

struct server_metadata {
    int lid;
	int qpn;
	int psn;
    char gid[33];
	uint32_t		length;//数据段长度
	uint32_t		lkey;//该数据段对应的L_Key
	uint64_t		addr;//数据段所在的虚拟内存的起始地址 
};

static int check_src_dst() 
{
	return memcmp((void*) src, (void*) dst, strlen(src));
}

/* This function prepares client side connection resources for an RDMA connection */
int client_prepare_connection()
{
    int ret = 0;

    context = ibv_open_device(ib_dev);
    if(!context)
    {
        printf("open device failed!\n");
    }

    pd = ibv_alloc_pd(context);
	if (!pd) {
        printf("failed to create pd\n");
		return -errno;
	}

    io_completion_channel = ibv_create_comp_channel(context);
	if(!io_completion_channel)
    {
        printf("failed to create completion_channel\n");
        return -errno;
    }


	/* Now we create a completion queue (CQ) where actual I/O 
	 * completion metadata is placed. The metadata is packed into a structure 
	 * called struct ibv_wc (wc = work completion). ibv_wc has detailed 
	 * information about the work completion. An I/O request in RDMA world 
	 * is called "work" ;) 
	 */
	client_cq = ibv_create_cq(context /* which device*/, 
			5 /* maximum capacity*/, 
			NULL /* user context, not used here */,
			io_completion_channel /* which IO completion channel */, 
			0 /* signaling vector, not used here*/);
	if (!client_cq) {
		printf("failed to create CQ\n");
		return -errno;
	}
    printf("CQ created at %p with %d elements\n",client_cq,client_cq->cqe);

	ret = ibv_req_notify_cq(client_cq, 0);
	if (ret) {
        printf("Failed to request notifications\n");
		return -errno;
	}
       /* Now the last step, set up the queue pair (send, recv) queues and their capacity.
         * The capacity here is define statically but this can be probed from the 
	 * device. We just use a small number as defined in rdma_common.h */
       bzero(&qp_init_attr, sizeof qp_init_attr);
       qp_init_attr.cap.max_recv_sge = 32; /* Maximum SGE per receive posting */
       qp_init_attr.cap.max_recv_wr = 32; /* Maximum receive posting capacity */
       qp_init_attr.cap.max_send_sge = 32; /* Maximum SGE per send posting */
       qp_init_attr.cap.max_send_wr = 32; /* Maximum send posting capacity */
       qp_init_attr.qp_type = IBV_QPT_RC; /* QP type, RC = Reliable connection */
       /* We use same completion queue, but one can use different queues */
       qp_init_attr.recv_cq = client_cq; /* Where should I notify for receive completion operations */
       qp_init_attr.send_cq = client_cq; /* Where should I notify for send completion operations */
       /*Lets create a QP */
       client_qp = ibv_create_qp(
		       pd /* which protection domain*/,
		       &qp_init_attr /* Initial attributes */);
	if (!client_qp) {
		printf("Failed to create QP\n");
	    return -errno;
	}

	printf("QP created at %p \n",client_qp);

    struct ibv_qp_attr attr = {
			.qp_state        = IBV_QPS_INIT,
			.pkey_index      = 0,
			.port_num        = 1,
			.qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE
		};

		if (ibv_modify_qp(client_qp, &attr,
				  IBV_QP_STATE              |
				  IBV_QP_PKEY_INDEX         |
				  IBV_QP_PORT               |
				  IBV_QP_ACCESS_FLAGS)) {
            printf("failed to modify QP to INIT\n");
	}
	return 0;
}


/* Exchange buffer metadata with the server. The client sends its, and then receives
 * from the server. The client-side metadata on the server is _not_ used because
 * this program is client driven. But it shown here how to do it for the illustration
 * purposes
 */
int client_xchange_metadata_with_server(int sockfd)
{
    //register memory:
    //1) register memory to write
    //2) register memory to store the data from server
    //exchange memory info with server
    int page_size = sysconf(_SC_PAGESIZE);
    src = malloc(sizeof(char)*8000);
	//src = memalign(page_size,1024+40);
    if(!src)
    {
        printf("could't allocate work buf\n");
        return -1;
    }
	dst = malloc(sizeof(char)*8000);
    //dst = memalign(page_size,1024+40); 
    if(!dst)
    {
        printf("could'n allocate work buf\n");
        return -1;
    }

    memset(src,0x7b,8000);
    memset(dst,0x6b,8000);
    client_mr = ibv_reg_mr(pd, src, 8000, 
			(IBV_ACCESS_LOCAL_WRITE|
			 IBV_ACCESS_REMOTE_READ|
			 IBV_ACCESS_REMOTE_WRITE));
    if (!client_mr) {
	    printf("couldn't register MR\n");
        return -1;
	}

    server_mr = ibv_reg_mr(pd,dst,8000,
			(IBV_ACCESS_LOCAL_WRITE|
			 IBV_ACCESS_REMOTE_READ|
			 IBV_ACCESS_REMOTE_WRITE));

    
	ibv_query_port(context, 1, &portinfo);
	char			 gid[33];
	local_metadata.lid = portinfo.lid;
	local_metadata.qpn = client_qp->qp_num;
	local_metadata.psn = 0;
    local_metadata.addr = client_mr->addr;
    local_metadata.length = client_mr->length;
    local_metadata.lkey = client_mr->lkey;

    union ibv_gid localgid;
	ibv_query_gid(context, 1, 1,&localgid);

	inet_ntop(AF_INET6,&localgid, local_metadata.gid, sizeof gid);

	printf("  local address:  LID 0x%04x, QPN 0x%06x, PSN 0x%06x: GID %s\n",
	       local_metadata.lid, local_metadata.qpn, local_metadata.psn, local_metadata.gid);

    printf(" local memory: address 0x%06x, length 0x%04x, rkey 0x%04x\n",
			local_metadata.addr,local_metadata.length,local_metadata.lkey);
	int needRecv=sizeof(local_metadata);
    char buffer[sizeof(local_metadata)];
    memcpy(buffer,&local_metadata,needRecv);
    int bytes = 0;
    if((bytes = send(sockfd,buffer,needRecv,0)) == -1)
    {
        printf("send data failed\n");
        return -1;
    }


    int bytes_received = 0;
    bytes_received = recv(sockfd, buffer, sizeof(remote_metadata), 0);
    

    memcpy(&remote_metadata,buffer,sizeof(buffer));
	printf("  remote address: LID 0x%04x, QPN 0x%06x, PSN 0x%06x, GID %s\n",
	       remote_metadata.lid, remote_metadata.qpn, remote_metadata.psn, remote_metadata.gid);
	
	printf(" remote memory: address 0x%06x, length 0x%04x, rkey 0x%04x\n",
			remote_metadata.addr,remote_metadata.length,remote_metadata.lkey);
	
    close(sockfd);
    union ibv_gid remotegid;
    inet_pton(AF_INET6, remote_metadata.gid, &remotegid);
    struct ibv_qp_attr attr = {
		.qp_state		= IBV_QPS_RTR,
		.path_mtu		= IBV_MTU_1024,
		.dest_qp_num		= remote_metadata.qpn,
		.rq_psn			= 0,
		.max_dest_rd_atomic	= 1,
		.min_rnr_timer		= 0x12,
		.ah_attr		= {
			.is_global	= 1,
			.dlid		= remote_metadata.lid,
			.sl		= 0,
			.src_path_bits	= 0,
			.port_num	= 1,
			.grh.dgid   = remotegid,
			.grh.sgid_index = 1,
			.grh.hop_limit = 1
		}
	};

	if (ibv_modify_qp(client_qp, &attr,
			  IBV_QP_STATE              |
			  IBV_QP_AV                 |
			  IBV_QP_PATH_MTU           |
			  IBV_QP_DEST_QPN           |
			  IBV_QP_RQ_PSN             |
			  IBV_QP_MAX_DEST_RD_ATOMIC |
			  IBV_QP_MIN_RNR_TIMER)) {
		printf("Failed to modify QP to RTR\n");
		return 1;
	}

	attr.qp_state	    = IBV_QPS_RTS;
	attr.timeout	    = 0x12;
	attr.retry_cnt	    = 6;
	attr.rnr_retry	    = 0;
	attr.sq_psn	    = 0;
	attr.max_rd_atomic  = 1;

	if (ibv_modify_qp(client_qp, &attr,
			  IBV_QP_STATE              |
			  IBV_QP_TIMEOUT            |
			  IBV_QP_RETRY_CNT          |
			  IBV_QP_RNR_RETRY          |
			  IBV_QP_SQ_PSN             |
			  IBV_QP_MAX_QP_RD_ATOMIC)) {
		printf("Failed to modify QP to RTS\n");
		return -1;
	}

	printf("success to modify QP state\n");
	return 0;
}
/* Connects to the RDMA server */
int client_connect_to_server() 
{
    const char* server_ip = "192.168.44.129";
	int port = 9999;
	struct sockaddr_in server_addr;
    int sockfd = -1;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("could not create socket\n");
        return NULL;
    }

	server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(server_ip);
    server_addr.sin_port = htons(port);

	if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        printf("connection %s %dfailed\n",server_ip,port);
        return NULL;
    }

	printf("connect to server\n");

	client_xchange_metadata_with_server(sockfd);
	return 0;
}

int process_work_completion_events (struct ibv_comp_channel *comp_channel, 
		struct ibv_wc *wc, int max_wc)
{
	struct ibv_cq *cq_ptr = NULL;
	void *context = NULL;
	int ret = -1, i, total_wc = 0;
       /* We wait for the notification on the CQ channel */
	ret = ibv_get_cq_event(comp_channel, /* IO channel where we are expecting the notification */ 
		       &client_cq, /* which CQ has an activity. This should be the same as CQ we created before */ 
		       &context); /* Associated CQ user context, which we did set */
       if (ret) {
            printf("Failed to get next CQ event due to\n");
	        return -errno;
       }

       /* Request for more notifications. */
       ret = ibv_req_notify_cq(client_cq, 0);
       if (ret){
            printf("Failed to request further notifications\n");
	        return -errno;
       }
       /* We got notification. We reap the work completion (WC) element. It is 
	    * unlikely but a good practice it write the CQ polling code that 
        * can handle zero WCs. ibv_poll_cq can return zero. Same logic as 
        * MUTEX conditional variables in pthread programming.
	    */
       total_wc = 0;
       do {
	       ret = ibv_poll_cq(client_cq /* the CQ, we got notification for */, 
		       max_wc - total_wc /* number of remaining WC elements*/,
		       wc + total_wc/* where to store */);
	       if (ret < 0) {
                printf("Failed to poll cq for wc due to %d \n",ret);
		       /* ret is errno here */
		       return ret;
	       }
	       total_wc += ret;
       } while (total_wc < max_wc); 
       printf("%d WC are completed \n",total_wc);

       /* Now we check validity and status of I/O work completions */
       for( i = 0 ; i < total_wc ; i++) {
	       if (wc[i].status != IBV_WC_SUCCESS) {
		       printf("Work completion (WC) has error status: %s at index %d\n",
                ibv_wc_status_str(wc[i].status), i);
		       /* return negative value */
		       return -(wc[i].status);
	       }
       }
       /* Similar to connection management events, we need to acknowledge CQ events */
       ibv_ack_cq_events(client_cq, 
		       1 /* we received one event notification. This is not 
		       number of WC elements */);
       return total_wc; 
}


/* This function does :
 * 1) Prepare memory buffers for RDMA operations 
 * 1) RDMA write from src -> remote buffer 
 * 2) RDMA read from remote bufer -> dst
 */ 
static int client_remote_memory_ops() 
{
	struct ibv_wc wc;
	int ret = -1;

	client_send_sge.addr = (uint64_t) server_mr->addr;
	client_send_sge.length = (uint32_t) server_mr->length;
	client_send_sge.lkey = server_mr->lkey;
	bzero(&client_send_wr, sizeof(client_send_wr));
	client_send_wr.sg_list = &client_send_sge;
	client_send_wr.num_sge = 1;
	client_send_wr.opcode = IBV_WR_RDMA_READ;
	client_send_wr.send_flags = IBV_SEND_SIGNALED;
	client_send_wr.wr.rdma.rkey = remote_metadata.lkey;
	client_send_wr.wr.rdma.remote_addr = remote_metadata.addr;
	client_send_wr.priority = 0;
	client_send_wr.next = &client_send_wr1;
	client_send_sge1.addr = (uint64_t) server_mr->addr;
	client_send_sge1.length = (uint32_t) server_mr->length;
	client_send_sge1.lkey = server_mr->lkey;
	bzero(&client_send_wr1, sizeof(client_send_wr1));
	client_send_wr1.sg_list = &client_send_sge1;
	client_send_wr1.num_sge = 1;
	client_send_wr1.opcode = IBV_WR_RDMA_READ;
	client_send_wr1.send_flags = IBV_SEND_SIGNALED;
	client_send_wr1.wr.rdma.rkey = remote_metadata.lkey;
	client_send_wr1.wr.rdma.remote_addr = remote_metadata.addr;
	client_send_wr1.priority = 0;
	client_send_wr1.next = & client_send_wr2;
	
	client_send_sge2.addr = (uint64_t) server_mr->addr;
	client_send_sge2.length = (uint32_t) server_mr->length;
	client_send_sge2.lkey = server_mr->lkey;
	bzero(&client_send_wr2, sizeof(client_send_wr2));
	client_send_wr2.sg_list = &client_send_sge2;
	client_send_wr2.num_sge = 1;
	client_send_wr2.opcode = IBV_WR_RDMA_READ;
	client_send_wr2.send_flags = IBV_SEND_SIGNALED;
	client_send_wr2.wr.rdma.rkey = remote_metadata.lkey;
	client_send_wr2.wr.rdma.remote_addr = remote_metadata.addr;
	client_send_wr2.priority = 0;
	
	client_send_wr2.next = & client_send_wr3;
	client_send_sge3.addr = (uint64_t) server_mr->addr;
	client_send_sge3.length = (uint32_t) server_mr->length;
	client_send_sge3.lkey = server_mr->lkey;
	bzero(&client_send_wr3, sizeof(client_send_wr3));
	client_send_wr3.sg_list = &client_send_sge3;
	client_send_wr3.num_sge = 1;
	client_send_wr3.opcode = IBV_WR_RDMA_READ;
	client_send_wr3.send_flags = IBV_SEND_SIGNALED;
	client_send_wr3.wr.rdma.rkey = remote_metadata.lkey;
	client_send_wr3.wr.rdma.remote_addr = remote_metadata.addr;
	client_send_wr3.priority = 0;

	client_send_wr3.next = & client_send_wr4;
	client_send_sge4.addr = (uint64_t) server_mr->addr;
	client_send_sge4.length = (uint32_t) server_mr->length;
	client_send_sge4.lkey = server_mr->lkey;
	bzero(&client_send_wr4, sizeof(client_send_wr4));
	client_send_wr4.sg_list = &client_send_sge4;
	client_send_wr4.num_sge = 1;
	client_send_wr4.opcode = IBV_WR_RDMA_READ;
	client_send_wr4.send_flags = IBV_SEND_SIGNALED;
	client_send_wr4.wr.rdma.rkey = remote_metadata.lkey;
	client_send_wr4.wr.rdma.remote_addr = remote_metadata.addr;
	client_send_wr4.priority = 0;


	/* Now we post it */
	ret = ibv_post_send(client_qp, 
		       &client_send_wr,
	       &bad_client_send_wr);
	if (ret) {
		printf("Failed to read client dst buffer from the master");
		return -errno;
	}
	/* at this point we are expecting 1 work completion for the write */
	ret = process_work_completion_events(io_completion_channel, 
			&wc, 3);
	if(ret != 3) {
        printf("We failed to get 1 work completions\n");
		return ret;
	}
	
    printf("Client side READ is complete \n");

	/*
	client_send_sge.addr = (uint64_t) local_metadata.addr;
	client_send_sge.length = (uint32_t) local_metadata.length;
	client_send_sge.lkey = local_metadata.lkey;

	bzero(&client_send_wr, sizeof(client_send_wr));
	client_send_wr.sg_list = &client_send_sge;
	client_send_wr.num_sge = 1;
	client_send_wr.opcode = IBV_WR_RDMA_WRITE;
	client_send_wr.send_flags = IBV_SEND_SIGNALED;

	client_send_wr.wr.rdma.rkey = remote_metadata.lkey;
	client_send_wr.wr.rdma.remote_addr = remote_metadata.addr;

	ret = ibv_post_send(client_qp,
		       &client_send_wr,
	       &bad_client_send_wr);
	if (ret) {
		printf("Failed to write client src buffer\n");
		return -errno;
	}

	ret = process_work_completion_events(io_completion_channel, 
			&wc, 1);
	if(ret != 1) {
		printf("we failed to get 1 work completions\n");
		return ret;
	}
	*/
    printf("Client side WRITE is complete \n");
	/* Now we prepare a READ using same variables but for destination */
	return 0;
}

int main(int argc, char **argv) {
	src = dst = NULL;
    const char *ib_devname = "rxe_0";

    int ret = 0;
    dev_list = ibv_get_device_list(NULL);
	if (!dev_list) {
		printf("Failed to get IB devices list\n");
		return 1;
	}

	ib_dev = dev_list[0];
	if(!ib_dev)
	{
		printf("counld't find device rxe_0\n");
	}

	ret = client_prepare_connection();
	if (ret) { 
        printf("Failed to setup client connection");
		return ret;
	 }
	client_connect_to_server();

	ret = client_remote_memory_ops();
	if (ret) {
        printf("Failed to finish remote memory ops\n");
		return ret;
	}
	if (check_src_dst()) {
		printf("src and dst buffers do not match\n");
	} else {
		printf("...\nSUCCESS, source and destination buffers match \n");
	}
	
	sleep(10);
	return ret;
}
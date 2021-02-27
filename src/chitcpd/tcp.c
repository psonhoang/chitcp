/*
 *  chiTCP - A simple, testable TCP stack
 *
 *  Implementation of the TCP protocol.
 *
 *  chiTCP follows a state machine approach to implementing TCP.
 *  This means that there is a handler function for each of
 *  the TCP states (CLOSED, LISTEN, SYN_RCVD, etc.). If an
 *  event (e.g., a packet arrives) while the connection is
 *  in a specific state (e.g., ESTABLISHED), then the handler
 *  function for that state is called, along with information
 *  about the event that just happened.
 *
 *  Each handler function has the following prototype:
 *
 *  int f(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event);
 *
 *  si is a pointer to the chiTCP server info. The functions in
 *       this file will not have to access the data in the server info,
 *       but this pointer is needed to call other functions.
 *
 *  entry is a pointer to the socket entry for the connection that
 *          is being handled. The socket entry contains the actual TCP
 *          data (variables, buffers, etc.), which can be extracted
 *          like this:
 *
 *            tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
 *
 *          Other than that, no other fields in "entry" should be read
 *          or modified.
 *
 *  event is the event that has caused the TCP thread to wake up. The
 *          list of possible events corresponds roughly to the ones
 *          specified in http://tools.ietf.org/html/rfc793#section-3.9.
 *          They are:
 *
 *            APPLICATION_CONNECT: Application has called socket_connect()
 *            and a three-way handshake must be initiated.
 *
 *            APPLICATION_SEND: Application has called socket_send() and
 *            there is unsent data in the send buffer.
 *
 *            APPLICATION_RECEIVE: Application has called socket_recv() and
 *            any received-and-acked data in the recv buffer will be
 *            collected by the application (up to the maximum specified
 *            when calling socket_recv).
 *
 *            APPLICATION_CLOSE: Application has called socket_close() and
 *            a connection tear-down should be initiated.
 *
 *            PACKET_ARRIVAL: A packet has arrived through the network and
 *            needs to be processed (RFC 793 calls this "SEGMENT ARRIVES")
 *
 *            TIMEOUT: A timeout (e.g., a retransmission timeout) has
 *            happened.
 *
 */

/*
 *  Copyright (c) 2013-2014, The University of Chicago
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or withsend
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 *  - Neither the name of The University of Chicago nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software withsend specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY send OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "chitcp/log.h"
#include "chitcp/utils.h"
#include "chitcp/buffer.h"
#include "chitcp/chitcpd.h"
#include "serverinfo.h"
#include "connection.h"
#include "tcp.h"
#include <stdlib.h>
#include <string.h>

/* Struct containing parameters for single timers' callback function */
typedef struct callback_void_param
{
    serverinfo_t *si;
    chisocketentry_t *entry;
    tcp_timer_type_t timer_type;
} callback_void_param_t;

/* Callback function for single timers as defined in multitimer.h */
void callback_func(multi_timer_t* multi_timer, single_timer_t* single_timer, 
                                                            void *tcp_param)
{
    chilog(DEBUG, "[CALLBACK] IT IS CALLED");
    callback_void_param_t *void_params;
    void_params = (callback_void_param_t *) tcp_param; 
    if (void_params->timer_type == RETRANSMISSION)
    {
        chilog(DEBUG, "[CALLBACK] CALLBACK FOR RETRANSMISSION");
    }
    else
    {
        chilog(DEBUG, "[CALLBACK] CALLBACK FOR PERSIST");
    }
    chitcpd_timeout(void_params->si, void_params->entry, 
                    void_params->timer_type);
}

void tcp_data_init(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    tcp_data->pending_packets = NULL;
    pthread_mutex_init(&tcp_data->lock_pending_packets, NULL);
    pthread_cond_init(&tcp_data->cv_pending_packets, NULL);

    /* Initialization of additional tcp_data_t fields,
     * and creation of retransmission thread, goes here */
    tcp_data->tcp_timer = malloc(sizeof (multi_timer_t));
    int rc = mt_init(tcp_data->tcp_timer, 2);
    single_timer_t *timer;
    callback_void_param_t *void_param_1 = malloc(sizeof(callback_void_param_t));
    callback_void_param_t *void_param_2 = malloc(sizeof(callback_void_param_t));
    void_param_1->si = si;
    void_param_1->entry = entry;
    void_param_2->si = si;
    void_param_2->entry = entry;
    for (int i = 0; i < tcp_data->tcp_timer->num_timers; i++)
    {
        tcp_data->tcp_timer->timers[i]->callback = callback_func;
        if (i == 0)
        {
            void_param_1->timer_type = RETRANSMISSION;
            mt_set_timer_name(tcp_data->tcp_timer, RETRANSMISSION, 
                                "RETRANSMISSION");
            tcp_data->tcp_timer->timers[i]->callback_args = void_param_1;
        }
        else if (i == 1)
        {
            void_param_2->timer_type = PERSIST;
            mt_set_timer_name(tcp_data->tcp_timer, PERSIST, "PERSIST");
            tcp_data->tcp_timer->timers[i]->callback_args = void_param_2;
        }
    }
    tcp_data->queue = NULL;
    tcp_data->list = NULL;
    tcp_data->biggest_ack = 0;
    tcp_data->RTO = SECOND;
    tcp_data->rtms_timer_on = false;
    tcp_data->first_RTT = false;
    tcp_data->unack_bytes = 0;
    tcp_data->probe_packet = NULL;
    tcp_data->closing = false;
    tcp_data->state_after_close = FIN_WAIT_1;
}

void tcp_data_free(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    // free pending packets list
    chitcp_packet_list_destroy(&tcp_data->pending_packets);
    // destroy thread mutex and cond
    pthread_mutex_destroy(&tcp_data->lock_pending_packets);
    pthread_cond_destroy(&tcp_data->cv_pending_packets);

    return;
}

/* This function returns the max value between CLOCK_G and RTT_VAR */
uint64_t max_var(uint64_t clock_g, uint64_t rtt_var)
{
    if (clock_g >= rtt_var)
    {
        return clock_g;
    }
    else
    {
        return rtt_var;
    }
}

/* Helper function that calculates the RTO given the start time and a flag 
 * indicating whether the packet has been retransmitted.
 * @Params: serverinfo_t struct pointer, chisocketentry_t struct pointer,
 * start time as pointer to timespec struct, and restransmitted flag. 
 */
void calculate_RTO(serverinfo_t *si, chisocketentry_t *entry, 
                    struct timespec *start_time, bool_t retransmitted)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    struct timespec *result = malloc (sizeof (struct timespec));
    struct timespec *end_time = malloc (sizeof (struct timespec));
    clock_gettime(CLOCK_REALTIME, end_time);
    timespec_subtract(result, end_time, start_time);
    tcp_data->RTT = result->tv_sec * SECOND + result->tv_nsec;
    chilog(DEBUG, "RTT timespec is %lis %lins", result->tv_sec, result->tv_nsec);
    chilog(DEBUG, "[RTO CALCULATION] CALCULATED RTT TIME IS %i", tcp_data->RTT);
    uint64_t RTO;
    if (tcp_data->first_RTT)
    {
        tcp_data->SRTT = tcp_data->RTT;
        tcp_data->RTTVAR = tcp_data->RTT / 2;
        RTO = tcp_data->SRTT + max_var(CLOCK_G, 4 * tcp_data->RTTVAR);
        chilog(DEBUG, "[RTO CALCULATION] CALCULATED RTO TIME IS %i", RTO);
        if (RTO < MIN_RTO)
        {
            chilog(DEBUG, "[RTO CALCULATION] MIN RTO CASE");    
            tcp_data->RTO = MIN_RTO;
        }
        else
        {
            chilog(DEBUG, "[RTO CALCULATION] NORMAL RTO CASE");    
            tcp_data->RTO = RTO;
        }
        tcp_data->first_RTT = false;
        chilog(DEBUG, "[RTO CALCULATION] RTO TIME IS %i", tcp_data->RTO);
        return;
    }
    else 
    {
        tcp_data->RTTVAR = ((tcp_data->RTTVAR * 3) / 4) + (abs(tcp_data->SRTT - tcp_data->RTT) / 4);
        tcp_data->SRTT = ((7 * tcp_data->SRTT) / 8) + (tcp_data->RTT/8);
        RTO = tcp_data->SRTT + max_var(CLOCK_G, 4 * tcp_data->RTTVAR);
        chilog(DEBUG, "[RTO CALCULATION] CALCULATED RTO TIME IS %i", RTO);
        if (RTO < MIN_RTO)
        {
            chilog(DEBUG, "[RTO CALCULATION] MIN RTO CASE");    
            tcp_data->RTO = MIN_RTO;
        }
        else
        {
            chilog(DEBUG, "[RTO CALCULATION] NORMAL RTO CASE");  
            tcp_data->RTO = RTO;
        }
        chilog(DEBUG, "[RTO CALCULATION] RTO TIME IS %i", tcp_data->RTO);
        return;
    }
}

/* HELPER FUNCTION */

/* This function frees a packet we create
 * or remove from the pending queue
 * Input: the packet we need to free
 * Output: nothing, packet gets free
 */
void free_packet(tcp_packet_t *packet)
{
    /* free memories associated with the struct */
    chitcp_tcp_packet_free(packet);
    /* free the packet itself */
    free(packet);
    return;
}

/* Wrapper function to set a single timer in our multitimer
 * @Params: serverinfo_t struct pointer, chisocketentry_t entry struct pointer,
 * timeout in nanoseconds, timer type (PERSIST || RETRANSMISSION).
 */
void set_timer(serverinfo_t *si, chisocketentry_t *entry, 
                            uint64_t timeout, tcp_timer_type_t timer_type)
{
    chilog(DEBUG, "[SET_TIMER] SET TIMER FUNCTION");
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    retransmission_queue_t *queue = tcp_data->queue;
    single_timer_t *timer = NULL;
    mt_get_timer_by_id(tcp_data->tcp_timer, timer_type, &timer);
    // single_timer_t *timer = tcp_data->tcp_timer->timers[timer_type];
    if (timer_type == RETRANSMISSION)
    {
        chilog(DEBUG, "[SET_TIMER] RETRANSMISSION TIMER");
        if ((!tcp_data->rtms_timer_on) && (queue != NULL))
        {
            /* Check if send buffer is empty */
            chilog(DEBUG, "[SET_TIMER] RTO TIME IS %i", tcp_data->RTO);
            tcp_data->rtms_timer_on = true;
            mt_set_timer(tcp_data->tcp_timer, timer_type, timeout, 
                            timer->callback, timer->callback_args);
            return;
        }
    }
    else 
    {
        chilog(DEBUG, "[SET_TIMER] PERSIST TIMER");
        mt_set_timer(tcp_data->tcp_timer, timer_type, timeout, 
                    timer->callback, timer->callback_args); 
        return;
    }
}

/* DEBUG function to print out packets' sequence number in RTX queue */
void print_rtx_queue(retransmission_queue_t *head)
{
    retransmission_queue_t *elt;
    DL_FOREACH(head, elt)
    {
        chilog(MINIMAL, "RTX packet seq: %d", elt->expected_ack_seq);
    }
}

/* This function removes packets in the retransmission queue whose sequence
 * number is less than or equal to the given ACK sequence
 * @Params: serverinfo_t struct pointer, chisocketentry_t struct pointer,
 * ACK sequence from incoming packet.
 */
void remove_from_queue(serverinfo_t *si, chisocketentry_t *entry, tcp_seq ack_seq)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    retransmission_queue_t *elt;
    chilog(DEBUG, "[REMOVE QUEUE] PACKET BEING REMOVED");
    if (tcp_data->queue == NULL)
    {
        chilog(DEBUG, "[REMOVE QUEUE] QUEUE IS EMPTY SO NOTHING GETS REMOVED");
        mt_cancel_timer(tcp_data->tcp_timer, RETRANSMISSION);
        return;
    }
    chilog(DEBUG, "[REMOVE QUEUE] QUEUE IS NOT EMPTY");
    int i = 0;
    int RTT;
    int payload_len;
    if (ack_seq < 0)
    {
        /* ACK sequence for SYN segments is -1 */
        retransmission_queue_t *head = tcp_data->queue;
        if (head == NULL)
        {
            head = head->next;
        }
        calculate_RTO(si, entry, head->send_start, head->retransmitted);
        free_packet(head->packet);
        DL_DELETE(tcp_data->queue, head);
        free(head);
        return;
    }
    else 
    {
        DL_FOREACH(tcp_data->queue, elt)
        {
            if (elt->expected_ack_seq <= ack_seq) {
                chilog(DEBUG, "[RTO CALCULATION] START RTO CALCULATION");
                calculate_RTO(si, entry, elt->send_start, elt->retransmitted);
                int payload_len = TCP_PAYLOAD_LEN(elt->packet);
                tcp_data->unack_bytes -= payload_len;
                circular_buffer_read(&tcp_data->send, NULL, payload_len, FALSE);
                free_packet(elt->packet);
                DL_DELETE(tcp_data->queue, elt);
                free(elt);
            }
            else
            {
                break;
            }
        }
    }
    
    if (tcp_data->rtms_timer_on)
    {
        tcp_data->rtms_timer_on = false;
        mt_cancel_timer(tcp_data->tcp_timer, RETRANSMISSION);
    }
    // tcp_data->rtms_timer_on = false;
    // chilog(DEBUG, "CANCEL TIMER CALLED HERE");
    // mt_cancel_timer(tcp_data->tcp_timer, RETRANSMISSION);
    int queue_len;
    retransmission_queue_t *tmp;
    DL_COUNT(tcp_data->queue, tmp, queue_len);
    // chilog(MINIMAL, "[REMOVE FROM QUEUE] queue len: %d; ack_seq: %d", queue_len, ack_seq);
    // print_rtx_queue(tcp_data->queue);
    if (queue_len > 0)
    {
        set_timer(si, entry, tcp_data->RTO, RETRANSMISSION);
    }
}

/* This function adds a packet to the retransmission queue 
 * @Params: serverinfo_t struct pointer, chisocketentry_t struct pointer,
 * packet's sequence number, pointer to packet
 */
void add_to_queue(serverinfo_t *si, chisocketentry_t *entry, tcp_seq seq_num, tcp_packet_t *packet)
{
    chilog(DEBUG, "[DEBUG] IT COMES TO ADD TO QUEUE");
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    retransmission_queue_t *item = malloc(sizeof (retransmission_queue_t));
    item->packet = packet;
    item->send_start = malloc (sizeof (struct timespec));
    clock_gettime(CLOCK_REALTIME, item->send_start);
    item->retransmitted = false;
    item->expected_ack_seq = TCP_PAYLOAD_LEN(packet) + seq_num;
    chilog(DEBUG, "[DEBUG] PAYLOAD LEN IS = %i", TCP_PAYLOAD_LEN(packet));
    chilog(DEBUG, "[DEBUG] SEQUENCE NUMBER IS = %i", seq_num);
    chilog(DEBUG, "[DEBUG] EXPECTED ACK SEQ = %i", item->expected_ack_seq);
    DL_APPEND(tcp_data->queue, item);
    /* DEBUG */
    retransmission_queue_t *elt;
    int rtx_len;
    DL_COUNT(tcp_data->queue, elt, rtx_len);
    chilog(DEBUG, "[DEBUG] QUEUE LENGTH IS %i", rtx_len);
    /* DEBUG ENDS */
    set_timer(si, entry, tcp_data->RTO, RETRANSMISSION);
    chilog(DEBUG, "[DEBUG] ADD TO QUEUE ENDS");
}

/* Helper function to create tcp packet to be sent 
 * @Params: severinfo_t struct pointer, chisocketentry_t struct pointer, 
 * FIN bit, SYN bit, ACK bit, payload bytes array, payload's length.
 * @Return: pointer to tcp_packet_t struct.
 */
tcp_packet_t *create_packet(serverinfo_t *si, chisocketentry_t *entry, 
                                    int fin, int syn, int ack,
                                    const uint8_t* payload, 
                                    uint16_t payload_len)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    tcp_packet_t *send_packet = malloc(sizeof(tcp_packet_t));
    if ((payload_len == 0) && (payload == NULL))
    {
        chitcpd_tcp_packet_create(entry, send_packet, NULL, 0);
    }
    else 
    {
        chitcpd_tcp_packet_create(entry, send_packet, 
                                        payload, payload_len);
    }
        tcphdr_t *send_header = TCP_PACKET_HEADER(send_packet);
        send_header->fin = fin;
        send_header->ack = ack;
        send_header->syn = syn;
        send_header->seq = htonl(tcp_data->SND_NXT);
        send_header->ack_seq = htonl(tcp_data->RCV_NXT);
        send_header->win = htons(tcp_data->RCV_WND);
    return send_packet;
}

/* This function looks at the current state
 * of the Transmission Control Block and
 * send over as much data remaining in
 * the host's send buffer as allowed
 * by the other host's receive window
 * Input: serverinfo_t *si, chisocketentry_t *entry
 * Output: nothing, we just packet messages
 * and send them
 */
void chitcpd_process_send_buffer(serverinfo_t *si, chisocketentry_t *entry)
{
    /* This function aims to empty send buffer */
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    /* bytes_in_send is the bytes in the send buffer that needs to be sent */
    int bytes_in_send = circular_buffer_count(&tcp_data->send) - tcp_data->unack_bytes;
    if (circular_buffer_count(&tcp_data->send) == 0 && tcp_data->closing)
    {
        chilog(DEBUG, "[SEND] CLOSING STATE");
        /* Create packet with fin segment to send over to other host */
        tcp_packet_t *send_packet = create_packet(si, entry, FIN_ON, SYN_OFF, 
                                                    ACK_ON, NULL, 0);
        chitcpd_send_tcp_packet(si, entry, send_packet);
        add_to_queue(si, entry, tcp_data->SND_NXT, send_packet);
        /* Update SND_NXT after sending fin segment */
        tcp_data->SND_NXT++;
        /* Transition to state after CLOSE call (FIN_WAIT_1 || LAST_ACK) */
        tcp_data->closing = false;
        chitcpd_update_tcp_state(si, entry, tcp_data->state_after_close);
        return;
    }
    else if (bytes_in_send == 0) 
    {
        /* If no bytes in send buffer, return */
        chilog(DEBUG, "[SEND] NOTHING TO SEND");
        return;
    }
    else
    {
    chilog(DEBUG, "[SEND] THERE ARE THINGS TO SEND");
    int possible_send_bytes = tcp_data->SND_WND - (tcp_data->SND_NXT - tcp_data->SND_UNA);
    int total_send_bytes = 0;
    int bytes_read;
    if (possible_send_bytes >= bytes_in_send)
    {
        /* If other host's receive window can take in 
         * all bytes in the send buffer
         * set total_send_bytes equal to number of bytes
         * in send buffer
         */
        total_send_bytes = bytes_in_send;
    }
    else
    {
        /* If other host's receive window can't take in 
         * all bytes in the send buffer
         * set total_send_bytes equal to other host's receive window
         */
        total_send_bytes = possible_send_bytes;
    }
    int payload_len;
    int i = 0;
    while (total_send_bytes > 0)
    {
        chilog(DEBUG, "[SEND] ENTER LOOP");
        chilog(DEBUG, "[SEND] PACKET %i", i);
        chilog(DEBUG, "[SEND] TOTAL BYTE NEEDS TO BE SENT IS %d", bytes_in_send);
        chilog(DEBUG, "[SEND] TOTAL SEND WINDOW IS %d", possible_send_bytes);
        chilog(DEBUG, "[SEND] TOTAL BYTE GOING TO BE SENT IS %d", 
                                            total_send_bytes);
        chilog(DEBUG, "[SEND] TOTAL UNACK_BYTES IS %d", 
                                            tcp_data->unack_bytes);
        /* Initialize send packet */
        tcp_packet_t *send_packet = malloc(sizeof(tcp_packet_t));
        if (total_send_bytes >= TCP_MSS)
        {
            /* if total_send_bytes > TCP_MSS, then
             * we are going to segmentize the
             * total_send_bytes
             */
            payload_len = TCP_MSS;
        }
        else
        {
            /* if total_send_bytes < TCP_MSS, then
             * payload len is equal to
             * total bytes we want to send
             */
            payload_len = total_send_bytes;
        }
        chilog(DEBUG, "[SEND] TOTAL PAYLOAD LEN IS %d", payload_len);
        uint8_t payload[payload_len];
        bytes_read = circular_buffer_peek_at(&tcp_data->send, payload, 
                                            tcp_data->SND_NXT, payload_len);
        chilog(DEBUG, "[SEND] TOTAL BYTES PEEKED FROM SENT BUFFER IS %d", 
                                                            bytes_read);
        chilog(DEBUG, "DATA REMAINING IN BUFFER IS %d", 
                                circular_buffer_count(&tcp_data->send));
        if (bytes_read > 0) {
            // update num of bytes left we need to send
            total_send_bytes -= bytes_read;
            tcp_data->unack_bytes += bytes_read;
            /* Create send packet */
            tcp_packet_t *send_packet = create_packet(si, entry, FIN_OFF, 
                                        SYN_OFF, ACK_ON, payload, payload_len);
            chitcpd_send_tcp_packet(si, entry, send_packet);
            add_to_queue(si, entry, tcp_data->SND_NXT, send_packet);
            tcp_data->SND_NXT = tcp_data->SND_NXT + bytes_read;
            i++;
        }
    }
    }
}

/* Handler function to handle retransmission timeout (TIMEOUT_RTX) event */
int chitcpd_tcp_handle_TIMEOUT_RTX(serverinfo_t *si, chisocketentry_t *entry)
{
    /* Check retransmission queue to check what packets need to be re-sent */
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    tcp_data->RTO = tcp_data->RTO*2;
    retransmission_queue_t *elt;
    DL_FOREACH(tcp_data->queue, elt)
    {
        clock_gettime(CLOCK_REALTIME, elt->send_start);
        elt->retransmitted = true;
        chitcpd_send_tcp_packet(si, entry, elt->packet);
    }
    tcp_data->rtms_timer_on = false;
    /* Reset retransmission timer */
    set_timer(si, entry, tcp_data->RTO, RETRANSMISSION);
    return 0;
}

/* Function to send probe segment */
void send_probe_segment(serverinfo_t *si, chisocketentry_t *entry)
{
    /* Send 1-byte probe segment with SND_NXT  */
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    tcp_packet_t *send_packet = malloc(sizeof(tcp_packet_t));
    if (circular_buffer_count(&tcp_data->send) > 0)
    {
        /* If there is data to send in the send buffer */
        if (tcp_data->probe_packet == NULL)
        {
            /* Sebd 1 byte of data from send buffer */
            uint8_t payload[1];
            circular_buffer_peek_at(&tcp_data->send, payload, 
                                    tcp_data->SND_NXT, 1);
            tcp_packet_t *send_packet = create_packet(si, entry, FIN_OFF, 
                                                SYN_OFF, ACK_ON, payload, 1);
            tcp_data->SND_NXT++;
            /* Send probe packet */
            chitcpd_send_tcp_packet(si, entry, send_packet);
            tcp_data->probe_packet = send_packet;
        }
        else
        {
            /* 1-byte probe segment has already been sent */
            chitcpd_send_tcp_packet(si, entry, tcp_data->probe_packet);
        }
    }
    else
    {
        free(send_packet);
    }
    return;
}

/* Handler function to handle persist timeout (TIMEOUT_PST) event */
int chitcpd_tcp_handle_TIMEOUT_PST(serverinfo_t *si, chisocketentry_t *entry)
{
    /* Sends probe segment */
    send_probe_segment(si , entry);
    /* Reset PST timer */
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    set_timer(si, entry, tcp_data->RTO, PERSIST);
    return 0;
}

/* Comparator function to check which segment in out of order list came first:
 * @Params: pointers to out of order list items: a and b
 *  Returns positive value if a's sequence number > b's sequence number
 *  Returns 0 if a's sequence number == b's sequence number
 *  Returns negative value if a's sequence number < b's sequence number
 */
int segmentcmp(out_of_order_list_t *a, out_of_order_list_t *b)
{
    return a->seq - b->seq;
}

/* Function to deal with PACKET_ARRIVAL event for all states 
 * Input: serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event
 * Output: return 0 when we are done with sending packets and updating
 * states
 */
int chitcpd_tcp_handle_PACKET_ARRIVAL(serverinfo_t *si, 
                            chisocketentry_t *entry, tcp_event_type_t event)
{
    tcp_state_t tcp_state = entry->tcp_state;
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    retransmission_queue_t *first_queue_item = tcp_data->queue;
    tcp_packet_t *packet = NULL;
    /* Extract and remove packet at the top of the queue */
    if (tcp_data->pending_packets)
    {
        /* tcp_data->pending_packets points to the head node of the list */
        pthread_mutex_lock(&tcp_data->lock_pending_packets);
        packet = tcp_data->pending_packets->packet;
        pthread_mutex_unlock(&tcp_data->lock_pending_packets);
        /* This removes the list node at the head of the list */
        chitcp_packet_list_pop_head(&tcp_data->pending_packets);
    }
    tcphdr_t *header = TCP_PACKET_HEADER(packet);
    tcp_seq recv_ack_seq = ntohl(header->ack_seq);
    tcp_seq recv_seq = ntohl(header->seq);
    tcp_seq recv_win = ntohs(header->win);
    /* Initialize packet to send over to the other host */
    tcp_packet_t *send_packet = malloc(sizeof(tcp_packet_t));
    // chitcpd_tcp_packet_create(entry, send_packet, NULL, 0);
    // tcphdr_t *send_header = TCP_PACKET_HEADER(send_packet);
    if (tcp_state == CLOSED)
    {
        // do nothing
        return 0;
    }
    else if (tcp_state == LISTEN)
    {
        if (header->ack == 1)
        {
            // not acceptable
            return 0;
        }
        if (header->syn == 1)
        {
            /* Initialize ISS and set TCB variables accordingly */
            uint32_t ISS = (rand() % 256) * 1000000;
            tcp_data->ISS = ISS;
            tcp_data->SND_UNA = ISS;
            tcp_data->SND_NXT = ISS + 1;
            tcp_data->RCV_NXT = recv_seq + 1;
            tcp_data->RCV_WND = circular_buffer_capacity(&tcp_data->recv);
            // tcp_data->IRS = header->seq;
            tcp_data->IRS = recv_seq;
            circular_buffer_set_seq_initial(&tcp_data->recv, 
                                                        tcp_data->IRS + 1);
            circular_buffer_set_seq_initial(&tcp_data->send, 
                                                        tcp_data->ISS + 1);
            /* Fill in header for send packet with syn segment */
            chitcpd_tcp_packet_create(entry, send_packet, NULL, 0);
            tcphdr_t *send_header = TCP_PACKET_HEADER(send_packet);
            send_header->syn = 1;
            send_header->ack = 1;
            send_header->fin = 0;
            send_header->seq = htonl(ISS);
            send_header->ack_seq = htonl(recv_seq + 1);
            send_header->win = htons(tcp_data->RCV_WND);
            chitcpd_send_tcp_packet(si, entry, send_packet);
            add_to_queue(si, entry, ISS, send_packet);
            /* Transition to SYN_RCVD */
            chitcpd_update_tcp_state(si, entry, SYN_RCVD);
            return 0;
        }
    }
    else if (tcp_state == SYN_SENT)
    {
        if (header->ack == 1)
        {
            if (!((tcp_data->SND_UNA <= recv_ack_seq) &&
                (recv_ack_seq <= tcp_data->SND_NXT)))
            {
                // not acceptable
                return 0;
            }
        }
        if (header->syn == 1)
        {
            // remove acknowledged segments from retransmission queue
            tcp_data->first_RTT = true;
            remove_from_queue(si, entry, -1);
            // reset tcp variables
            tcp_data->SND_UNA = recv_ack_seq;
            tcp_data->SND_NXT = recv_ack_seq;
            tcp_data->RCV_NXT = recv_seq + 1;
            tcp_data->IRS = recv_seq;
            tcp_data->SND_WND = recv_win;
            circular_buffer_set_seq_initial(&tcp_data->recv, 
                                                tcp_data->IRS + 1);
            if (tcp_data->SND_UNA > tcp_data->ISS)
            {
                // If our SYN has been acknowledged
                send_packet = create_packet(si, entry, FIN_OFF, SYN_OFF, 
                                            ACK_ON, NULL, 0);
                chitcpd_send_tcp_packet(si, entry, send_packet);        
                // Transition to ESTABLISHED
                chitcpd_update_tcp_state(si, entry, ESTABLISHED);
                chitcpd_process_send_buffer(si, entry);
            }
            else
            {
                // If we haven't sent over SYN segment
                chitcpd_tcp_packet_create(entry, send_packet, NULL, 0);
                tcphdr_t *send_header = TCP_PACKET_HEADER(send_packet);
                send_header->ack = 1;
                send_header->syn = 1;
                send_header->fin = 0;
                send_header->seq = htonl(tcp_data->ISS);
                send_header->ack_seq = htonl(tcp_data->RCV_NXT);
                send_header->win = htons(tcp_data->RCV_WND);
                chitcpd_send_tcp_packet(si, entry, send_packet);
                add_to_queue(si, entry, send_header->seq, send_packet);
                // Transition to SYN_RCVD
                chitcpd_update_tcp_state(si, entry, SYN_RCVD);
            }
            return 0;
        }
        else
        {
            // If not a syn segment, ignore
            return 0;
        }
    }
    else
    {
        // SYN-RECEIVED STATE
        // ESTABLISHED STATE
        // FIN-WAIT-1 STATE
        // FIN-WAIT-2 STATE
        // CLOSE-WAIT STATE
        // CLOSING STATE
        // LAST-ACK STATE
        // TIME-WAIT STATE

        /* FIRST: check acceptability */
        uint16_t SEG_LEN = SEG_LEN(packet);
        uint16_t RCV_WND = tcp_data->RCV_WND;

        if (recv_seq > tcp_data->RCV_NXT)
        {
            /* Out of order segment */
            out_of_order_list_t *item = malloc(sizeof(out_of_order_list_t));
            item->seq = recv_seq;
            item->packet = packet;
            DL_APPEND(tcp_data->list, item);
            return 0;
        }
        
        if (recv_seq < tcp_data->RCV_NXT)
        {
            /* Redundant segment */
            return 0;
        }

        if ((RCV_WND == 0) && (SEG_LEN == 0))
        {
            if (recv_seq != tcp_data->RCV_NXT)
            {
                chilog(DEBUG,"[LISTEN] IT DOESN'T PASS FIRST ACCEPTABILITY TEST IN THE PACKET_ARRIVAL HANDLER FUNCTION");
                send_packet = create_packet(si, entry, FIN_OFF, SYN_OFF, 
                                            ACK_ON, NULL, 0);
                chitcpd_send_tcp_packet(si, entry, send_packet);
                return 0;
            }
        }
        else if ((RCV_WND > 0) && (SEG_LEN == 0))
        {
            if (!((tcp_data->RCV_NXT <= recv_seq) &&
                (recv_seq < (tcp_data->RCV_NXT + tcp_data->RCV_WND))))
            {
                send_packet = create_packet(si, entry, FIN_OFF, SYN_OFF, 
                                            ACK_ON, NULL, 0);
                chitcpd_send_tcp_packet(si, entry, send_packet);
                return 0;
            }
        }
        else if ((RCV_WND == 0) && (SEG_LEN > 0))
        {
            chilog(DEBUG,"[LISTEN] IT COMES TO THIRD ACCEPTABILITY TEST IN THE PACKET_ARRIVAL HANDLER FUNCTION");
            send_packet = create_packet(si, entry, FIN_OFF, SYN_OFF, ACK_ON,
                                         NULL, 0);
            chitcpd_send_tcp_packet(si, entry, send_packet);
            return 0;
        }
        else if ((RCV_WND > 0) && (SEG_LEN > 0))
        {
            chilog(DEBUG,"[LISTEN] IT COMES TO FOURTH ACCEPTABILITY TEST IN THE PACKET_ARRIVAL HANDLER FUNCTION");
            if (!(((tcp_data->RCV_NXT <= recv_seq) &&
                (recv_seq < (tcp_data->RCV_NXT + tcp_data->RCV_WND))) ||
                ((tcp_data->RCV_NXT <= (recv_seq + SEG_LEN - 1)) &&
                ((recv_seq + SEG_LEN - 1) < 
                                (tcp_data->RCV_NXT + tcp_data->RCV_WND)))))
            {
                chilog(DEBUG,"[LISTEN] IT DOESN'T PASS FOURTH ACCEPTABILITY TEST IN THE PACKET_ARRIVAL HANDLER FUNCTION");
                send_packet = create_packet(si, entry, FIN_OFF, SYN_OFF, 
                                            ACK_ON, NULL, 0);
                chitcpd_send_tcp_packet(si, entry, send_packet);
                return 0;
            }
        }
        /* FOURTH : check the SYN bit */
        if (header->syn == 1)
        {
            chilog(DEBUG,"[LISTEN] IT COMES TO HEADER SYN == 1 TEST IN THE PACKET_ARRIVAL HANDLER FUNCTION");
            // error
            return 0;
        }
        /* FIFTH: check the ACK bit */
        if (header->ack == 0)
        {
            // error
            chilog(DEBUG,"WHEN ACK == 0 IN THE PACKET_ARRIVAL HANDLER FUNCTION");
            return 0;
        }
        else
        {
            chilog(DEBUG,"[LISTEN] IT COMES TO ACK == 1 IN THE PACKET_ARRIVAL HANDLER FUNCTION");
            if (tcp_state == SYN_RCVD)
            {
                chilog(DEBUG,"[LISTEN] IT COMES INSIDE SYN_RCVD EVENT THE PACKET_ARRIVAL HANDLER FUNCTION");
                if ((tcp_data->SND_UNA <= recv_ack_seq) &&
                    (recv_ack_seq <= tcp_data->SND_NXT))
                {
                    // acceptable segment
                    tcp_data->first_RTT = true;
                    remove_from_queue(si, entry, -1);
                    tcp_data->SND_UNA = recv_ack_seq;
                    tcp_data->SND_NXT = recv_ack_seq;
                    tcp_data->SND_WND = recv_win;
                    chitcpd_update_tcp_state(si, entry, ESTABLISHED);
                    return 0;
                }
            }
            else
            {
                chilog(DEBUG,"[LISTEN] IT COMES OTHER EVENTS IN THE PACKET_ARRIVAL HANDLER FUNCTION");
                /* ACK check */
                if ((tcp_data->SND_UNA <= recv_ack_seq) &&
                    (recv_ack_seq <= tcp_data->SND_NXT))
                {
                    remove_from_queue(si, entry, recv_ack_seq);
                    single_timer_t *pst, *rtx;
                    mt_get_timer_by_id(tcp_data->tcp_timer, PERSIST, &pst);
                    mt_get_timer_by_id(tcp_data->tcp_timer, 
                                        RETRANSMISSION, &rtx);
                    if (recv_win == 0)
                    {
                        /* Advertised window == 0 */
                        if (pst->active)
                        {
                            mt_cancel_timer(tcp_data->tcp_timer, PERSIST);
                        }
                        set_timer(si, entry, tcp_data->RTO, PERSIST);
                    }
                    else if (recv_win > 0 && tcp_data->SND_WND == 0)
                    {
                        /* Advertised window is updated to > 0 */
                        mt_cancel_timer(tcp_data->tcp_timer, PERSIST);
                        if (tcp_data->probe_packet != NULL)
                        {
                            free(tcp_data->probe_packet);
                            tcp_data->probe_packet = NULL;
                            circular_buffer_read(&tcp_data->send, NULL, 1, 
                                                FALSE);
                        }
                    }
                    tcp_data->SND_UNA = recv_ack_seq;
                    tcp_data->SND_WND = recv_win;
                    chitcpd_process_send_buffer(si, entry);
                }
                else if (recv_ack_seq > tcp_data->SND_NXT)
                {
                    // ACK acks something not yet sent, send Ack
                    chilog(DEBUG, "[LISTEN] header->ack_seq: %d", 
                                                        recv_ack_seq);
                    chilog(DEBUG, "[LISTEN] tcp_data->SND_NXT: %d", 
                                                        tcp_data->SND_NXT);
                    chilog(DEBUG, "[LISTEN] header->ack_seq > tcp_data->SND_NXT");
                    send_packet = create_packet(si, entry, FIN_OFF, SYN_OFF, 
                                                ACK_ON, NULL, 0);
                    chitcpd_send_tcp_packet(si, entry, send_packet);
                }
                else 
                {
                    // If the ACK is a duplicate - retransmission error
                    return 0;
                }
                if (tcp_state == FIN_WAIT_1)
                {
                    if (header->fin != 1)
                    {
                        // If not the second case where CLOSING is involved
                        chitcpd_update_tcp_state(si, entry, FIN_WAIT_2);
                        return 0;
                    }
                }
                else if (tcp_state == CLOSING)
                {
                    chilog(DEBUG, "[CLOSING] Transitioning to CLOSED state");
                    chitcpd_update_tcp_state(si, entry, TIME_WAIT);
                    chitcpd_update_tcp_state(si, entry, CLOSED);
                    return 0;
                }
                else if (tcp_state == LAST_ACK)
                {
                    chilog(DEBUG, "[LAST_ACK] Transitioning to CLOSED state");
                    chitcpd_update_tcp_state(si, entry, CLOSED);
                    return 0;
                }
            }
            /* SEVENTH: process segment */
            if ((tcp_state == ESTABLISHED) || 
                (tcp_state == FIN_WAIT_1) || 
                (tcp_state == FIN_WAIT_2))
            {
                /* Copy to recv buffer and updates RCV_NXT */
                if ((header->fin != 1) && (tcp_state == ESTABLISHED)
                                            && (TCP_PAYLOAD_LEN(packet) > 0))
                {
                    /* Writes incoming data with seq == RCV.NXT */
                    int bytes_written = circular_buffer_write(
                        &tcp_data->recv,
                        TCP_PAYLOAD_START(packet),
                        TCP_PAYLOAD_LEN(packet),
                        FALSE);
                    chilog(DEBUG, "[RECEIVE] payload length: %d", 
                                                TCP_PAYLOAD_LEN(packet));
                    chilog(DEBUG, "[RECEIVE] bytes written is %d", 
                                                bytes_written);
                    tcp_data->RCV_NXT += bytes_written;
                    tcp_data->RCV_WND = 
                        circular_buffer_available(&tcp_data->recv);
                        
                    if(recv_seq == tcp_data->biggest_ack)
                    {
                        /* Time to send ACK segment */
                        tcp_data->biggest_ack = 0;
                    }

                    /* Process out of order delivery list */
                    out_of_order_list_t *elt;
                    int ooo_len;
                    DL_COUNT(tcp_data->list, elt, ooo_len);
                    if (ooo_len > 0)
                    {
                        /* Reassemblnig data from out of order list */
                        DL_SORT(tcp_data->list, segmentcmp);
                        /* Tracker of next expected contingous sequence */
                        int next_seq = tcp_data->RCV_NXT;
                        DL_FOREACH(tcp_data->list, elt);
                        {
                            /* Process contingous data in out-of-order list */
                            if (elt != NULL && elt->seq == next_seq)
                            {
                                /* Add contingous packet to pending packets */
                                chitcp_packet_list_append(
                                    &tcp_data->pending_packets, 
                                    elt->packet);
                                
                                /* Wait until a packet with this seq number
                                before sending an ACK segment to sender */
                                tcp_data->biggest_ack = elt->seq;
                                /* Update value of next expected contingous 
                                sequence */
                                next_seq += TCP_PAYLOAD_LEN(elt->packet);
                                DL_DELETE(tcp_data->list, elt);
                                free(elt);
                            }
                        }
                    }

                    if (tcp_data->biggest_ack == 0)
                    {
                        /* Send ACK segment */
                        send_packet = create_packet(si, entry, FIN_OFF, SYN_OFF,
                                                    ACK_ON, NULL, 0);
                        chitcpd_send_tcp_packet(si, entry, send_packet);
                    }
                }
            }
            else 
            {
                return 0;
            }
            /* EIGHT: Check FIN bit */
            if ((tcp_state == CLOSED) || (tcp_state == LISTEN) ||
                (tcp_state == SYN_SENT))
            {
                return 0;
            }
            else
            {
                if (header->fin == 1)
                {
                    /* Send ACK */
                    send_packet = create_packet(si, entry, FIN_OFF, SYN_OFF, ACK_ON, NULL, 0);
                    tcp_data->RCV_NXT = recv_seq + 1;
                    chitcpd_send_tcp_packet(si, entry, send_packet);
                    /* Transitions to next states in connection termination */
                    if ((tcp_state == SYN_RCVD) || (tcp_state == ESTABLISHED))
                    {
                        if (tcp_state == ESTABLISHED) {
                            chilog(DEBUG, "[ESTABLISHED] moving into CLOSE_WAIT state");
                        }
                        chitcpd_update_tcp_state(si, entry, CLOSE_WAIT);
                        return 0;
                    }
                    else if (tcp_state == FIN_WAIT_1)
                    {
                        /* Transitions to FIN_WAIT_2 */
                        chilog(DEBUG, "[FIN_WAIT_1] Transititiong to CLOSING");
                        chitcpd_update_tcp_state(si, entry, CLOSING);
                        return 0;
                    }
                    else if (tcp_state == FIN_WAIT_2)
                    {
                        /* Transitions to TIME_WAIT */
                        chilog(DEBUG, "[FIN_WAIT_2] Transitioning to TIME_WAIT");
                        chitcpd_update_tcp_state(si, entry, TIME_WAIT);
                        chitcpd_update_tcp_state(si, entry, CLOSED);
                        return 0;
                    }
                }
            }
        }
    }
}

/* END OF HELPER FUNCTION */

int chitcpd_tcp_state_handle_CLOSED(serverinfo_t *si, 
                            chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == APPLICATION_CONNECT)
    {
        /* Your code goes here */
        chilog(DEBUG, "[CLOSED] APPLICATION_CONNECT");
        tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
        /* Setting ISS and update TCB variables accordingly */
        uint32_t ISS = (rand() % 256) * 1000000;
        tcp_data->ISS = ISS;
        tcp_data->SND_UNA = ISS;
        tcp_data->SND_NXT = ISS + 1;
        tcp_data->RCV_WND = circular_buffer_capacity(&tcp_data->recv);
        circular_buffer_set_seq_initial(&tcp_data->send, tcp_data->ISS + 1);
        /* Create packet with syn segment to send
         * to the other host
         */
        tcp_packet_t *packet = malloc(sizeof(tcp_packet_t));
        chitcpd_tcp_packet_create(entry, packet, NULL, 0);
        tcphdr_t *header = TCP_PACKET_HEADER(packet);
        header->syn = 1;
        header->ack = 0;
        header->fin = 0;
        header->seq = htonl(ISS);
        header->ack_seq = htonl(0);
        header->win = htons(tcp_data->RCV_WND);
        //send process
        chitcpd_send_tcp_packet(si, entry, packet);
        add_to_queue(si, entry, header->seq, packet);
        /* Transition to SYN_SENT */
        chitcpd_update_tcp_state(si, entry, SYN_SENT);
    }
    else if (event == CLEANUP)
    {
        /* Any additional cleanup goes here */
        tcp_data_free(si, entry);
    }
    else
        chilog(WARNING, "In CLOSED state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_LISTEN(serverinfo_t *si, 
                            chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
        chilog(DEBUG, "[LISTEN] PACKET_ARRIVAL");
        chitcpd_tcp_handle_PACKET_ARRIVAL(si, entry, event);
    }
    else
        chilog(WARNING, "In LISTEN state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_SYN_RCVD(serverinfo_t *si, 
                            chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
        chilog(DEBUG, "[SYNC_RCVD] PACKET_ARRIVAL");
        chitcpd_tcp_handle_PACKET_ARRIVAL(si, entry, event);
    }
    else if (event == TIMEOUT_RTX)
    {
        /* Your code goes here */
        chitcpd_tcp_handle_TIMEOUT_RTX(si, entry);
    }
    else
        chilog(WARNING, "In SYN_RCVD state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_SYN_SENT(serverinfo_t *si, 
                            chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
        chitcpd_tcp_handle_PACKET_ARRIVAL(si, entry, event);
    }
    else if (event == TIMEOUT_RTX)
    {
        /* Your code goes here */
        chitcpd_tcp_handle_TIMEOUT_RTX(si, entry);
    }
    else
        chilog(WARNING, "In SYN_SENT state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_ESTABLISHED(serverinfo_t *si, 
                            chisocketentry_t *entry, tcp_event_type_t event)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    if (event == APPLICATION_SEND)
    {
        /* Your code goes here */
        /* send data from send buffer to other host */
        chitcpd_process_send_buffer(si, entry);
    }
    else if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
        chitcpd_tcp_handle_PACKET_ARRIVAL(si, entry, event);
    }
    else if (event == APPLICATION_RECEIVE)
    {
        /* Your code goes here */
        /* Update RCV_WND */
        tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);
    }
    else if (event == APPLICATION_CLOSE)
    {
        /* Your code goes here */
        chilog(DEBUG, "[ESTABLISHED] APPLICATION_CLOSE");
        /* Mark the socket is closing */
        tcp_data->closing = true;
        tcp_data->state_after_close = FIN_WAIT_1;
        /* Before closing the connection, send over
         * all data remaining in send buffer
         */
        chitcpd_process_send_buffer(si, entry);
    }
    else if (event == TIMEOUT_RTX)
    {
        /* Your code goes here */
        chilog(DEBUG, "[ESTABLISHED] STARTING TO CALL TIMEOUT EVENT");
        chitcpd_tcp_handle_TIMEOUT_RTX(si, entry);
    }
    else if (event == TIMEOUT_PST)
    {
        /* Your code goes here */
        chitcpd_tcp_handle_TIMEOUT_PST(si, entry);
    }
    else
        chilog(WARNING, "In ESTABLISHED state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_FIN_WAIT_1(serverinfo_t *si, 
                            chisocketentry_t *entry, tcp_event_type_t event)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    if (event == PACKET_ARRIVAL)
    {
        chilog(DEBUG, "[FIN_WAIT_1] PACKET_ARRIVAL");
        chitcpd_tcp_handle_PACKET_ARRIVAL(si, entry, event);
    }
    else if (event == APPLICATION_RECEIVE)
    {
        /* Your code goes here */
        chilog(DEBUG, "[FIN_WAIT_1] APPLICATION_RECEIVE");
        /* Update RCV_WND */
        tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);
    }
    else if (event == TIMEOUT_RTX)
    {
        /* Your code goes here */
        chitcpd_tcp_handle_TIMEOUT_RTX(si, entry);
    }
    else if (event == TIMEOUT_PST)
    {
        /* Your code goes here */
        chitcpd_tcp_handle_TIMEOUT_PST(si, entry);
    }
    else
        chilog(WARNING, "In FIN_WAIT_1 state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_FIN_WAIT_2(serverinfo_t *si, 
                            chisocketentry_t *entry, tcp_event_type_t event)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    if (event == PACKET_ARRIVAL)
    {
        chilog(DEBUG, "[FIN_WAIT_2] PACKET_ARRIVAL");
        chitcpd_tcp_handle_PACKET_ARRIVAL(si, entry, event);
    }
    else if (event == APPLICATION_RECEIVE)
    {
        /* Your code goes here */
        chilog(DEBUG, "[FIN_WAIT_2] APPLICATION_RECEIVE");
        /* Update RCV_WND */
        tcp_data->RCV_WND = tcp_data->recv.maxsize - tcp_data->recv.count;
    }
    else if (event == TIMEOUT_RTX)
    {
        /* Your code goes here */
        chitcpd_tcp_handle_TIMEOUT_RTX(si, entry);
    }
    else
        chilog(WARNING, "In FIN_WAIT_2 state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_CLOSE_WAIT(serverinfo_t *si, 
                            chisocketentry_t *entry, tcp_event_type_t event)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    if (event == APPLICATION_CLOSE)
    {
        /* Your code goes here */
        chilog(DEBUG, "[CLOSE_WAIT] APPLICATION_CLOSE");
        tcp_data->closing = true;
        tcp_data->state_after_close = LAST_ACK;
        /* Before closing the connection, send over
         * all data remaining in send buffer
         */
        chitcpd_process_send_buffer(si, entry);
    }
    else if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
        chilog(DEBUG, "[CLOSE_WAIT] PACKET_ARRIVAL");
        chitcpd_tcp_handle_PACKET_ARRIVAL(si, entry, event);
    }
    else if (event == TIMEOUT_RTX)
    {
        /* Your code goes here */
        chitcpd_tcp_handle_TIMEOUT_RTX(si, entry);
    }
    else if (event == TIMEOUT_PST)
    {
        /* Your code goes here */
        chitcpd_tcp_handle_TIMEOUT_PST(si, entry);
    }
    else
        chilog(WARNING, "In CLOSE_WAIT state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_CLOSING(serverinfo_t *si, 
                            chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        chilog(DEBUG, "[CLOSING] PACKET_ARRIVAL");
        chitcpd_tcp_handle_PACKET_ARRIVAL(si, entry, event);
    }
    else if (event == TIMEOUT_RTX)
    {
        /* Your code goes here */
        chitcpd_tcp_handle_TIMEOUT_RTX(si, entry);
    }
    else if (event == TIMEOUT_PST)
    {
        /* Your code goes here */
        chitcpd_tcp_handle_TIMEOUT_PST(si, entry);
    }
    else
        chilog(WARNING, "In CLOSING state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_TIME_WAIT(serverinfo_t *si, 
                            chisocketentry_t *entry, tcp_event_type_t event)
{
    chilog(WARNING, "Running handler for TIME_WAIT. This should not happen.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_LAST_ACK(serverinfo_t *si, 
                            chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        chilog(DEBUG, "[LAST_ACK] PACKET_ARRIVAL");
        chitcpd_tcp_handle_PACKET_ARRIVAL(si, entry, event);
    }
    else if (event == TIMEOUT_RTX)
    {
        /* Your code goes here */
        chitcpd_tcp_handle_TIMEOUT_RTX(si, entry);
    }
    else if (event == TIMEOUT_PST)
    {
        /* Your code goes here */
        chitcpd_tcp_handle_TIMEOUT_PST(si, entry);
    }
    else
        chilog(WARNING, "In LAST_ACK state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

/*                                                           */
/*     Any additional functions you need should go here      */
/*                                                           */


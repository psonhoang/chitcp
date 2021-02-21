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

void callback_func(multi_timer_t* multi_timer, single_timer_t* single_timer, 
                                                            void *tcp_param)
{
    callback_void_param_t *void_params;
    void_params = (callback_void_param_t *) tcp_param; 
    chitcpd_timeout(void_params->si, void_params->entry, void_params->timer_type);
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
    callback_void_param_t *void_param = malloc(sizeof (callback_void_param_t));
    void_param->si = si;
    void_param->entry = entry;
    callback_args_t *callback_args = malloc(sizeof (callback_args_t));
    callback_args->multi_timer = tcp_data->tcp_timer;
    for (int i = 0; i < tcp_data->tcp_timer->num_timers; i++)
    {
        timer = tcp_data->tcp_timer->timers[i];
        timer->callback = callback_func;
        if (i == 0) {
            void_param->timer_type = RETRANSMISSION;
        }
        else 
        {
            void_param->timer_type = PERSIST;
        }
        callback_args->single_timer = timer;
        callback_args->tcp_param = void_param;
        timer->callback_args = (void *) callback_args;
    }
    tcp_data->queue = NULL;
    tcp_data->list = NULL;
    tcp_data->RTO = MIN_RTO;
    tcp_data->rtms_timer_on = false;
}

void tcp_data_free(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    mt_free(tcp_data->tcp_timer);
    free(tcp_data->tcp_timer);
    //free(tcp_data->queue); //TODO
    //free(tcp_data->list ); //TODO
    circular_buffer_free(&tcp_data->send);
    circular_buffer_free(&tcp_data->recv);
    chitcp_packet_list_destroy(&tcp_data->pending_packets);
    pthread_mutex_destroy(&tcp_data->lock_pending_packets);
    pthread_cond_destroy(&tcp_data->cv_pending_packets);

    /* Cleanup of additional tcp_data_t fields goes here */
}

/* P2a */

/* HELPER FUNCTION */

/* Generate random uint32_t */
uint32_t random_uint32()
{
    /* This code is referred from a StackOverflow answer
     * Source: See README
     */
    uint32_t x = rand() & 0xff;
    x |= (rand() & 0xff) << 8;
    x |= (rand() & 0xff) << 16;
    x |= (rand() & 0xff) << 24;

    return x;
}

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

struct timespec *set_timer(serverinfo_t *si, chisocketentry_t *entry, 
                            uint64_t timeout, tcp_timer_type_t timer_type)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    retransmission_queue_t *queue = tcp_data->queue;
    if ((!tcp_data->rtms_timer_on) && (queue != NULL)) //// check if send buffer is empty
    {
        tcp_data->rtms_timer_on = true;
        single_timer_t *timer = tcp_data->tcp_timer->timers[timer_type];
        mt_set_timer(tcp_data->tcp_timer, timer_type, tcp_data->RTO, 
                            timer->callback, timer->callback_args); 
        return timer->timeout_spec;
    }
    else
    {
        struct timespec *result = malloc(sizeof (struct timespec));
        clock_gettime(CLOCK_REALTIME, result);
        result->tv_nsec += timeout;
        while (result->tv_nsec > 1.0e9)
        {
            // Normalizing timespec
            result->tv_nsec -= 1.0e9;
            result->tv_sec++;
        }
        return result;
    }
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
    /* bytes_in_send is the total bytes currently in the send buffer */
    int bytes_in_send = circular_buffer_count(&tcp_data->send);
    chilog(DEBUG, "[SEND] TOTAL BYTE IN SEND BUFFER IS %d", bytes_in_send);
    if (bytes_in_send == 0) 
    {
        // If no bytes in send buffer, then return as we have nothing to send
        return;
    }
    int possible_send_bytes = tcp_data->SND_WND;
    chilog(DEBUG, "[SEND] TOTAL SEND WINDOW IS %d", possible_send_bytes);
    // total_send_bytes are total bytes we are going to send
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
    chilog(DEBUG, "[SEND] TOTAL BYTE GOING TO BE SENT IS %d", 
                                            total_send_bytes);
    int payload_len;
    while (total_send_bytes > 0)
    {
        //chilog(DEBUG, "[SEND] ENTER LOOP");
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
        bytes_read = circular_buffer_read(&tcp_data->send, payload, 
                                                payload_len, FALSE);
        chilog(DEBUG, "[SEND] TOTAL BYTES READ FROM SENT BUFFER IS %d", 
                                                            bytes_read);
        chilog(DEBUG, "DATA REMAINING IN BUFFER IS %d", 
                                circular_buffer_count(&tcp_data->send));
        if (bytes_read > 0) {
            // update num of bytes left we need to send
            total_send_bytes -= bytes_read;
            /* Create send packet */
            chitcpd_tcp_packet_create(entry, send_packet, 
                                                    payload, payload_len);
            tcphdr_t *send_header = TCP_PACKET_HEADER(send_packet);
            /* Update TCP variables and send header */
            tcp_data->SND_NXT = tcp_data->SND_NXT + bytes_read;
            send_header->ack = 1;
            send_header->syn = 0;
            send_header->fin = 0;
            send_header->ack_seq = tcp_data->RCV_NXT;
            send_header->seq = tcp_data->SND_NXT;
            send_header->win = tcp_data->RCV_WND;
            /* Send packet */
            chilog(DEBUG, "[SEND] send payload's length: %d", 
                                        TCP_PAYLOAD_LEN(send_packet));
            chitcpd_send_tcp_packet(si, entry, send_packet);
            free_packet(send_packet);
        }
    }
}

int chitcpd_tcp_handle_TIMEOUT_RTX(serverinfo_t *si, 
                            chisocketentry_t *entry, tcp_event_type_t event)
{

}

int chitcpd_tcp_handle_TIMEOUT_PST(serverinfo_t *si, 
                            chisocketentry_t *entry, tcp_event_type_t event)
{

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
    /* Initialize packet to send over to the other host */
    tcp_packet_t *send_packet = malloc(sizeof(tcp_packet_t));
    chitcpd_tcp_packet_create(entry, send_packet, NULL, 0);
    tcphdr_t *send_header = TCP_PACKET_HEADER(send_packet);
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
            uint32_t ISS = random_uint32();
            tcp_data->ISS = ISS;
            tcp_data->SND_UNA = ISS;
            tcp_data->SND_NXT = ISS + 1;
            tcp_data->RCV_NXT = header->seq + 1;
            tcp_data->RCV_WND = circular_buffer_capacity(&tcp_data->recv);
            tcp_data->IRS = header->seq;
            circular_buffer_set_seq_initial(&tcp_data->recv, 
                                                        tcp_data->IRS + 1);
            circular_buffer_set_seq_initial(&tcp_data->send, 
                                                        tcp_data->ISS + 1);
            /* Fill in header for send packet with syn segment */
            send_header->syn = 1;
            send_header->ack = 1;
            send_header->fin = 0;
            send_header->seq = ISS;
            send_header->ack_seq = header->seq + 1;
            send_header->win = tcp_data->RCV_WND;
            chitcpd_send_tcp_packet(si, entry, send_packet);
            clock_gettime(CLOCK_REALTIME, tcp_data->begin);
            free_packet(send_packet);
            /* Transition to SYN_RCVD */
            chitcpd_update_tcp_state(si, entry, SYN_RCVD);
            return 0;
        }
    }
    else if (tcp_state == SYN_SENT)
    {
        if (header->ack == 1)
        {
            if (!((tcp_data->SND_UNA <= header->ack_seq) &&
                (header->ack_seq <= tcp_data->SND_NXT)))
            {
                // not acceptable
                return 0;
            }
        }
        if (header->syn == 1)
        {
            tcp_data->SND_UNA = header->ack_seq;
            tcp_data->SND_NXT = header->ack_seq;
            tcp_data->RCV_NXT = header->seq + 1;
            tcp_data->IRS = header->seq;
            tcp_data->SND_WND = header->win;
            circular_buffer_set_seq_initial(&tcp_data->recv, 
                                                tcp_data->IRS + 1);
            if (tcp_data->SND_UNA > tcp_data->ISS)
            {
                // If our SYN has been acknowledged
                clock_gettime(CLOCK_REALTIME, tcp_data->end);
                send_header->ack = 1;
                send_header->syn = 0;
                send_header->fin = 0;
                send_header->seq = tcp_data->SND_NXT;
                send_header->ack_seq = tcp_data->RCV_NXT;
                send_header->win = tcp_data->RCV_WND;
                chitcpd_send_tcp_packet(si, entry, send_packet);
                free_packet(send_packet);
                // Transition to ESTABLISHED
                chitcpd_update_tcp_state(si, entry, ESTABLISHED);
            }
            else
            {
                // If we haven't sent over SYN segment
                send_header->ack = 1;
                send_header->syn = 1;
                send_header->fin = 0;
                send_header->seq = tcp_data->ISS;
                send_header->ack_seq = tcp_data->RCV_NXT;
                send_header->win = tcp_data->RCV_WND;
                chitcpd_send_tcp_packet(si, entry, send_packet);
                free_packet(send_packet);
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
        if ((RCV_WND == 0) && (SEG_LEN == 0))
        {
            if (header->seq != tcp_data->RCV_NXT)
            {
                chilog(DEBUG,"[LISTEN] IT DOESN'T PASS FIRST ACCEPTABILITY TEST IN THE PACKET_ARRIVAL HANDLER FUNCTION");
                send_header->ack = 1;
                send_header->syn = 0;
                send_header->fin = 0;
                send_header->seq = tcp_data->SND_NXT;
                send_header->ack_seq = tcp_data->RCV_NXT;
                send_header->win = tcp_data->RCV_WND;
                chitcpd_send_tcp_packet(si, entry, send_packet);
                free_packet(send_packet);
                return 0;
            }
        }
        else if ((RCV_WND > 0) && (SEG_LEN == 0))
        {
            if (!((tcp_data->RCV_NXT <= header->seq) &&
                (header->seq < (tcp_data->RCV_NXT + tcp_data->RCV_WND))))
            {
                // if (tcp_data->RCV_NXT > header->seq)
                // {
                //     chilog(DEBUG, "[LISTEN] RCV_NXT: %d", tcp_data->RCV_NXT);
                //     chilog(DEBUG, "[LISTEN] header->seq: %d", header->seq);
                //     chilog(DEBUG,"[LISTEN] rcv_nxt > sequence number in SECOND ACCEPTABILITY TEST");
                // }
                // if (header->seq > (tcp_data->RCV_NXT + tcp_data->RCV_WND))
                // {
                //     chilog(DEBUG,"[LISTEN] sequence num > receive fram in SECOND ACCEPTABILITY TEST");
                // }
                send_header->ack = 1;
                send_header->syn = 0;
                send_header->fin = 0;
                send_header->seq = tcp_data->SND_NXT;
                send_header->ack_seq = tcp_data->RCV_NXT;
                send_header->win = tcp_data->RCV_WND;
                chitcpd_send_tcp_packet(si, entry, send_packet);
                free_packet(send_packet);
                return 0;
            }
        }
        else if ((RCV_WND == 0) && (SEG_LEN > 0))
        {
            chilog(DEBUG,"[LISTEN] IT COMES TO THIRD ACCEPTABILITY TEST IN THE PACKET_ARRIVAL HANDLER FUNCTION");
            send_header->ack = 1;
            send_header->syn = 0;
            send_header->fin = 0;
            send_header->seq = tcp_data->SND_NXT;
            send_header->ack_seq = tcp_data->RCV_NXT;
            send_header->win = tcp_data->RCV_WND;
            chitcpd_send_tcp_packet(si, entry, send_packet);
            free_packet(send_packet);
            return 0;
        }
        else if ((RCV_WND > 0) && (SEG_LEN > 0))
        {
            chilog(DEBUG,"[LISTEN] IT COMES TO FOURTH ACCEPTABILITY TEST IN THE PACKET_ARRIVAL HANDLER FUNCTION");
            if (!(((tcp_data->RCV_NXT <= header->seq) &&
                (header->seq < (tcp_data->RCV_NXT + tcp_data->RCV_WND))) ||
                ((tcp_data->RCV_NXT <= (header->seq + SEG_LEN - 1)) &&
                ((header->seq + SEG_LEN - 1) < 
                                (tcp_data->RCV_NXT + tcp_data->RCV_WND)))))
            {
                chilog(DEBUG,"[LISTEN] IT DOESN'T PASS FOURTH ACCEPTABILITY TEST IN THE PACKET_ARRIVAL HANDLER FUNCTION");
                send_header->ack = 1;
                send_header->syn = 0;
                send_header->fin = 0;
                send_header->seq = tcp_data->SND_NXT;
                send_header->ack_seq = tcp_data->RCV_NXT;
                send_header->win = tcp_data->RCV_WND;
                chitcpd_send_tcp_packet(si, entry, send_packet);
                free_packet(send_packet);
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
                chilog(DEBUG, "[LISTEN] header->ack = %d", header->ack);
                chilog(DEBUG, "[LISTEN] tcp_data->ISS = %d", tcp_data->ISS);
                chilog(DEBUG, "[LISTEN] tcp_data->SND_UNA = %d", 
                                                        tcp_data->SND_UNA);
                chilog(DEBUG, "[LISTEN] tcp_data->SND_NEXT = %d", 
                                                        tcp_data->SND_NXT);
                if ((tcp_data->SND_UNA <= header->ack_seq) &&
                    (header->ack_seq <= tcp_data->SND_NXT))
                {
                    // acceptable segment
                    tcp_data->SND_UNA = header->ack_seq;
                    tcp_data->SND_NXT = header->ack_seq;
                    tcp_data->SND_WND = header->win;
                    chitcpd_update_tcp_state(si, entry, ESTABLISHED);
                    return 0;
                }
            }
            else
            {
                chilog(DEBUG,"[LISTEN] IT COMES OTHER EVENTS IN THE PACKET_ARRIVAL HANDLER FUNCTION");
                if ((tcp_data->SND_UNA <= header->ack_seq) &&
                    (header->ack_seq <= tcp_data->SND_NXT))
                {
                    tcp_data->SND_UNA = header->ack_seq;
                    tcp_data->SND_WND = header->win;
                    chitcpd_process_send_buffer(si, entry);
                }
                else if (header->ack_seq > tcp_data->SND_NXT)
                {
                    // ACK acks something not yet sent, send Ack
                    chilog(DEBUG, "[LISTEN] header->ack_seq: %d", 
                                                        header->ack_seq);
                    chilog(DEBUG, "[LISTEN] tcp_data->SND_NXT: %d", 
                                                        tcp_data->SND_NXT);
                    chilog(DEBUG, "[LISTEN] header->ack_seq > tcp_data->SND_NXT");
                    send_header->ack = 1;
                    send_header->syn = 0;
                    send_header->fin = 0;
                    send_header->seq = tcp_data->SND_NXT;
                    send_header->ack_seq = tcp_data->RCV_NXT;
                    send_header->win = tcp_data->RCV_WND;
                    chitcpd_send_tcp_packet(si, entry, send_packet);
                    free_packet(send_packet);
                }
                else 
                {
                    // If the ACK is a duplicate
                    //ignore
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
                else if (tcp_state == FIN_WAIT_2)
                {
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
                    int bytes_written = circular_buffer_write(&tcp_data->recv,
                                                    TCP_PAYLOAD_START(packet),
                                                    TCP_PAYLOAD_LEN(packet), 
                                                    FALSE);
                    chilog(DEBUG, "[SEND] payload length: %d", 
                                                TCP_PAYLOAD_LEN(packet));
                    chilog(DEBUG, "[SEND] bytes written is %d", 
                                                bytes_written);
                    tcp_data->RCV_NXT += bytes_written;
                    tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);
                    send_header->ack = 1;
                    send_header->syn = 0;
                    send_header->fin = 0;
                    send_header->seq = tcp_data->SND_NXT;
                    send_header->ack_seq = tcp_data->RCV_NXT;
                    send_header->win = tcp_data->RCV_WND;
                    chitcpd_send_tcp_packet(si, entry, send_packet);
                    free_packet(send_packet);
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
                    tcp_data->RCV_NXT = header->seq + 1;
                    send_header->ack = 1;
                    send_header->syn = 0;
                    send_header->fin = 0;
                    send_header->seq = tcp_data->SND_NXT;
                    send_header->ack_seq = tcp_data->RCV_NXT;
                    send_header->win = tcp_data->RCV_WND;
                    chitcpd_send_tcp_packet(si, entry, send_packet);
                    free_packet(send_packet);
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
    if (packet != NULL)
    {
        free_packet(packet);
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
        uint32_t ISS = random_uint32();
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
        header->seq = ISS;
        header->ack_seq = 0;
        header->win = tcp_data->RCV_WND;
        chitcpd_send_tcp_packet(si, entry, packet);
        clock_gettime(CLOCK_REALTIME, tcp_data->begin);
        free_packet(packet);
        /* Transition to SYN_SENT */
        chitcpd_update_tcp_state(si, entry, SYN_SENT);
    }
    else if (event == CLEANUP)
    {
        /* Any additional cleanup goes here */
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
        /* Before closing the connection, send over
         * all data remaining in send buffer
         */
        while (circular_buffer_count(&tcp_data->send) != 0)
        {
            //chilog(DEBUG, "[ESTABLISHED] APPLICATION_CLOSE - stuck in send loop!");
            // tcp_data is updated during these sends
            chitcpd_process_send_buffer(si, entry);
        }
        /* Create packet with fin segment to send over to other host */
        tcp_packet_t *send_packet = malloc(sizeof(tcp_packet_t));
        chitcpd_tcp_packet_create(entry, send_packet, NULL, 0);
        tcphdr_t *send_header = TCP_PACKET_HEADER(send_packet);
        send_header->fin = 1;
        send_header->ack = 1;
        send_header->syn = 0;
        send_header->seq = tcp_data->SND_NXT;
        send_header->ack_seq = tcp_data->RCV_NXT;
        send_header->win = tcp_data->RCV_WND;
        chitcpd_send_tcp_packet(si, entry, send_packet);
        free_packet(send_packet);
        /* Update SND_NXT after sending fin segment */
        tcp_data->SND_NXT += 1;
        /* Transition to FIN_WAIT_1 */
        chitcpd_update_tcp_state(si, entry, FIN_WAIT_1);
    }
    else if (event == TIMEOUT_RTX)
    {
        /* Your code goes here */
    }
    else if (event == TIMEOUT_PST)
    {
        /* Your code goes here */
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
    }
    else if (event == TIMEOUT_PST)
    {
        /* Your code goes here */
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
        /* Before closing the connection, send over
         * all data remaining in send buffer
         */
        while (circular_buffer_count(&tcp_data->send) != 0)
        {
            chilog(DEBUG, "[CLOSE_WAIT] stuck in send buffer loop!");
            chitcpd_process_send_buffer(si, entry);
        }
        // Create a packet with fin segment to send over to the other host
        tcp_packet_t *send_packet = malloc(sizeof(tcp_packet_t));
        chitcpd_tcp_packet_create(entry, send_packet, NULL, 0);
        tcphdr_t *send_header = TCP_PACKET_HEADER(send_packet);
        send_header->fin = 1;
        send_header->ack = 1;
        send_header->syn = 0;
        send_header->seq = tcp_data->SND_NXT;
        send_header->ack_seq = tcp_data->RCV_NXT;
        send_header->win = tcp_data->RCV_WND;
        chitcpd_send_tcp_packet(si, entry, send_packet);
        free_packet(send_packet);
        // Update SND_NXT after having sent fin segment
        tcp_data->SND_NXT += 1;
        // Transition to LAST_ACK
        chitcpd_update_tcp_state(si, entry, LAST_ACK);
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
    }
    else if (event == TIMEOUT_PST)
    {
        /* Your code goes here */
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
    }
    else if (event == TIMEOUT_PST)
    {
        /* Your code goes here */
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
    }
    else if (event == TIMEOUT_PST)
    {
        /* Your code goes here */
    }
    else
        chilog(WARNING, "In LAST_ACK state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

/*                                                           */
/*     Any additional functions you need should go here      */
/*                                                           */


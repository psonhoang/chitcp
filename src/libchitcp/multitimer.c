/*
 *  chiTCP - A simple, testable TCP stack
 *
 *  An API for managing multiple timers
 */

/*
 *  Copyright (c) 2013-2019, The University of Chicago
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
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
 *    software without specific prior written permission.
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
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <inttypes.h>
#include "chitcp/multitimer.h"
#include "chitcp/log.h"


void *multitimer_thread(void *args)
{
    chilog(INFO, "[MULTITIMER] MULTITIMER THREAD BEGINS\r\n");
    worker_args_t *wa;
    wa = (worker_args_t *) args;
    multi_timer_t *mt = wa->mt;
    int rc;
    pthread_mutex_lock(&mt->lock);
    while (mt->active_thread)
    {
        if(mt->num_active_timers == 0)
        {
            chilog(INFO, "[MULTITIMER] I'M SLEEPING\r\n");
            pthread_cond_wait(&mt->condwait, &mt->lock);
        }
        else
        {
            single_timer_t *head = mt->active_timers;
            rc = pthread_cond_timedwait(&mt->condwait, &mt->lock, 
                                    head->timeout_spec);
            if (rc == ETIMEDOUT)
            {
                chilog(DEBUG, "[MULTITIMER] TIME OUT!\r\n");
                if (head->callback != NULL)
                {
                    head->callback(mt, head, head->callback_args);
                }
                head->active = false;
                head->num_timeouts++;
                mt->num_active_timers--;
                DL_DELETE(mt->active_timers, head);
            }
            else
            {
                chilog(DEBUG, "[MULTITIMER] WAKEN UP BUT NOT BECAUSE OF TIMEOUT!\r\n");
            }
        }
    }
    pthread_mutex_unlock(&mt->lock);
    chilog(DEBUG, "[MULTITIMER] MULTITIMER THREAD ENDS\r\n");
    pthread_exit(NULL);
}

struct timespec *count_timeout_spec(uint64_t timeout)
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

/* See multitimer.h */
int timespec_subtract(struct timespec *result, struct timespec *x, struct timespec *y)
{
    struct timespec tmp;
    tmp.tv_sec = y->tv_sec;
    tmp.tv_nsec = y->tv_nsec;

    /* Perform the carry for the later subtraction by updating tmp. */
    if (x->tv_nsec < tmp.tv_nsec) {
        uint64_t sec = (tmp.tv_nsec - x->tv_nsec) / SECOND + 1;
        tmp.tv_nsec -= SECOND * sec;
        tmp.tv_sec += sec;
    }
    if (x->tv_nsec - tmp.tv_nsec > SECOND) {
        uint64_t sec = (x->tv_nsec - tmp.tv_nsec) / SECOND;
        tmp.tv_nsec += SECOND * sec;
        tmp.tv_sec -= sec;
    }

    /* Compute the time remaining to wait.
       tv_nsec is certainly positive. */
    result->tv_sec = x->tv_sec - tmp.tv_sec;
    result->tv_nsec = x->tv_nsec - tmp.tv_nsec;

    /* Return 1 if result is negative. */
    return x->tv_sec < tmp.tv_sec;
}


/* See multitimer.h */
int mt_init(multi_timer_t *mt, uint16_t num_timers)
{
    /* Your code here */
    /* Initialize multitimer */
    chilog(INFO, "[MULTITIMER] INITIALIZE TIMER\r\n");
    mt->timers = malloc(sizeof(single_timer_t *) * num_timers);
    mt->active_thread = true;
    mt->active_timers = NULL;
    mt->num_timers = num_timers;
    mt->num_active_timers = 0;
    for (int i = 0; i < num_timers; i++)
    {
        //chilog(INFO, "[MULTITIMER] INITIALIZE TIMER %d\r\n", i);
        mt->timers[i] = malloc(sizeof (single_timer_t));
        single_timer_t *timer = mt->timers[i];
        timer->id = i;
        timer->callback = NULL;
        timer->callback_args = NULL;
        timer->active = false;
        timer->num_timeouts = 0;
        timer->timeout_spec = malloc(sizeof(struct timespec));
        //chilog(INFO, "[MULTITIMER] FINISH INITIALIZING TIMER %d\r\n", i);
    }
    //chilog(INFO, "[MULTITIMER] INITIALIZE SINGLE TIMERS\r\n");
    pthread_mutex_init(&mt->lock, NULL);
    pthread_cond_init(&mt->condwait, NULL); // check error?
    /* Initialize multitimer thread */
    worker_args_t(*wa);
    wa = calloc(1, sizeof(worker_args_t));
    wa->mt = mt;
    if (pthread_create(&mt->multimer_thread, NULL, multitimer_thread, wa) != 0)
    {
        chilog(INFO, "[MULTITIMER] THREAD COULDN'T BE CREATED\r\n");
        mt_free(mt);
        return CHITCP_ETHREAD;
    }

    return CHITCP_OK;
}

void free_single_timer(single_timer_t *timer)
{
    free(timer->timeout_spec);
}

/* See multitimer.h */
int mt_free(multi_timer_t *mt)
{
    /* Your code here */
    chilog(INFO, "[MULTITIMER] FREE TIMER BEGINS\r\n");
    pthread_mutex_lock(&mt->lock);
    mt->active_thread = false;
    pthread_cond_signal(&mt->condwait);
    pthread_mutex_unlock(&mt->lock);

    for (int i = 0; i < mt->num_timers; i++)
    {
        free_single_timer(mt->timers[i]);
    }
    free(mt->timers);
    free(mt->active_timers);
    pthread_join(mt->multimer_thread, NULL);
    pthread_mutex_destroy(&mt->lock);
    pthread_cond_destroy(&mt->condwait);
    // free(mt);
    // chilog(INFO, "[MULTITIMER] FREE MULTIMER STRUCT WORKS\r\n");
    chilog(DEBUG, "[MULTITIMER] MAIN THREAD ENDS\r\n");
    return CHITCP_OK;
}


/* See multitimer.h */
int mt_get_timer_by_id(multi_timer_t *mt, uint16_t id, single_timer_t **timer)
{
    /* Your code here */
    if (id < 0 || id >= mt->num_timers)
    {
        return CHITCP_EINVAL;
    }

    *timer = mt->timers[id];

    return CHITCP_OK;
}

int timeoutcmp(single_timer_t *a, single_timer_t *b)
{
    /* Function to compare absolute timeouts of timers */
    struct timespec *first_item = a->timeout_spec;
    struct timespec *second_item = b->timeout_spec;
    if (first_item->tv_sec > second_item->tv_sec)
    {
        return 1;
    }
    else if (first_item->tv_sec < second_item->tv_sec)
    {
        return -1;
    }
    else
    {
        if (first_item->tv_nsec > second_item->tv_nsec)
        {
            return 1;
        }
        else if (first_item->tv_nsec < second_item->tv_nsec)
        {
            return -1;
        }
        else 
        {
            return 0;
        }
    }
}

/* See multitimer.h */
int mt_set_timer(multi_timer_t *mt, uint16_t id, uint64_t timeout, mt_callback_func callback, void* callback_args)
{
    /* Your code here */
    /* Checks if valid id */
    if (id < 0 || id >= mt->num_timers)
    {
        return CHITCP_EINVAL;
    }
    /* Checks if timer is already active */
    single_timer_t *elt;
    DL_FOREACH(mt->active_timers, elt)
    {
        if(elt->id == id)
        {
            return CHITCP_EINVAL;
        }
    }
    /* Update timer's timeout timespec */
    single_timer_t *timer = mt->timers[id];
    // clock_gettime(CLOCK_REALTIME, timer->timeout_spec);
    // timer->timeout_spec->tv_nsec += timeout;
    // while (timer->timeout_spec->tv_nsec > 1.0e9)
    // {
    //     // Normalizing timespec
    //     timer->timeout_spec->tv_nsec -= 1.0e9;
    //     timer->timeout_spec->tv_sec++;
    // }
    timer->timeout_spec = count_timeout_spec(timeout);
    /* Timer's callback */
    timer->callback = callback;
    timer->callback_args = callback_args;
    /* Set timer to active status and sort active timers list */
    timer->active = true;
    DL_APPEND(mt->active_timers, timer);
    mt->num_active_timers++;
    DL_SORT(mt->active_timers, timeoutcmp);
    pthread_mutex_lock(&mt->lock);
    pthread_cond_signal(&mt->condwait);
    pthread_mutex_unlock(&mt->lock);

    return CHITCP_OK;
}


/* See multitimer.h */
int mt_cancel_timer(multi_timer_t *mt, uint16_t id)
{
    /* Your code here */
    /* Checks if valid id */
    if (id < 0 || id >= mt->num_timers)
    {
        return CHITCP_EINVAL;
    }
    /* Checks if timer is already active */
    single_timer_t *elt;
    bool is_active = false;
    DL_FOREACH(mt->active_timers, elt)
    {
        if (elt->id == id)
        {
            is_active = true;
            break;
        }
    }
    if (!is_active)
    {
        return CHITCP_EINVAL;
    }
    /* Set timer to inactive status and update active timers list */
    single_timer_t *timer = mt->timers[id];
    timer->active = false;
    mt->num_active_timers--;
    DL_DELETE(mt->active_timers, timer);
    /* Wake up thread */
    pthread_mutex_lock(&mt->lock);
    pthread_cond_signal(&mt->condwait);
    pthread_mutex_unlock(&mt->lock);
    return CHITCP_OK;
}


/* See multitimer.h */
int mt_set_timer_name(multi_timer_t *mt, uint16_t id, const char *name)
{
    /* Your code here */
    if (id < 0 || id >= mt->num_timers)
    {
        return CHITCP_EINVAL;
    }
    strcpy(mt->timers[id]->name, name);

    return CHITCP_OK;
}


/* mt_chilog_single_timer - Prints a single timer using chilog
 *
 * level: chilog log level
 *
 * timer: Timer
 *
 * Returns: Always returns CHITCP_OK
 */
int mt_chilog_single_timer(loglevel_t level, single_timer_t *timer)
{
    struct timespec now, diff;
    clock_gettime(CLOCK_REALTIME, &now);

    if(timer->active)
    {
        /* Compute the appropriate value for "diff" here; it should contain
         * the time remaining until the timer times out.
         * Note: The timespec_subtract function can come in handy here*/
        diff.tv_sec = 0;
        diff.tv_nsec = 0;
        chilog(level, "%i %s %lis %lins", timer->id, timer->name, diff.tv_sec, diff.tv_nsec);
    }
    else
        chilog(level, "%i %s", timer->id, timer->name);

    return CHITCP_OK;
}


/* See multitimer.h */
int mt_chilog(loglevel_t level, multi_timer_t *mt, bool active_only)
{
    /* Your code here */

    return CHITCP_OK;
}

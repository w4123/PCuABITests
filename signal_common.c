// SPDX-License-Identifier: GPL-2.0
/*
 * Based on mainline tools/testing/selftests/arm64/bti/signal.c
 *
 * Copyright (C) 2019  Arm Limited
 * Original author: Dave Martin <Dave.Martin@arm.com>
 */

#include <linux/errno.h>
#include <linux/time.h>
#include <linux/stat.h>
#include "freestanding.h"
#include "signal_common.h"

int sigemptyset(sigset_t *s)
{
	unsigned int i;

	for (i = 0; i < _NSIG_WORDS; ++i)
		s->sig[i] = 0;

	return 0;
}

int sigaddset(sigset_t *s, int n)
{
	if (n < 1 || n > _NSIG)
		return -EINVAL;

	s->sig[(n - 1) / _NSIG_BPW] |= 1UL << (n - 1) % _NSIG_BPW;
	return 0;
}

int sigaction(int n, struct sigaction *sa, const struct sigaction *old)
{
	return syscall(__NR_rt_sigaction, n, sa, old, sizeof(sa->sa_mask));
}

int sigprocmask(int how, const sigset_t *mask, sigset_t *old)
{
	return syscall(__NR_rt_sigprocmask, how, mask, old, sizeof(*mask));
}

int sigaltstack(const stack_t *ss, stack_t *old_ss)
{
	return syscall(__NR_sigaltstack, ss, old_ss);
}

int setitimer(int which, const struct itimerval *new_value, struct itimerval *old_value)
{
	return syscall(__NR_setitimer, which, new_value, old_value);
}

mqd_t mq_open(const char *name, int oflag)
{
	return syscall(__NR_mq_open, name, oflag, 0666, NULL);
}

int mq_unlink(const char *name)
{
	return syscall(__NR_mq_unlink, name);
}

int mq_notify(mqd_t mqdes, const struct sigevent *sevp)
{
	return syscall(__NR_mq_notify, mqdes, sevp);
}

int mq_timedsend(mqd_t mqdes, const char *msg, size_t len, unsigned int prio,
		 const struct timespec *timeout)
{
	return syscall(__NR_mq_timedsend, mqdes, msg, len, prio, timeout);
}

int timer_create(clockid_t clockid, struct sigevent *sevp, timer_t *timerid)
{
	return syscall(__NR_timer_create, clockid, sevp, timerid);
}

int timer_delete(timer_t timerid)
{
	return syscall(__NR_timer_delete, timerid);
}

int timer_settime(timer_t timerid, int flags, const struct itimerspec *new_value,
		  struct itimerspec *old_value)
{
	return syscall(__NR_timer_settime, timerid, flags, new_value, old_value);
}

int rt_sigqueueinfo(pid_t tgid, int sig, siginfo_t *uinfo)
{
	return syscall(__NR_rt_sigqueueinfo, tgid, sig, uinfo);
}

int rt_tgsigqueueinfo(pid_t tgid, pid_t tid, int sig, siginfo_t *uinfo)
{
	return syscall(__NR_rt_tgsigqueueinfo, tgid, tid, sig, uinfo);
}

int pidfd_open(pid_t pid, int flags)
{
	return syscall(__NR_pidfd_open, pid, flags);
}

int pidfd_send_signal(int pidfd, int sig, siginfo_t *uinfo, unsigned int flags)
{
	return syscall(__NR_pidfd_send_signal, pidfd, sig, uinfo, flags);
}

int rt_sigtimedwait(const sigset_t *set, siginfo_t *info,
		    const struct timespec *timeout, size_t sigsetsize)
{
	return syscall(__NR_rt_sigtimedwait, set, info, timeout, sigsetsize);
}

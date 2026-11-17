#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/ipc.h>
#include <sys/msg.h>
int main(void){
	int q = msgget(IPC_PRIVATE, 0600|IPC_CREAT);
	printf("msgget=%d errno=%d (%s)\n", q, errno, strerror(errno));
	if (q >= 0) {
		struct { long mtype; char mtext[80]; } mb;
		mb.mtype = 0x100000000L; memset(mb.mtext,0x41,80);
		errno=0; int r = msgsnd(q, &mb, 80, IPC_NOWAIT);
		printf("msgsnd=%d errno=%d (%s)\n", r, errno, strerror(errno));
		msgctl(q, IPC_RMID, NULL);
	}
	return 0;
}

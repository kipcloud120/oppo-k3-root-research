#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/xattr.h>
static long slab128(void){
	FILE *f=fopen("/proc/slabinfo","r"); char l[512],n[64]; long a,num,o,op,pp;
	if(!f) return -1;
	while(fgets(l,sizeof(l),f))
		if(sscanf(l,"%63s %ld %ld %ld %ld %ld",n,&a,&num,&o,&op,&pp)==6 && !strcmp(n,"kmalloc-128")){fclose(f);return a;}
	fclose(f);return -1;
}
int main(void){
	char v[96]; memset(v,0x42,sizeof(v));
	int fd=open("/data/local/tmp/xa_spray",O_CREAT|O_RDWR,0600);
	if(fd<0){printf("open fail %d\n",errno);return 1;}
	close(fd);
	long a0=slab128();
	int ok=0, N=2000, i;
	char name[64];
	for(i=0;i<N;i++){
		snprintf(name,sizeof(name),"user.k%04d",i);
		if(setxattr("/data/local/tmp/xa_spray",name,v,sizeof(v),0)==0) ok++;
	}
	usleep(200000);
	long a1=slab128();
	printf("baseline=%ld after=%ld delta=%ld  setxattr_ok=%d/%d\n",a0,a1,a1-a0,ok,N);
	for(i=0;i<N;i++){
		snprintf(name,sizeof(name),"user.k%04d",i);
		removexattr("/data/local/tmp/xa_spray",name);
	}
	usleep(200000);
	long a2=slab128();
	printf("after_remove=%ld (vs baseline %ld)\n",a2,a0);
	unlink("/data/local/tmp/xa_spray");
	return 0;
}

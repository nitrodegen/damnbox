/*
 *
 *              
 *              "DamnBox" -  basic x86_64 sandboxing utility 
 *              
 *              This sandbox will cover protecting these syscalls:
 *                      open
 *                      write
 *                      close
 *                      mmap
 *                      munmap
 *                      exec's
 *
 *              google writes better sandboxes than i do?
 *                      watch me.
 *
 *              (C) Gavrilo Palalic 2022.
 */

//testmodule #01
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
int main(){
	

	int fd = open("test.txt",O_RDWR);
	printf("\nFD:%x",fd);
	char hello[5] = "hello";
	write(fd,hello,6);
	close(fd);
	fd =open("test.txt",O_RDONLY);
	char test[32];
	read(fd,test,5);
	printf("\n%s",test);

	char *d = (char*)mmap(0,1024,PROT_READ| PROT_WRITE ,MAP_ANONYMOUS,0,0);
	munmap(d,1024);
	execl("/bin/ls"," -l " ,NULL);

}



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
	char *d = (char*)mmap(NULL,1024,PROT_READ| PROT_WRITE ,MAP_PRIVATE,fd,0);
	printf("\naddress:%p\n",d);
	printf("\naddress:%p\n",d);


	munmap(d,1024);
	execl("/bin/ls"," -l " ,NULL);

}

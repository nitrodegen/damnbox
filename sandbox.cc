/*
 *
 *		"DamnBox" -  basic x86_64 sandboxing utility
 *
 *		This sandbox will cover protecting these syscalls:
 *			open
 *			write
 *			close
 *			mmap
 *			munmap
 *			exec's
 *
 *		google writes better sandboxes than i do?
 *			watch me.
 *
 *		(C) Gavrilo Palalic 2022.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/personality.h>
#include <sys/user.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <fcntl.h>
#include <elf.h>
#include <iostream>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <vector>
#include <sys/syscall.h>
#define INFO "[INFO]"
#define ERROR "[ERROR]"
#define OK "[OK]"

//this helped alot: https://filippo.io/linux-syscall-table/
#define SYS_WRITE 1
#define SYS_READ 0
#define SYS_OPEN 2 //opening files only in current dir
#define SYS_MMAP 9
#define SYS_MUNMAP 11
#define SYS_EXECVE 59
#define SYS_OPENAT 257 //opening files anywhere
using namespace std;
bool debug = false;
#define ELF64_HEADER "\x7f\x45\x4c\x46\x02\x01\x01"

vector<string> split1(string str,string del){
	vector<string>dele;
	ssize_t beg,pos=0;
	while((beg=str.find_first_not_of(del,pos)) != string::npos){ // loop until you find everything that isn't a delimiter , and always set that to be beginning
		pos = str.find_first_of(del,pos+1);//position is always the next case of del

		dele.push_back(str.substr(beg,pos-beg)); // and push
	}
	return dele;
}


class DamnBox{

	public:
		vector<string>allowed_paths={"bin","etc","lib","usr"};
		vector<pair<string, int > >opened_files;
		char *read_reg_string(long value,pid_t pid ){

					char *buf = (char*)malloc(1024);
					memset(buf,0,1024);

					int cc =0;
					while(1){
						if(cc > 1024){
							ptrace(PTRACE_KILL,pid,0,0);
						}

						char c = ptrace(PTRACE_PEEKTEXT,pid,value+(cc*sizeof(char)),NULL);
						if(c != 0xFFFFF){
						//printf("\n%c",c);
						if(c == '\0'){
							buf[cc ] = c;
							break;
						}
						buf[cc] = c;
						cc++;
						}else{
							return NULL;
						}

					}
					
					return buf;

	
		}
		void trace_process(pid_t pid){
			if(debug){
				printf("%s tracing started with pid:%d\n",INFO,pid);
			}
			int stat;
			//wait(&stat);
			waitpid(pid,&stat,0);
			struct user_regs_struct rg;
			string curr_path;
			int curr_fd =0 ;
			while(WIFSTOPPED(stat)){
			
				
				ptrace(PTRACE_SYSCALL,pid,0,0);
				waitpid(pid,&stat,0);
				
				struct user_regs_struct rg;
				ptrace(PTRACE_GETREGS,pid,0,&rg);
				long eax = rg.orig_rax;
				ptrace(PTRACE_SINGLESTEP,pid,0,0);
				waitpid(pid,&stat,0);				
				ptrace(PTRACE_GETREGS,pid,0,&rg);
				if(eax == SYS_OPENAT || eax == SYS_OPEN){
					char *buf = (char*)malloc(1024);
					memset(buf,0,1024);
					int cc =0;
					while(1){
						if(cc > 1024){
							ptrace(PTRACE_KILL,pid,0,0); //preventing buffer overflow :)
						}
						char c = ptrace(PTRACE_PEEKTEXT,pid,rg.rsi+(cc*sizeof(char)),NULL);
						if(c == '\0'){
							buf[cc ] = c;
							break;
						}
						buf[cc] = c;
						cc++;

					}
					
					bool safe_to_open = false;
					if(access(buf,F_OK) ==0){
						safe_to_open = true;
						opened_files.push_back(make_pair(buf,rg.rdi));
						if (debug)
						{	
							printf("\n%s safe to open? %d %s %lld\n", INFO, safe_to_open, buf, rg.rax);
							curr_path = buf;
							curr_fd = rg.rax;

						}
					}					
					
					if(safe_to_open == false){
						rg.rax =-EPERM;
						rg.orig_rax =-1;
						if (debug)
						{
							printf("\n%s not safe to open %s.\n",ERROR,buf);;
						}
						ptrace(PTRACE_SETREGS,pid,0,&rg);
						ptrace(PTRACE_KILL,pid,0,0);
					
						
					}

					free(buf);	

				}
				if(eax == SYS_WRITE){
					//RULES: cant write to any of the system files, cant write to invalid FD ( can cause buffer overflows )
					string path;
					if(rg.rdi == curr_fd){
						path = curr_path;
					}
					if(path.length() > 0 ){
						int can_write=0;
						vector<string>paths = split1(path,"/");
						for(int i =0;i<allowed_paths.size();i++){
							if(paths[0] != allowed_paths[i]);
							{	
								can_write++;
							}
						}
						if(can_write <= 0){
							printf("\n[ERROR] unsafe write %s .",path.c_str());
							rg.orig_rax = -1;
							rg.rax = -1;
							ptrace(PTRACE_SETREGS, pid, 0, &rg);
							ptrace(PTRACE_KILL, pid, 0, 0);
						}

					}

				}
				if(eax == SYS_MMAP){

					/*

						what would be an invalid mmap?
							
							mmaping to already used address.
							mmaping too much memory
							using actual mmap failed address
					

					*/
				
					struct user_regs_struct testrg;					
					ptrace(PTRACE_SINGLESTEP,pid,0,0);
					waitpid(pid,&stat,0);	
					ptrace(PTRACE_GETREGS,pid,0,&testrg);

					long size = rg.rsi;
					long address = testrg.rax;
					if(debug){

						printf("\naddr:%llx size:%ld",testrg.rax,size);
					}
					int valid =0;
					for(int i =0;i<13;i++){
						char ch = ptrace(PTRACE_PEEKDATA,pid,address+i,0);
						if(ch!=(char)0x41){
							valid++;
						}
					}
					
					if(testrg.rax == 0xffffffffffffffea || testrg.rax == 0xffffffffffffffff || rg.rax == 0xffffffffffffffea || rg.rax == 0xffffffffffffffff ){
						printf("\n[ERROR] mmap region returned MAP_FAILED.");
						rg.orig_rax = -1;
						rg.rax = -1;
						ptrace(PTRACE_SETREGS, pid, 0, &rg);
						ptrace(PTRACE_KILL, pid, 0, 0);
					}
					if(valid ==0 ){
						printf("\n[ERROR] mmap failed.");
						rg.orig_rax = -1;
						rg.rax = -1;
						ptrace(PTRACE_SETREGS, pid, 0, &rg);
						ptrace(PTRACE_KILL, pid, 0, 0);
					}
				}
				
				if(eax == SYS_READ){
					string path;
					if(rg.rdi == curr_fd){
						path = curr_path;
					}
					if(path.length() > 0 ) { 
						vector<string> paths = split1(path,"/");
							int check1=0;
							for(int i =0;i<allowed_paths.size();i++){
								if(paths[0] == allowed_paths[i]){
									check1++;
								}
							}
							if(check1 == 0 ){
								FILE *a = fopen(path.c_str(),"rb");
								char * b = (char*)malloc(7);
								fread(b,7,sizeof(char),a);
								int conf = 0; 
								for(int i =0 ;i<7;i++){
									if(b[i] == ELF64_HEADER[i]){
										conf++;
									}
								}
								if(conf == 0){
									check1++;
								}
								else{
									check1--;
								}
							}
							if(check1 <= 0 ){
								printf("\n[ERROR] unsafe read %s .",path.c_str());
								rg.orig_rax = -1;
								rg.rax = -1;
								ptrace(PTRACE_SETREGS, pid, 0, &rg);
								ptrace(PTRACE_KILL, pid, 0, 0);
							}
					}

					
				}
	
				
				if(eax == SYS_EXECVE){
					//he can only execute code, that is in ,bin /etc lib , but not anywhere else!!
					if(rg.rdi >0 ){
				
						char* r = read_reg_string(rg.rdi,pid);
						vector<string> path = split1(r,"/");
						int bob =0; 
						for(int i =0 ;i<allowed_paths.size();i++){
							if(path[0] == allowed_paths[i]){
								bob++;
							}
						}
						if(bob <= 0 ){
							printf("\n%s error, unsafe exec call initiated  %s .\n",ERROR,r);
							rg.orig_rax = -1;
							rg.rax = -1;
							ptrace(PTRACE_SETREGS, pid, 0, &rg);
							ptrace(PTRACE_KILL, pid, 0, 0);
						}
						
					}

				}
	
				ptrace(PTRACE_SYSCALL,pid,0,0);
				waitpid(pid,&stat,0);

			}
		}

};

int main(int argc, char *argv[] ){

	if(argc < 3 ){
		printf("\n'DamnBox' -  basic x86_64 sandboxing utility\n\tplease specify filename to track with DamnBox:\n\t\t argv[1] - filename, argv[2] - debug (1 or 0)\n\n*** please do not take this tool seriously. it's crap. ***\n\n");
		exit(1);
	}
	char * res = argv[1];
	char *d = argv[2];
	int deb = atoi(d);
	debug = deb;

	DamnBox *box = new DamnBox();

	pid_t pid = fork();
	if(pid == 0){
		personality(ADDR_NO_RANDOMIZE);
		ptrace(PTRACE_TRACEME,0,0,NULL);
		string g = res ;
		execl(("./"+g).c_str(),g.c_str(),NULL);

	}
	else{
		box->trace_process(pid);
	}

}

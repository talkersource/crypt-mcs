/**************************************************************************/
/*                     Main code file for Crypt v5.0                      */
/**************** (Was) Code file for NUTS version 3.2.1 ******************/

/**************************************************************************

This version released: September, 1997

This is the Crypt talker system v5.0 based on Nuts v3.2.1 by Neil Robertson, 
as modified by Bryan McPhail, see the files README & COPYRIGHT for further 
information.

 This software is provided as is. It is not intended as any sort of bullet
 proof system for commercial operation (though you may use it to set up a 
 pay-to-use system, just don't attempt to sell the code itself) and I accept 
 no liability for any problems that may arise from you using it. Since this is 
 freeware (NOT public domain , I have not relinquished the copyright) you may 
 distribute it as you see fit and you may alter the code to suit your needs.

Send mail about this package to either of these addresses (listed in order
of preference):

  mish@tendril.force9.net
  mish@mudhole.spodnet.uk.com
  bmcphail@cs.strath.ac.uk
  crypt@churchnet2.ucsm.ac.uk

The webpage for this package is at: http://www.tendril.force9.co.uk/crypt/

At the time of writing the Crypt runs at: churchnet2.ucsm.ac.uk 3000
Webpage: http://churchnet2.ucsm.ac.uk/~crypt

*****************************************************************************/

/* Unix or Windows compile option is defined here */
#include "platform.h"

/* General include files */
#include <stdio.h>  
#include <time.h>
#include <fcntl.h>
#include <setjmp.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

/* Windows includes */
#ifdef WIN_NT
#include <winsock.h>
#include <stdlib.h>
#include <winnt.h>
#include <process.h>
#else
/* Unix includes */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#ifdef _AIX
#include <sys/select.h>
#endif
#endif

#ifdef UFC_CRYPT
#include "ufc.c"
#endif

#include "cryptv5.h"

main(argc,argv)
int argc;
char *argv[];
{
fd_set readmask;
int i,len,ret;
char inpstr[ARR_SIZE];
UR_OBJECT user,next;

#ifdef WIN_NT
WSADATA WsaData;
DWORD dwThreadId, dwThrdParam = 1;
DWORD alarm_thread(LPDWORD lpdwParam);
OSVERSIONINFO myinfo;
#else
struct utsname uname_info;
#endif

strcpy(progname,argv[0]);
if (argc<2) strcpy(confile,CONFIGFILE);
else strcpy(confile,argv[1]);

/* Startup */
write_syslog("\n*** SERVER BOOTING ***\n",0);
printf("\n*** Crypt %s server booting ***\n\n",VERSION);
init_globals();

/* Setup windows sockets library */
#ifdef WIN_NT
sprintf(inpstr,"Crypt Talker %s - Win32 Version",VERSION);
SetConsoleTitle(inpstr);

if (WSAStartup(MAKEWORD(1, 1), &WsaData))
  boot_exit(4);
#endif

set_date_time();
init_signals();
load_and_parse_config();
init_sockets();
check_messages(1);

/* Run in background automatically. */
#ifndef WIN_NT
switch(fork()) {
 case -1: boot_exit(11);  /* fork failure */
 case  0: break;  /* child continues */
 default: sleep(1); exit(0);  /* parent dies */
 }

/* Get operating system version */
uname(&uname_info);
strcpy(myos,uname_info.sysname);
strcat(myos," ");
strcat(myos,uname_info.release);

/* Set up interrupts */
reset_alarm();

#else

/* Start timer thread */
hThread = CreateThread(
	NULL, /* no security attributes */
	0,    /* use default stack size */
	(LPTHREAD_START_ROUTINE) alarm_thread, /* thread function */
	&dwThrdParam, /* argument to thread function   */
	0,            /* use default creation flags    */
	&dwThreadId); /* returns the thread identifier */

/* Check the return value for success. */
if (hThread == NULL)
 boot_exit(7);

/* Get Windows version */
myinfo.dwOSVersionInfoSize=sizeof(OSVERSIONINFO);
GetVersionEx(&myinfo);
sprintf(myos,"Windows v%d.%d",myinfo.dwMajorVersion,myinfo.dwMinorVersion);

#endif

/* Get hostname */
if (gethostname(myhost,80))
  strcpy(myhost,"(Gethostname() failed!)");
#ifndef WIN_NT
if (!getdomainname(text,80)) {
  strcat(myhost,".");
  strcat(myhost,text);
}
#endif

printf("Running on %s at %s\n",myos,myhost);

printf("\n*** Booted with PID %d ***\n\n",getpid());
sprintf(text,"*** ~FRBooted~RS successfully with PID %d on %s, %d %s, %02d:%02d:%02d ***\n\n",getpid(),day[twday],tmday,month[tmonth],thour,tmin,tsec);
write_syslog(text,0);


/**** Main program loop. *****/
setjmp(jmpvar); /* rescue if we crash and crash_action = IGNORE */
while(1) {
  /* set up mask then wait */
  setup_readmask(&readmask);
  ret=select(FD_SETSIZE,&readmask,NULL,NULL,NULL);
#ifdef WIN_NT
  if (ret==SOCKET_ERROR || ret==0) continue;
#else
  if (ret==-1 || ret==0) continue;
#endif
  
  /* check for connection to listen sockets */
  for(i=0;i<2;++i)
    if (FD_ISSET(listen_sock[i],&readmask))
      accept_connection(listen_sock[i],i);
  
  /* Cycle through users. Use a while loop instead of a for because
     user structure may be destructed during loop in which case we
     may lose the user->next link. */
  next=user_first;
  while(next!=NULL) {
    user=next;
    next=user->next; /* store in case user object is destructed */
    
    /* If clone ignore */
    if (user->type!=USER_TYPE)
      continue;
    
    /* see if any data on socket else continue */
    if (!FD_ISSET(user->socket,&readmask))
      continue;
    
    /* see if client (eg, telnet) has closed socket */
    inpstr[0]='\0';
#ifdef WIN_NT
    len=READ_S(user->socket,inpstr,sizeof(inpstr));
    if (!len || len==SOCKET_ERROR) {
#else
      if (!(len=READ_S(user->socket,inpstr,sizeof(inpstr)))) {
#endif
	disconnect_user(user);
	continue;
      }
      
      /* Ignore control codes */
      if ((unsigned char)inpstr[0]>127 || inpstr[0]==10)
	continue;
      
      /* Deal with input chars. If the following if test succeeds we
	 are dealing with a character mode client so call function. */
      if (inpstr[len-1]>=32 || user->buffpos || inpstr[0]==8) {
	if (get_charclient_line(user,inpstr,len))
	  goto GOT_LINE;
	continue;
      }
      else terminate(inpstr);
      
    GOT_LINE:

      no_prompt=0;
      com_num=-1;
      force_listen=0;
      destructed=0;
      user->buff[0]='\0';
      user->buffpos=0;
      user->last_input=time(0);
      if (user->login) {
	login(user,inpstr);  continue;
      }
      clear_words();
      if (user->afk) {
	write_user(user,"You are no longer AFK.\n");
	if (user->vis) {
	  sprintf(text,"%s comes back from being ~FGAFK~RS.\n",user->name);
	  write_room_except(user->room,text,user);
	}
	user->afk=0;
      }
      if (!(word_count=wordfind(inpstr))) {
	if (misc_ops(user,inpstr))
	  continue;
	
	prompt(user);
	continue;
      }
      if (misc_ops(user,inpstr))
	continue;
      com_num=-1;
      
      if (user->command_mode || strchr(".;:!<>,-#\"",inpstr[0]))
	exec_com(user,inpstr);
      else say(user,inpstr);
      
      if (!destructed)
	prompt(user);
    }
  } /* end while */
}


/************ MAIN LOOP FUNCTIONS ************/

/*** Set up readmask for select ***/
setup_readmask(mask)
fd_set *mask;
{
UR_OBJECT user;
int i;

FD_ZERO(mask);

/* Listen sockets */
for(i=0;i<2;++i) FD_SET(listen_sock[i],mask);

/* User sockets */
for (user=user_first;user!=NULL;user=user->next)
  if (user->type==USER_TYPE) FD_SET(user->socket,mask);

}


/*** Accept incoming connections on listen sockets ***/
accept_connection(lsock,num)
int lsock,num;
{
UR_OBJECT user;
char *get_ip_address(),site[80];
struct sockaddr_in acc_addr;
int accept_sock,size;

size=sizeof(struct sockaddr_in);
accept_sock=accept(lsock,(struct sockaddr *)&acc_addr,&size);
strcpy(site,get_ip_address(acc_addr));

/* You can hardcode banned sites in at this point, just compare the
site to the banned site and CLOSE(accept_socket) */

/* Check for a TOTAL site ban... */
if (site_banned(site) && !num) { /* Allow banned logins on archport */
  write_sock(accept_sock,"\n\rLogins from your site are banned.\n\n\r");
  CLOSE(accept_sock);
  sprintf(text,"Attempted login from ~FRbanned~RS site %s.\n",site);
  write_syslog(text,1);
  sprintf(text,"~OLSYSTEM: ~RSAttempted login from ~FRbanned~RS site %s\n",site);
  write_room(NULL,text);
  return;
}

more(NULL,accept_sock,MOTD1); /* send pre-login message */
if (num_of_users+num_of_logins>=max_users && !num) {
  write_sock(accept_sock,"\n\rSorry, the talker is full at the moment.\n\n\r");
  CLOSE(accept_sock);
  sprintf(text,"~OLSYSTEM: ~RSLogin for user failed due to talker being full.\n");
  write_wiz(ARCH,text,NULL);
  return;
}
if ((user=create_user())==NULL) {
  sprintf(text,"\n\r%s: unable to create session.\n\n\r",syserror);
  write_sock(accept_sock,text);
  CLOSE(accept_sock);
  return;
}
user->socket=accept_sock;
user->login=1;
user->last_input=time(0);
if (!num) user->port=port[0];
else {
  user->port=port[1];
  write_user(user,"*** Archport login ***\n\n");
}
strcpy(user->site,site);

/* Get the local port number & network address for user */
strcpy(user->ip_num,(char *)inet_ntoa(acc_addr.sin_addr));
user->site_port=(int)ntohs(acc_addr.sin_port);
user->auth_addr=acc_addr.sin_addr.s_addr;

echo_on(user);
write_user(user,"Enter your name: ");
num_of_logins++;
}


/*** Get the name of a site from the ip address ***/
get_ip_text(user,input)
UR_OBJECT user;
char *input;
{
FILE *fp;
char tmp[83],*tok,class,new_text[20],input2[20];
int d;

strcpy(input2,input);

/* Get class of IP Address */
tok=strtok(input2,".");
d=atoi(tok);

if (d>191)
  class='C';
else
  if (d>127)
    class='B';
	else
    class='A';

switch (class) {
 case 'A': sprintf(tmp,"%s/%s",DATAFILES, WHERE_FILE_A); break;
 case 'B': sprintf(tmp,"%s/%s",DATAFILES, WHERE_FILE_B); break;
 case 'C': sprintf(tmp,"%s/%s",DATAFILES, WHERE_FILE_C); break;  
}

if (!(fp=fopen(tmp,"r"))) {
  strcpy(user->ip_name, "IP datafile missing!\n");
  return;
}

strcpy(new_text,tok);
strcat(new_text,".");
if (class=='B' || class=='C') {
  tok=strtok(NULL,".");
  strcat(new_text,tok);
  strcat(new_text,".");
}
if (class=='C') {
  tok=strtok(NULL,".");
  strcat(new_text,tok);
  strcat(new_text,".");
}

while (!feof(fp)) {
  fgets(tmp,81,fp);
  
  if (!isdigit(tmp[0]))
    continue;
  
  if (!strncmp(new_text,tmp,strlen(new_text))) {
    fgets(tmp,81,fp);
    strcpy(user->ip_name, tmp);
    fclose(fp);
    return;
  }
}

strcpy(user->ip_name, "Sorry, unknown location!\n");
fclose(fp);

/* Mark unknown locations to syslog */
sprintf(text,"~FRUnknown site~RS %s (%s) (~FG%s~RS)\n", user->site,user->ip_num,user->name);
write_syslog(text,1);
}


/*** Get net address of accepted connection ***/
char *get_ip_address(acc_addr)
struct sockaddr_in acc_addr;
{
static char site[80];
unsigned int addr;
struct hostent *host;

strcpy(site,(char *)inet_ntoa(acc_addr.sin_addr)); /* get number addr */
addr=inet_addr(site);
if ((host=gethostbyaddr((char *)&addr,4,AF_INET))!=NULL)
  strcpy(site,host->h_name); /* copy name addr. */
strtolower(site);
return site;
}


/*** See if users site is banned ***/
site_banned(site)
char *site;
{
FILE *fp;
char line[82],filename[80];

sprintf(filename,"%s/%s",DATAFILES,SITEBAN);
if (!(fp=fopen(filename,"r"))) return 0;
fscanf(fp,"%s",line);
while(!feof(fp)) {
  if (strstr(site,line)) {  fclose(fp);  return 1;  }
	fscanf(fp,"%s",line);
}
fclose(fp);
return 0;
}


/*** See if users site is banned ***/
partial_site_banned(site)
char *site;
{
FILE *fp;
char line[82],filename[80];

sprintf(filename,"%s/%s",DATAFILES,PARTIAL_SITEBAN);
if (!(fp=fopen(filename,"r"))) return 0;
fscanf(fp,"%s",line);
while(!feof(fp)) {
  if (strstr(site,line)) {  fclose(fp);  return 1;  }
	fscanf(fp,"%s",line);
}
fclose(fp);
return 0;
}


/*** See if user is banned ***/
user_banned(name)
char *name;
{
FILE *fp;
char line[82],filename[80];

sprintf(filename,"%s/%s",DATAFILES,USERBAN);
if (!(fp=fopen(filename,"r"))) return 0;
fscanf(fp,"%s",line);
while(!feof(fp)) {
  if (!strcmp(line,name)) {  fclose(fp);  return 1;  }
  fscanf(fp,"%s",line);
}
fclose(fp);
return 0;
}


/*** Attempt to get '\n' terminated line of input from a character
  mode client else store data read so far in user buffer. ***/
get_charclient_line(user,inpstr,len)
UR_OBJECT user;
char *inpstr;
int len;
{
int l;
char *lf="\r";

for(l=0;l<len;++l) {
  /* see if delete entered */
  if (inpstr[l]==8 || inpstr[l]==127) {
    if (user->buffpos) {
      user->buffpos--;
      if (user->charmode_echo) write_user(user,"\b \b");
    }
    continue;
  }
    
  user->buff[user->buffpos]=inpstr[l];
  
  /* See if end of line */
  if (inpstr[l]<32 || user->buffpos+3==ARR_SIZE) {
    WRITE_S(user->socket,lf,1);
    terminate(user->buff);
    strcpy(inpstr,user->buff);
    if (user->charmode_echo) write_user(user,"\n\r");
    return 1;
  }
  user->buffpos++;
}

if (user->charmode_echo && (user->login!=2 || password_echo))
  WRITE_S(user->socket,inpstr,len);

return 0;
}


/*** Put string terminate char. at first char < 32 || > 126  ***/
terminate(str)
char *str;
{
int i;

for (i=0;i<ARR_SIZE;++i)
  if ((*(str+i)<32) || (*(str+i)>126)) {  *(str+i)=0;  return;  }

str[i-1]=0;
}


/*** Get words from sentence. This function prevents the words in the
  sentence from writing off the end of a word array element. This is
  difficult to do with sscanf() hence I use this function instead. ***/
wordfind(inpstr)
char *inpstr;
{
int wn,wpos;

wn=0; wpos=0;
do {
  while(*inpstr<33) if (!*inpstr++) return wn;
  while(*inpstr>32 && wpos<WORD_LEN-1) {
    word[wn][wpos]=*inpstr++;  wpos++;
  }
  word[wn][wpos]='\0';
  wn++;  wpos=0;
} while (wn<MAX_WORDS);
return wn-1;
}

/* Copies the first word of a string into a buffer - used by > shortcut */
namecpy(dest,src)
char *dest;
char *src;
{
int i=0;

while (src[i]!='\0' && src[i]!=' ') {
  dest[i]=src[i];
  i++;
  if (i==WORD_LEN-2)
    break;
}

dest[i]='\0';
}


/*** clear word array etc. ***/
clear_words()
{
int w;
for(w=0;w<MAX_WORDS;++w) word[w][0]='\0';
word_count=0;
}


/************ PARSE CONFIG FILE **************/

load_and_parse_config()
{
FILE *fp;
char line[81]; /* Should be long enough */
char c,filename[80];
int i,section_in,got_init,got_rooms;
RM_OBJECT rm1,rm2;

section_in=0;
got_init=0;
got_rooms=0;

sprintf(filename,"%s/%s",DATAFILES,confile);
printf("Parsing config file \"%s\"...\n",filename);
if (!(fp=fopen(filename,"r"))) {
  perror("NUTS: Can't open config file");  boot_exit(1);
}
/* Main reading loop */
config_line=0;
fgets(line,81,fp);
while(!feof(fp)) {
  config_line++;
  for(i=0;i<8;++i) wrd[i][0]='\0';
  sscanf(line,"%s %s %s %s %s %s %s %s",wrd[0],wrd[1],wrd[2],wrd[3],wrd[4],wrd[5],wrd[6],wrd[7]);
  if (wrd[0][0]=='#' || wrd[0][0]=='\0') {
    fgets(line,100,fp);  continue;
  }
  /* See if new section */
  if (wrd[0][strlen(wrd[0])-1]==':') {
    if (!strcmp(wrd[0],"INIT:")) section_in=1;
    else if (!strcmp(wrd[0],"ROOMS:")) section_in=2; 
    else {
      fprintf(stderr,"NUTS: Unknown section header on line %d.\n",config_line);
      fclose(fp);  boot_exit(1);
    }
  }
  switch(section_in) {
  case 1: parse_init_section();  got_init=1;  break;
  case 2: parse_rooms_section(); got_rooms=1; break;
  default:
    fprintf(stderr,"NUTS: Section header expected on line %d.\n",config_line);
    boot_exit(1);
  }
  fgets(line,100,fp);
}
fclose(fp);

/* See if required sections were present and if required parameters were set. 
 */
if (!got_init) {
  fprintf(stderr,"NUTS: INIT section missing from config file.\n");
  boot_exit(1);
}
if (!got_rooms) {
  fprintf(stderr,"NUTS: ROOMS section missing from config file.\n");
  boot_exit(1);
}
if (!port[0]) {
  fprintf(stderr,"NUTS: Main port number not set in config file.\n");
  boot_exit(1);
}
if (!port[1]) {
  fprintf(stderr,"NUTS: Wiz port number not set in config file.\n");
  boot_exit(1);
}
if (port[0]==port[1]) {
  fprintf(stderr,"NUTS: Port numbers must be unique.\n");
  boot_exit(1);
}
if (room_first==NULL) {
  fprintf(stderr,"NUTS: No rooms configured in config file.\n");
  boot_exit(1);
}

/* Parsing done, now check data is valid. Check room stuff first. */
for(rm1=room_first;rm1!=NULL;rm1=rm1->next) {
  for(i=0;i<MAX_LINKS;++i) {
    if (!rm1->link_label[i][0]) break;
    for(rm2=room_first;rm2!=NULL;rm2=rm2->next) {
      if (rm1==rm2) continue;
      if (!strcmp(rm1->link_label[i],rm2->label)) {
	rm1->link[i]=rm2;  break;
      }
    }
    if (rm1->link[i]==NULL) {
      fprintf(stderr,"NUTS: Room %s has undefined link label '%s'.\n",rm1->name,rm1->link_label[i]);
      boot_exit(1);
    }
  }
}


/*** Load room descriptions ***/
for(rm1=room_first;rm1!=NULL;rm1=rm1->next) {
  sprintf(filename,"%s/%s.R",DATAFILES,rm1->name);
  if (!(fp=fopen(filename,"r"))) {
    fprintf(stderr,"NUTS: Can't open description file for room %s.\n",rm1->name);
    sprintf(text,"Couldn't open description file for room %s.\n",rm1->name);
    write_syslog(text,1);
    continue;
  }
  i=0;
  c=getc(fp);
  while(!feof(fp)) {
    if (i==ROOM_DESC_LEN) {
      fprintf(stderr,"NUTS: Description too long for room %s.\n",rm1->name);
      sprintf(text,"Description too long for room %s.\n",rm1->name);
      write_syslog(text,1);
      break;
    }
    rm1->desc[i]=c;  
    c=getc(fp);  ++i;
  }
  rm1->desc[i]='\0';
  fclose(fp);
}

/* Load atmospherics details.... */
sprintf(filename,"%s/%s",DATAFILES,ATMOS_FILE);
if (fp=fopen(filename,"r")) {
  fscanf(fp, "%s\n", text);
  atmos_no=atoi(text);
  printf("Loading atmospherics - %d lines.\n",atmos_no);
  if (!atmos_no)
    return;
  
  if (atmos_no>MAX_NO_OF_ATMOS) {
    fprintf(stderr,"NUTS: Too many atmospheric lines found - allocate more memory in the .h file\n");
    exit(1);
  }
  
  for (i=0; i<atmos_no; i++) {
    fgets(line,81,fp);
    strcpy(atmos_array[i], line);
  }
  fclose(fp);
}
else
  fprintf(stderr,"NUTS: Cannot open atmospherics file.\n");
}



/*** Parse init section ***/
parse_init_section()
{
static int in_section=0;
int op,val;
char *options[]={ 
"mainport","wizport","linkport","logging","minlogin_level","mesg_life","wizport_level","prompt_def","gatecrash_level","min_private","ignore_mp_level","mesg_check_time","rem_user_min", "rem_user_max","verification","max_users","heartbeat","login_idle_time","user_idle_time","password_echo","ignore_sigterm","auto_connect","max_clones","ban_swearing","crash_action","colour_def","time_out_afks","allow_caps_in_name","atmospherics","backup_check_time","spod_check_time","web_page","save_newbies","ewtoo_default","autopromote","userweb","backups","*"
};

if (!strcmp(wrd[0],"INIT:")) {
  if (++in_section>1) {
    fprintf(stderr,"NUTS: Unexpected INIT section header on line %d.\n",config_line);
    boot_exit(1);
  }
  return;
}
op=0;
while(strcmp(options[op],wrd[0])) {
  if (options[op][0]=='*') {
    fprintf(stderr,"NUTS: Unknown INIT option on line %d.\n",config_line);
    boot_exit(1);
  }
  ++op;
}
if (!wrd[1][0]) {
  fprintf(stderr,"NUTS: Required parameter missing on line %d.\n",config_line);
  boot_exit(1);
}
if (wrd[2][0] && wrd[2][0]!='#') {
  fprintf(stderr,"NUTS: Unexpected word following init parameter on line %d.\n",config_line);
  boot_exit(1);
}
val=atoi(wrd[1]);
switch(op) {
 case 0: /* main port */
 case 1:
  if ((port[op]=val)<1 || val>65535) {
    fprintf(stderr,"NUTS: Illegal port number on line %d.\n",config_line);
    boot_exit(1);
	}
  return;
  
 case 3:
  if ((system_logging=yn_check(wrd[1]))==-1) {
    fprintf(stderr,"NUTS: System_logging must be YES or NO on line %d.\n",config_line);
    boot_exit(1);
  }
  return;
  
 case 4:
  if ((minlogin_level=get_level(wrd[1]))==-1) {
    if (strcmp(wrd[1],"NONE")) {
      fprintf(stderr,"NUTS: Unknown level specifier on line %d.\n",config_line);
      boot_exit(1);	
    }
    minlogin_level=-1;
  }
  return;
  
 case 5:  /* message lifetime */
  if ((mesg_life=val)<1) {
    fprintf(stderr,"NUTS: Illegal message lifetime on line %d.\n",config_line);
    boot_exit(1);
	}
  return;
  
 case 6: /* wizport_level */
  if ((wizport_level=get_level(wrd[1]))==-1) {
    fprintf(stderr,"NUTS: Unknown level specifier on line %d.\n",config_line);
    boot_exit(1);	
  }
  return;
  
 case 7: /* prompt defaults - changed.. */
  prompt_def=val;
  if (val<0 || val>PROMPT_TYPES) {
    fprintf(stderr,"NUTS: Invalid prompt type on line %d.\n",config_line);
    boot_exit(1);
  }
  return;
  
 case 8: /* gatecrash level */
  if ((gatecrash_level=get_level(wrd[1]))==-1) {
    fprintf(stderr,"NUTS: Unknown level specifier on line %d.\n",config_line);
    boot_exit(1);	
  }
  return;

 case 9:
  if (val<1) {
    fprintf(stderr,"NUTS: Number too low on line %d.\n",config_line);
    boot_exit(1);
  }
  min_private_users=val;
  return;
  
 case 10:
  if ((ignore_mp_level=get_level(wrd[1]))==-1) {
    fprintf(stderr,"NUTS: Unknown level specifier on line %d.\n",config_line);
    boot_exit(1);	
  }  return;
  
 case 11: return; 
 case 12: return;
 case 13: return;
  
 case 14: /* mesg_check_time */
  if (wrd[1][2]!=':'
      || strlen(wrd[1])>5
      || !isdigit(wrd[1][0]) 
      || !isdigit(wrd[1][1])
      || !isdigit(wrd[1][3]) 
      || !isdigit(wrd[1][4])) {
		fprintf(stderr,"NUTS: Invalid time on line %d.\n",config_line);
    boot_exit(1);
  }
  wrd[1][2]=' ';
  sscanf(wrd[1],"%d %d",&mesg_check_hour,&mesg_check_min);
  if (mesg_check_hour>23 || mesg_check_min>59) {
    fprintf(stderr,"NUTS: Invalid time on line %d.\n",config_line);
    boot_exit(1);	
	}
  return;
  
 case 15:
  if ((max_users=val)<1) {
    fprintf(stderr,"NUTS: Invalid value for max_users on line %d.\n",config_line);
    boot_exit(1);
  }
  return;
  
 case 16:
  if ((heartbeat=val)<1) {
    fprintf(stderr,"NUTS: Invalid value for heartbeat on line %d.\n",config_line);
    boot_exit(1);
  }
  return;

 case 17:
  if ((login_idle_time=val)<10) {
    fprintf(stderr,"NUTS: Invalid value for login_idle_time on line %d.\n",config_line);
    boot_exit(1);
  }
  return;
  
 case 18:
  if ((user_idle_time=val)<10) {
    fprintf(stderr,"NUTS: Invalid value for user_idle_time on line %d.\n",config_line);
    boot_exit(1);
  }
  return;
  
 case 19: 
  if ((password_echo=yn_check(wrd[1]))==-1) {
    fprintf(stderr,"NUTS: Password_echo must be YES or NO on line %d.\n",config_line);
    boot_exit(1);
  }
  return;
  
 case 20: 
  if ((ignore_sigterm=yn_check(wrd[1]))==-1) {
		fprintf(stderr,"NUTS: Ignore_sigterm must be YES or NO on line %d.\n",config_line);
    boot_exit(1);
  }
  return;
  
 case 21: return;
  
 case 22:
  if ((max_clones=val)<0) {
    fprintf(stderr,"NUTS: Invalid value for max_clones on line %d.\n",config_line);
    boot_exit(1);
  }
  return;
  
 case 23:
  if ((ban_swearing=yn_check(wrd[1]))==-1) {
    fprintf(stderr,"NUTS: Ban_swearing must be YES or NO on line %d.\n",config_line);
    boot_exit(1);
  }
  return;
  
 case 24:
  if (!strcmp(wrd[1],"NONE")) crash_action=0;
  else if (!strcmp(wrd[1],"IGNORE")) crash_action=1;
  else if (!strcmp(wrd[1],"REBOOT")) crash_action=2;
  else {
    fprintf(stderr,"NUTS: Crash_action must be NONE, IGNORE or REBOOT on line %d.\n",config_line);
    boot_exit(1);
  }
  return;
  
 case 25:
  if ((colour_def=onoff_check(wrd[1]))==-1) {
    fprintf(stderr,"NUTS: Colour_def must be ON or OFF on line %d.\n",config_line);
    boot_exit(1);
  }
  return;
  
 case 26:
  if ((time_out_afks=yn_check(wrd[1]))==-1) {
    fprintf(stderr,"NUTS: Time_out_afks must be YES or NO on line %d.\n",config_line);
    boot_exit(1);
  }
  return;
  
 case 27:
  if ((allow_caps_in_name=yn_check(wrd[1]))==-1) {
    fprintf(stderr,"NUTS: Allow_caps_in_name must be YES or NO on line %d.\n",config_line);
    boot_exit(1);
  }
  return;
  
  /* New INIT options here */
 case 28:
  if ((atmos=onoff_check(wrd[1]))==-1) {
    fprintf(stderr,"NUTS: Atmospherics must be ON or OFF on line %d.\n",config_line);
    boot_exit(1);
  }
  return;
  
 case 29: /* backup_check_time */
  if (wrd[1][2]!=':'
      || strlen(wrd[1])>5
      || !isdigit(wrd[1][0]) 
      || !isdigit(wrd[1][1])
      || !isdigit(wrd[1][3]) 
      || !isdigit(wrd[1][4])) {
    fprintf(stderr,"NUTS: Invalid time on line %d.\n",config_line);
    boot_exit(1);
  }
  wrd[1][2]=' ';
  sscanf(wrd[1],"%d %d",&backup_check_hour,&backup_check_min);
  if (backup_check_hour>23 || backup_check_min>59) {
    fprintf(stderr,"NUTS: Invalid time on line %d.\n",config_line);
    boot_exit(1);	
  }
  return;
  
 case 30: /* spod_check_time */
  if (wrd[1][2]!=':'
      || strlen(wrd[1])>5
      || !isdigit(wrd[1][0]) 
      || !isdigit(wrd[1][1])
      || !isdigit(wrd[1][3]) 
      || !isdigit(wrd[1][4])) {
    fprintf(stderr,"NUTS: Invalid time on line %d.\n",config_line);
    boot_exit(1);
  }
  wrd[1][2]=' ';
  sscanf(wrd[1],"%d %d",&spod_check_hour,&spod_check_min);
  if (spod_check_hour>23 || spod_check_min>59) {
		fprintf(stderr,"NUTS: Invalid time on line %d.\n",config_line);
    boot_exit(1);	
  }
  return;
  
 case 31:
  if ((web_page_on=onoff_check(wrd[1]))==-1) {
    fprintf(stderr,"NUTS: Web_page must be ON or OFF on line %d.\n",config_line);
    boot_exit(1);
  }
  return;
  
 case 32:
  if ((save_newbies=yn_check(wrd[1]))==-1) {
    fprintf(stderr,"NUTS: Save_newbies must be YES or NO on line %d.\n",config_line);
    boot_exit(1);
  }
  return;
  
 case 33:
  if ((command_mode_def=yn_check(wrd[1]))==-1) {
    fprintf(stderr,"NUTS: Ewtoo_default must be YES or NO on line %d.\n",config_line);
    boot_exit(1);
  }
  return;
  
 case 34:
  if ((auto_promote=onoff_check(wrd[1]))==-1) {
    fprintf(stderr,"NUTS: Autopromote must be ON or OFF on line %d.\n",config_line);
    boot_exit(1);
  }
  return;

 case 35:
  if ((userweb_on=onoff_check(wrd[1]))==-1) {
    fprintf(stderr,"NUTS: Userweb must be ON or OFF on line %d.\n",config_line);
    boot_exit(1);
  }
  return;

 case 36:
  if ((backup_on=onoff_check(wrd[1]))==-1) {
    fprintf(stderr,"NUTS: Backups must be ON or OFF on line %d.\n",config_line);
    boot_exit(1);
  }
  return;

  }
}



/*** Parse rooms section ***/
parse_rooms_section()
{
static int in_section=0;
int i;
char *ptr1,*ptr2,c;
RM_OBJECT room;

if (!strcmp(wrd[0],"ROOMS:")) {
  if (++in_section>1) {
    fprintf(stderr,"NUTS: Unexpected ROOMS section header on line %d.\n",config_line);
    boot_exit(1);
  }
  return;
}
if (!wrd[2][0]) {
  fprintf(stderr,"NUTS: Required parameter(s) missing on line %d.\n",config_line);
  boot_exit(1);
}
if (strlen(wrd[0])>ROOM_LABEL_LEN) {
  fprintf(stderr,"NUTS: Room label too long on line %d.\n",config_line);
  boot_exit(1);
}
if (strlen(wrd[1])>ROOM_NAME_LEN) {
  fprintf(stderr,"NUTS: Room name too long on line %d.\n",config_line);
  boot_exit(1);
}
/* Check for duplicate label or name */
for(room=room_first;room!=NULL;room=room->next) {
  if (!strcmp(room->label,wrd[0])) {
    fprintf(stderr,"NUTS: Duplicate room label on line %d.\n",config_line);
    boot_exit(1);
  }
  if (!strcmp(room->name,wrd[1])) {
    fprintf(stderr,"NUTS: Duplicate room name on line %d.\n",config_line);
    boot_exit(1);
  }
}
room=create_room();
if (room==NULL)
  boot_exit(1);
strcpy(room->label,wrd[0]);
strcpy(room->name,wrd[1]);

/* Parse internal links bit ie hl,gd,of etc. MUST NOT be any spaces between
   the commas */
i=0;
ptr1=wrd[2];
ptr2=wrd[2];
while(1) {
  while(*ptr2!=',' && *ptr2!='\0') ++ptr2;
  if (*ptr2==',' && *(ptr2+1)=='\0') {
    fprintf(stderr,"NUTS: Missing link label on line %d.\n",config_line);
    boot_exit(1);
  }
  c=*ptr2;  *ptr2='\0';
  if (!strcmp(ptr1,room->label)) {
    fprintf(stderr,"NUTS: Room has a link to itself on line %d.\n",config_line);
    boot_exit(1);
  }
  strcpy(room->link_label[i],ptr1);
  if (c=='\0') break;
  if (++i>=MAX_LINKS) {
    fprintf(stderr,"NUTS: Too many links on line %d.\n",config_line);
    boot_exit(1);
  }
  *ptr2=c;
  ptr1=++ptr2;
}

/* Parse access privs */
if (wrd[3][0]=='#') {  room->access=PUBLIC;  return;  }
if (!wrd[3][0] || !strcmp(wrd[3],"BOTH")) room->access=PUBLIC;
else if (!strcmp(wrd[3],"PUB")) room->access=FIXED_PUBLIC;
else if (!strcmp(wrd[3],"PRIV")) room->access=FIXED_PRIVATE;
else {
  fprintf(stderr,"NUTS: Unknown room access type on line %d.\n",config_line);
  boot_exit(1);
}

if (!wrd[4][0] || wrd[4][0]=='#') return;

boot_exit(1);
}


yn_check(wd)
char *wd;
{
if (!strcmp(wd,"YES")) return 1;
if (!strcmp(wd,"NO")) return 0;
return -1;
}


onoff_check(wd)
char *wd;
{
if (!strcmp(wd,"ON")) return 1;
if (!strcmp(wd,"OFF")) return 0;
return -1;
}


/************ INITIALISATION FUNCTIONS *************/

/*** Initialise globals ***/
init_globals()
{
port[0]=0;
port[1]=0;
max_users=50;
max_clones=1;
ban_swearing=0;
heartbeat=2;
login_idle_time=180;
user_idle_time=300;
time_out_afks=0;
wizport_level=WIZ;
minlogin_level=-1;
mesg_life=1;
no_prompt=0;
num_of_users=0;
num_of_logins=0;
system_logging=1;
password_echo=0;
ignore_sigterm=0;
crash_action=2; /* reboot */
prompt_def=1;
command_mode_def=0;
colour_def=1;
mesg_check_hour=0;
mesg_check_min=0;
allow_caps_in_name=1;
gatecrash_level=GOD+2; /* minimum user level which can enter private rooms */
min_private_users=2; /* minimum num. of users in room before can set to priv */
ignore_mp_level=GOD; /* User level which can ignore the above var. */
user_first=NULL;
user_last=NULL;
room_first=NULL;
room_last=NULL; 
atmos=0; /* Atmos turned off */
atmos_no=0;
backup_check_hour=2;
backup_check_min=0;
spod_check_hour=3;
spod_check_min=0;
web_page_on=1;
save_newbies=0;
auto_promote=1;
backup_on=0;
userweb_on=0;

clear_words();
time(&boot_time);
}


/*** Initialise the signal traps etc ***/
init_signals()
{
void sig_handler();

/* Windows and Unix both support these signals */
signal(SIGILL,SIG_IGN);
signal(SIGSEGV,sig_handler);
signal(SIGTERM,sig_handler);
signal(SIGINT,SIG_IGN);
signal(SIGFPE,SIG_IGN);
signal(SIGABRT,SIG_IGN);

#ifndef WIN_NT
/* Unix only signals */
signal(SIGBUS,sig_handler);
signal(SIGTRAP,SIG_IGN);
signal(SIGIOT,SIG_IGN);
signal(SIGTSTP,SIG_IGN);
signal(SIGCONT,SIG_IGN);
signal(SIGHUP,SIG_IGN);
signal(SIGQUIT,SIG_IGN);
signal(SIGURG,SIG_IGN);
signal(SIGPIPE,SIG_IGN);
signal(SIGTTIN,SIG_IGN);
signal(SIGTTOU,SIG_IGN);
#endif
}

/*** Some signal trapping functions ***/
void sig_handler(sig)
int sig;
{
force_listen=1;

switch(sig) {
 case SIGTERM:
  if (ignore_sigterm) {
    write_syslog("SIGTERM signal received - ignoring.\n",1);
    return;
  }
  write_room(NULL,"\n\n~OLSYSTEM:~FY~LI SIGTERM recieved, initiating shutdown.\n\n");
  talker_shutdown(NULL,"a termination signal ~FY(SIGTERM)~RS",0);
  
 case SIGSEGV:
  switch(crash_action) {
  case 0:
    write_room(NULL,"\n\n\07~OLSYSTEM:~FR~LI PANIC - Segmentation fault, initiating shutdown!\n\n");
    talker_shutdown(NULL,"a segmentation fault ~FY(SIGSEGV)~RS",0);
    
  case 1:
    write_room(NULL,"\n\n\07~OLSYSTEM:~FR~LI WARNING - A segmentation fault has just occured!\n\n");
    write_syslog("WARNING: A segmentation fault occured!\n",1);
    longjmp(jmpvar,0);
    
  case 2:
    write_room(NULL,"\n\n\07~OLSYSTEM:~FR~LI PANIC - Segmentation fault, initiating reboot!\n\n");
    talker_shutdown(NULL,"a segmentation fault ~FY(SIGSEGV)~RS",1);
  }
  
#ifndef WIN_NT
  /* Windows doesn't support sigbus... */
 case SIGBUS:
  switch(crash_action) {
  case 0:
    write_room(NULL,"\n\n\07~OLSYSTEM:~FR~LI PANIC - Bus error, initiating shutdown!\n\n");
    talker_shutdown(NULL,"a bus error ~FY(SIGBUS)~RS",0);
    
  case 1:
    write_room(NULL,"\n\n\07~OLSYSTEM:~FR~LI WARNING - A bus error has just occured!\n\n");
    write_syslog("WARNING: A bus error occured!\n",1);
    longjmp(jmpvar,0);
    
  case 2:
    write_room(NULL,"\n\n\07~OLSYSTEM:~FR~LI PANIC - Bus error, initiating reboot!\n\n");
    talker_shutdown(NULL,"a bus error ~FY(SIGBUS)~RS",0);
  }
#endif
}
}


/*** Initialise sockets on ports ***/
init_sockets()
{
struct sockaddr_in bind_addr;
int i,on,size;

printf("Initialising sockets on ports: %d, %d\n",port[0],port[1]);
size=sizeof(struct sockaddr_in);
bind_addr.sin_family=AF_INET;
bind_addr.sin_addr.s_addr=INADDR_ANY;
for(i=0;i<2;++i) {
  /* create sockets */
#ifdef WIN_NT
  if ((listen_sock[i]=socket(AF_INET,SOCK_STREAM,0))==INVALID_SOCKET) boot_exit(i+2);
#else
  if ((listen_sock[i]=socket(AF_INET,SOCK_STREAM,0))==-1) boot_exit(i+2);
  
  /* allow reboots on port even with TIME_WAITS */
  on=1;
  setsockopt(listen_sock[i],SOL_SOCKET,SO_REUSEADDR,(char *)&on,sizeof(on));
#endif
  
  /* bind sockets and set up listen queues */
  bind_addr.sin_port=htons(port[i]);
#ifdef WIN_NT
  if (bind(listen_sock[i],(struct sockaddr *)&bind_addr,size)!=0) boot_exit(i+5);
  if (listen(listen_sock[i],10)==SOCKET_ERROR) boot_exit(i+8);
#else
  if (bind(listen_sock[i],(struct sockaddr *)&bind_addr,size)==-1) boot_exit(i+5);
  if (listen(listen_sock[i],10)==-1) boot_exit(i+8);
  /* Set to non-blocking , do we need this? not really */
  fcntl(listen_sock[i],F_SETFL,O_NDELAY);
#endif
}
}


/************* WRITE FUNCTIONS ************/

/*** Write a NULL terminated string to a socket ***/
write_sock(sock,str)
int sock;
char *str;
{
WRITE_S(sock,str,strlen(str));
}


/*** Send message to user ***/
write_user(user,str)
UR_OBJECT user;
char *str;
{
int buffpos,sock,i;
char buff[OUT_BUFF_SIZE];
int bold_on=0;

if (user==NULL) return;

buffpos=0;
sock=user->socket;
/* Process string and write to buffer. We use pointers here instead of arrays
   since these are supposedly much faster (though in reality I guess it depends
   on the compiler) which is necessary since this routine is used all the
   time. */
while(*str) {
  if (*str=='\n') {
    if (buffpos>OUT_BUFF_SIZE-6) {
      WRITE_S(sock,buff,buffpos);  buffpos=0;
    }
    /* Reset terminal before every newline */
    if (user->colour) {
      memcpy(buff+buffpos,"\033[0m",4);  buffpos+=4;
    }
    *(buff+buffpos)='\n';  *(buff+buffpos+1)='\r';
    buffpos+=2;  ++str;
  }
  else {
    /* Process colour commands eg ~FR. We have to strip out the commands
       from the string even if user doesnt have colour switched on hence
       the user->colour check isn't done just yet */
    if (*str=='~') {
      if (buffpos>OUT_BUFF_SIZE-6) {
	WRITE_S(sock,buff,buffpos);  buffpos=0;
      }
      ++str;
      for(i=0;i<NUM_COLS;++i) {
	if (!strncmp(str,colcom[i],2)) {
	  if (user->colour) {
	    memcpy(buff+buffpos,colcode[i],strlen(colcode[i]));
	    buffpos+=strlen(colcode[i])-1;
	  }
	  else buffpos--;
	  ++str;
	  goto CONT;
	}
      }
      --str;  *(buff+buffpos)=*str;
    }
    else
      /* Mish - Check for 'old style' bold text */
      if (*str=='^') {
	if (buffpos>OUT_BUFF_SIZE-6) {
	  WRITE_S(sock,buff,buffpos);  buffpos=0;
	}
	
	/* If colour isn't turned on then continue... */
	if (!user->colour) {
	  buffpos--;
	  goto CONT;
	}
	
	if (*str=='^' && !bold_on) {
	  memcpy(buff+buffpos, colcode[1], strlen(colcode[1]));
	  buffpos+=strlen(colcode[1])-1;
	  bold_on=1;
	}
	else if (*str=='^' && bold_on) {
	    memcpy(buff+buffpos, colcode[0], strlen(colcode[0]));
	    buffpos+=strlen(colcode[0])-1;
	    bold_on=0;
	  }
      }
      else
	*(buff+buffpos)=*str;

  CONT:
    ++buffpos;   ++str;
    
  }
  if (buffpos==OUT_BUFF_SIZE) {
    WRITE_S(sock,buff,OUT_BUFF_SIZE);  buffpos=0;
  }
}
if (buffpos) WRITE_S(sock,buff,buffpos);
/* Reset terminal at end of string */
if (user->colour) write_sock(sock,"\033[0m");
}


/*** Write to users of level 'level' and above. The function name is a bit of
	a misnomer I guess. ***/
write_wiz(level,str,user)
int level;
char *str;
UR_OBJECT user;
{
UR_OBJECT u;

for(u=user_first;u!=NULL;u=u->next) {
  if (u!=user && u->level>=level && !u->login && u->type!=CLONE_TYPE)
    write_user(u,str);
}
}


/*** Write to all wizs in a particular room ***/
write_wiz_at_room(level,str,user,room)
int level;
char *str;
UR_OBJECT user;
RM_OBJECT room;
{
UR_OBJECT u;

for(u=user_first;u!=NULL;u=u->next) {
  if (u!=user && u->level>=level && !u->login 
      && u->type!=CLONE_TYPE
      && u->room==room
      && u->room
      ) 
    write_user(u,str);
}
}


/*** Subsid function to below but this one is used the most ***/
write_room(rm,str)
RM_OBJECT rm;
char *str;
{
write_room_except(rm,str,NULL);
}

/*** Write to everyone in room rm except for "user". If rm is NULL write 
     to all rooms. ***/
write_room_except(rm,str,user)
RM_OBJECT rm;
char *str;
UR_OBJECT user;
{
UR_OBJECT u;
char text2[ARR_SIZE];

for(u=user_first;u!=NULL;u=u->next) {
  if (u->login
      || (u->room!=rm && rm!=NULL)
      || (u->ignall && !force_listen)
      || (u->ignshout && (com_num==SHOUT || com_num==SEMOTE))
      || u==user) continue;
  
  if (u->type==CLONE_TYPE) {
    if (u->clone_hear==CLONE_HEAR_NOTHING || u->owner->ignall) continue;
    /* Ignore anything not in clones room, eg shouts, system messages
       and semotes since the clones owner will hear them anyway. */
    if (rm!=u->room || !u->room) continue;
    if (u->clone_hear==CLONE_HEAR_SWEARS) {
      if (!contains_swearing(str)) continue;
    }
    sprintf(text2,"~FT[ %s ]:~RS %s",u->room,str);
    write_user(u->owner,text2);
  }
  else write_user(u,str); 
}
}

/*** Write to everyone in room rm except for "user" and "user2", used for 
  promotion bit ***/
write_room_except2(rm,str,user,user2)
RM_OBJECT rm;
char *str;
UR_OBJECT user, user2;
{
UR_OBJECT u;
char text2[ARR_SIZE];

for(u=user_first;u!=NULL;u=u->next) {
  if (u->login 
      || (u->room!=rm && rm!=NULL)
      || (u->ignall && !force_listen)
      || (u->ignshout && (com_num==SHOUT || com_num==SEMOTE))
      || u==user
      || u==user2) continue;
  if (u->type==CLONE_TYPE) {
    if (u->clone_hear==CLONE_HEAR_NOTHING || u->owner->ignall) continue;
    /* Ignore anything not in clones room, eg shouts, system messages
       and semotes since the clones owner will hear them anyway. */
    if (rm!=u->room || !u->room) continue;
    if (u->clone_hear==CLONE_HEAR_SWEARS) {
      if (!contains_swearing(str)) continue;
    }
    sprintf(text2,"~FT[ %s ]:~RS %s",u->room,str);
    write_user(u->owner,text2);
  }
  else write_user(u,str); 
}
}

/*** Write text figlets & intros ***/
write_text_figlet(fig_text,name,font)
char *fig_text;
char *name;
char *font;
{
UR_OBJECT u;
char fig1[ARR_SIZE];
char fig2[ARR_SIZE];

if (strcmp(font,"standard.flf"))
  sprintf(fig1,"~FRBroadcast figlet from ~OL%s~RS~FR (%s font): ~RS%s\n",name,font,fig_text);
else
  sprintf(fig1,"~FRBroadcast figlet from ~OL%s~RS~FR: ~RS%s\n",name,fig_text);

sprintf(fig2,"~FRBroadcast figlet from ~OL%s~RS~FR:\n",name);
record(room_first,fig1);

for(u=user_first;u!=NULL;u=u->next) {
  if (u->login 
      || (u->ignall && !force_listen)
      || u->type==CLONE_TYPE) continue;
  
  if (u->figlet)
    write_user(u,fig1);
  else
    write_user(u,fig2);
}
}

/*** Write figlet lines to users that want them ***/
write_broadcast_figlet(fig_text)
char *fig_text;
{
UR_OBJECT u;

for(u=user_first;u!=NULL;u=u->next) {
  if (u->login 
      || (u->ignall && !force_listen)
      || u->type==CLONE_TYPE
      || u->figlet) continue;
  
  write_user(u,fig_text); 
}
}


/*** Write a string to system log ***/
write_syslog(str,write_time)
char *str;
int write_time;
{
FILE *fp;

if (!system_logging || !(fp=fopen(SYSLOG,"a"))) return;
if (!write_time) fputs(str,fp);
else fprintf(fp,"%02d/%02d %02d:%02d:%02d: %s",tmday,tmonth+1,thour,tmin,tsec,str);
fclose(fp);
}


/******** LOGIN/LOGOUT FUNCTIONS ********/

/*** Login function - all mostly inline code  ***/
login(user,inpstr)
UR_OBJECT user;
char *inpstr;
{
UR_OBJECT u;
UR_OBJECT get_user_by_full(char *);
int i;
char name[ARR_SIZE],passwd[ARR_SIZE];
char tmp[ARR_SIZE];

name[0]='\0';  passwd[0]='\0';
switch(user->login) {
 case 1:
  sscanf(inpstr,"%s",name);
  if(name[0]<33) {
    write_user(user,"\nEnter your name: ");  return;
  }
  if (!strcmp(name,"quit")) {
    write_user(user,"\n\n*** Abandoning login attempt ***\n\n");
    disconnect_user(user);  return;
  }
  if (!strcmp(name,"who")) {
    who(user,0);
    write_user(user,"\nEnter your name: ");
    return;
  }
  if (!strcmp(name,"version")) {
    sprintf(text,"\nCrypt Talker version %s (Based on Nuts v3.2.1)\n\nEnter your name: ",VERSION);
    write_user(user,text);  return;
	}
  if (strlen(name)<MIN_USER_NAME_LEN) {
    write_user(user,"\nName too short.\n\n");
    attempts(user);  return;
  }
  if (strlen(name)>USER_NAME_LEN) {
    write_user(user,"\nName too long.\n\n");
    attempts(user);  return;
  }
  /* see if only letters in login */
  for (i=0;i<strlen(name);++i) {
    if (!isalpha(name[i])) {
      write_user(user,"\nOnly letters are allowed in a name.\n\n");
      attempts(user);  return;
    }
  }
  if (!allow_caps_in_name) strtolower(name);
  name[0]=toupper(name[0]);
  
  /* Prelogins get shown to arches & above */
  sprintf(text,"~OL[PRE-LOGIN]~RS %s ~FT(%s)\n",name,user->site);
  write_wiz(SHOW_PRE_LEVEL,text,NULL);
  
  if (user_banned(name)) {
    write_user(user,"\nYou are banned from this talker.\n\n");
    disconnect_user(user);
    sprintf(text,"Attempted login by banned user %s.\n",name);
    write_syslog(text,1);
    sprintf(text,"~OLSYSTEM:~RS Login denied for banned user %s\n",name);
    write_room(NULL,text);
    return;
  }
  
  /* Fix to stop users throwing off newbies by logging in under their name */
  u=get_user_by_full(name);
  if (u && u->level==NEW) {
    write_user(user,"\nThat name is currently in use.  Choose another.\n\n");
    attempts(user);
    return;
  }
  
  strcpy(user->name,name);
  /* If user has hung on another login clear that session */
  for(u=user_first;u!=NULL;u=u->next) {
    if (u->login && u!=user && !strcmp(u->name,user->name)) {
      disconnect_user(u);  break;
    }
  }
  if (!load_user_details(user)) {
    if (user->port==port[1]) {
      write_user(user,"\nSorry, new logins cannot be created on this port.\n\n");
      disconnect_user(user);
      return;
    }
    if (minlogin_level>-1) {
      write_user(user,"\nSorry, new logins cannot be created at this time.\n\n");
      sprintf(text,"~OLSYSTEM:~RS %s denied login due to current minlogin level ~FR(%s)\n",user->name,level_name[minlogin_level]);
      write_room(NULL,text);
      disconnect_user(user);
      return;
    }
 
    if (partial_site_banned(user->site)) {
      sprintf(text,"~OLSYSTEM:~RS %s denied login due to partial site ban\n",user->name);
      write_room(NULL,text);
      sprintf(text,"%s/%s",DATAFILES,PARTIALBAN_MOTD);
      more(user,user->socket,text);
      disconnect_user(user);
      return;
    } 

    if (!save_newbies)
      write_user(user,"New user...Ask for promotion to USER if you want your details saved\n");
    else
      write_user(user,"New user...Welcome!\n");
    
  }
  else {
    if (user->port==port[1] && user->level<wizport_level) {
      sprintf(text,"\nSorry, only users of level %s or %s and above can log in on this port.\n\n",new_levels[1][wizport_level], new_levels[2][wizport_level]);
      write_user(user,text);
      disconnect_user(user);
      return;
    }
    if (user->level<minlogin_level) {
      write_user(user,"\nSorry, the talker is locked out to users of your level.\n\n");
      sprintf(text,"~OLSYSTEM:~RS %s denied login due to current minlogin level ~FR(%s)\n",user->name,level_name[minlogin_level]);
      write_room(NULL,text);
      disconnect_user(user);
      return;
    }
  }
  
  if (user->level==NEW)
    write_user(user,"Enter a password for yourself: ");
  else
    write_user(user,"Enter your password: ");
  
  echo_off(user);
  user->login=2;
  return;
  
  /* Deal with password */
 case 2:
  sscanf(inpstr,"%s",passwd);
  if (strlen(passwd)<3) {
    write_user(user,"\n\nPassword too short.\n\n");
    attempts(user);  return;
  }
  if (strlen(passwd)>PASS_LEN) {
    write_user(user,"\n\nPassword too long.\n\n");
    attempts(user);  return;
  }
  
  /* if new user... */
  if (!user->pass[0]) {
    strcpy(user->pass,(char *)crypt(passwd,"NU"));
    write_user(user,"\nPlease confirm password: ");
    user->login=3;
  }
  else { /* Account user - final stage */
    if (!strcmp(user->pass,(char *)crypt(passwd,"NU"))) {
      echo_on(user);
      connect_user(user);
      return;
    }
    write_user(user,"\n\nIncorrect login.\n\n");
    attempts(user);
  }
  return;
  
  /* Confirm password for newusers... */
 case 3:
  sscanf(inpstr,"%s",passwd);
  if (strcmp(user->pass,(char*)crypt(passwd,"NU"))) {
    write_user(user,"\n\nPasswords do not match.\n\n");
    attempts(user);
    return;
  }
  echo_on(user);
  sprintf(text,"\nEnter your sex - (M)ale, (F)emale, (N)either: ");
  write_user(user,text);
  user->login=4;
  
  return;
  
  /* Set gender */
 case 4:
  sscanf(inpstr,"%s",tmp);
  
  tmp[0]=tolower(tmp[0]);
  
  switch (tmp[0]) {
  case 'm': 
  case 'M': user->sex=1; break;
  case 'F':
  case 'f': user->sex=2; break;
  case 'N':
  case 'n': user->sex=0; break;
  default:
    sprintf(text,"Error - Enter M, F or N\nEnter your sex - (M)ale, (F)emale, (N)either: ");
    write_user(user,text);
    return;
  }
  
  user->login=5;
  sprintf(text,"%s/%s",DATAFILES,NEWBIE_MOTD);
  more(user,user->socket,text);
  return;
  
  /* Final stage for newusers */
 case 5:
  echo_on(user);
  strcpy(user->desc,"- a new user");
  strcpy(user->in_phrase,"enters");
  strcpy(user->out_phrase,"goes");
  strcpy(user->login_phrase,"enters the talker");
  strcpy(user->logout_phrase,"leaves the talker");
  strcpy(user->email,"Unknown");
  strcpy(user->www,"None");
  strcpy(user->rank,level_name[0]);
  
  user->last_site[0]='\0';
  user->pre_desc[0]='\0';
  user->level=0;
  user->prompt=prompt_def;
  user->charmode_echo=0;
  user->muzzled=0;
  user->total_login=0;

  save_user_details(user,1);
  sprintf(text,"New user ~FG\"%s\"~RS created.\n",user->name);
  write_syslog(text,1);
  connect_user(user);
}
}


/*** Count up attempts made by user to login ***/
attempts(user)
UR_OBJECT user;
{
user->attempts++;
if (user->attempts==3) {
  write_user(user,"\nMaximum attempts reached.\n\n");
  disconnect_user(user);  return;
}
user->login=1;
user->pass[0]='\0';
write_user(user,"Enter your name: ");
echo_on(user);
}


/*** Load the users stats ***/
load_user_details(user)
UR_OBJECT user;
{
FILE *fp;
char line[81],filename[80];
int temp1,temp2,temp3;

sprintf(filename,"%s/%s.D",USERFILES,user->name);
if (!(fp=fopen(filename,"r"))) return 0;
fscanf(fp,"%s",user->pass); /* password */
fscanf(fp,"%d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d",&temp1,&temp2,&user->last_login_len,&temp3,&user->level,&user->prompt,&user->muzzled,&user->charmode_echo,&user->command_mode,&user->colour,&user->sex,&user->termtype, &user->xterm, &user->figlet, &user->vis_email, &user->examined);

user->last_login=(time_t)temp1;
user->total_login=(time_t)temp2;
user->read_mail=(time_t)temp3;
fscanf(fp,"%s\n",user->last_site);

/* Need to do the rest like this 'cos they may be more than 1 word each */
fgets(line,80,fp);
line[strlen(line)-1]=0;
strcpy(user->pre_desc,line);

if (!strcmp(user->pre_desc,"none"))
  user->pre_desc[0]='\0';

fgets(line,80,fp);
line[strlen(line)-1]=0;
strcpy(user->desc,line);

fgets(line,PHRASE_LEN+2,fp);
line[strlen(line)-1]=0;
strcpy(user->in_phrase,line);

fgets(line,PHRASE_LEN+2,fp);
line[strlen(line)-1]=0;
strcpy(user->out_phrase,line);

fgets(line,LOG_PHRASE_LEN+2,fp);
line[strlen(line)-1]=0;
strcpy(user->login_phrase,line);

fgets(line,LOG_PHRASE_LEN+2,fp);
line[strlen(line)-1]=0;
strcpy(user->logout_phrase,line);

fscanf(fp,"%s\n",user->email);
fscanf(fp,"%s\n",user->www);

fgets(line,38,fp);
line[strlen(line)-1]=0;
strcpy(user->rank,line);

fclose(fp);

return 1;
}


/*** Save a users stats ***/
save_user_details(user,save_current)
UR_OBJECT user;
int save_current;
{
FILE *fp;
char filename[80];

if (!save_newbies) {
  if (user->level==NEW && !(user->login)) {
    sprintf(text,"Newbie %s ~FRnot~RS saved\n", user->name);
    write_syslog(text, 1);
    sprintf(text,"Your details have not been saved!  Ask for promotion to USER next time!");
    write_user(user, text);
    return 0;
  }
  
if (user->level==NEW && user->login)
  return 0;
}

sprintf(filename,"%s/%s.D",USERFILES,user->name);
if (!(fp=fopen(filename,"w"))) {
  sprintf(text,"%s: failed to save your details.\n",syserror);
  write_user(user,text);
  sprintf(text,"SAVE_USER_STATS: Failed to save %s's details.\n",user->name);
  write_syslog(text,1);
  return 0;
}
/* Insurance against any odd values so we don't crash. Shouldn't be needed if
   there are no bugs but it does no harm to have. */
if (user->level<0) user->level=0;
if (user->level>UBERGOTH) user->level=UBERGOTH;
if (user->muzzled<0) user->muzzled=0;
if (user->muzzled>GOD) user->muzzled=GOD;
fprintf(fp,"%s\n",user->pass);
if (save_current)
  fprintf(fp,"%d %d %d ",(int)time(0),(int)user->total_login,(int)(time(0)-user->last_login));
else fprintf(fp,"%d %d %d ",(int)user->last_login,(int)user->total_login,user->last_login_len);

fprintf(fp,"%d %d %d %d %d %d %d %d %d %d %d %d %d\n",(int)user->read_mail,user->level,user->prompt,user->muzzled,user->charmode_echo,user->command_mode,user->colour,user->sex,user->termtype,user->xterm,user->figlet,user->vis_email,user->examined);

if (save_current)
  fprintf(fp,"%s\n",user->site);
else
  fprintf(fp,"%s\n",user->last_site);

if (user->pre_desc[0])
  fprintf(fp,"%s\n",user->pre_desc);
else
  fprintf(fp,"none\n",user->pre_desc);

fprintf(fp,"%s\n",user->desc);
fprintf(fp,"%s\n",user->in_phrase);
fprintf(fp,"%s\n",user->out_phrase);
fprintf(fp,"%s\n",user->login_phrase);
fprintf(fp,"%s\n",user->logout_phrase);
fprintf(fp,"%s\n",user->email);
fprintf(fp,"%s\n",user->www);
fprintf(fp,"%s\n\n",user->rank);
fclose(fp);
return 1;
}


/*** Connect the user to the talker proper ***/
connect_user(user)
UR_OBJECT user;
{
UR_OBJECT u,u2;
char temp[30];

/* Get the ip name here so lookups are only done for users that actually log
   in */
get_ip_text(user, user->ip_num);

/* See if user already connected */
for(u=user_first;u!=NULL;u=u->next) {
  if (user!=u && user->type!=CLONE_TYPE && !strcmp(user->name,u->name)) {
    write_user(user,"\n\nYou are already connected - switching to old session...\n");
    sprintf(text,"%s swapped sessions (%s)\n",user->name,user->site);
    write_user(u,"\n\nAnother login in your name - Switching sessions.\n");
    write_syslog(text,1);
    CLOSE(u->socket);
    u->socket=user->socket;
    
    sprintf(text,"~OL[+]~RS %s %s ~FG(Switched sessions)\n",user->name,user->desc);
    write_room(NULL,text);
    record(room_first,text); /* Record logins to rev buffer */
    num_of_logins--;
    
    strcpy(u->site,user->site);
    strcpy(u->ip_name, user->ip_name);
    u->site_port=user->site_port;
    destruct_user(user);

    look(u);  prompt(u);

    /* Reset the sockets on any clones */
    for(u2=user_first;u2!=NULL;u2=u2->next) {
      if (u2->type==CLONE_TYPE && !strcmp(u->name,u2->name))
	u2->socket=u->socket;
    }
    return;
  }
}

if (user->muzzled)
  sprintf(text,"~OL[+]~RS %s %s ~FR(Muzzled)\n",user->name,user->desc);
else
  sprintf(text,"~OL[+]~RS %s %s\n",user->name,user->desc);
write_room(NULL,text);
record(room_first,text); /* Record logins to rev buffer */
write_user(user,"\n");
more(user,user->socket,MOTD2); /* send post-login message */

sprintf(text,"\nWelcome ~FY%s~RS...  Your level is: ~FG%s\n",user->name,new_levels[user->sex][user->level]);
write_user(user,text);

if (user->last_site[0]) {
  sprintf(temp,"%s",ctime(&user->last_login));
  temp[strlen(temp)-1]=0;
  sprintf(text,"\n~FBYou were last logged in on %s from %s\n",temp,user->last_site);
  write_user(user,text);
}

user->room=room_first;
user->last_login=time(0); /* set to now */
look(user);

if (user->pre_desc[0])
  sprintf(text,"%s~RS %s %s\n", user->pre_desc, user->name, user->login_phrase);
else
  sprintf(text,"%s %s\n", user->name, user->login_phrase);
write_room(user->room, text);
record(user->room,text);

if (has_unread_mail(user)) write_user(user,"\07~OL~LI** YOU HAVE ~FGNEW~RS~LI~OL MAIL **\n");
prompt(user);

sprintf(text,"%s logged in on port %d from %s\n",user->name,user->port,user->site);
write_syslog(text,1);
num_of_users++;
num_of_logins--;
user->login=0;

if (web_page_on)
  web_page();
}


/*** Disconnect user from talker ***/
disconnect_user(user)
UR_OBJECT user;
{
RM_OBJECT rm;

rm=user->room;
if (user->login) {
  CLOSE(user->socket);
  destruct_user(user);
  num_of_logins--;
  return;
}

/* Destroy clones before logout */
destroy_user_clones(user);

save_user_details(user,1);
sprintf(text,"%s logged out.\n",user->name);
write_syslog(text,1);
write_user(user,"\nYou are removed from this reality...  ~LIBut come back soon!\n\n");

/* No logout phrase for auto logouts */
if (user->logout_phrase[0] && !(user->autologout)) {
  if (user->pre_desc[0])
    sprintf(text,"%s~RS %s %s\n", user->pre_desc, user->name, user->logout_phrase);
  else
    sprintf(text,"%s %s\n",user->name,user->logout_phrase);
  write_room_except(user->room,text,user);
  record(user->room,text);
}

CLOSE(user->socket);

if (user->malloc_start!=NULL) free(user->malloc_start);
num_of_users--;

reset_access(rm);
destruct_room(user->name);

destructed=0;

switch (user->autologout) {
 case 0:
  sprintf(text,"~OL[-]~RS %s %s\n",user->name,user->desc); 
  break;
 case 1:
  sprintf(text,"~OL[-]~RS %s %s~RS ~FR(Automatic Logout)\n",user->name,user->desc); 
  break;
 case 2:
  sprintf(text,"~OL[-]~RS %s %s~RS ~FR(Killed!)\n",user->name,user->desc);
  break;
 case 3:
  sprintf(text,"~OL[-]~RS %s %s~RS ~FR(Tongued!)\n",user->name,user->desc);
  break;
 case 4:
  sprintf(text,"~OL[-]~RS %s %s~RS ~FR(Suicide!!!)\n",user->name,user->desc);
  break;
}

write_room_except(NULL,text,user);
record(room_first,text); /* Record logouts to rev buffer */
destruct_user(user);

if (web_page_on)
  web_page();
}


/*** Web Page Generator ***/
web_page()
{
UR_OBJECT u;
int total=0,mins;
FILE *fp;
fp=fopen(WEB_PAGE_FILE,"w");

if (!fp) {
  write_wiz(GOD,"~OL~FRSYSTEM: ~RSCouldn't open web page file!!\n",NULL);
  write_syslog("~FRSYSTEM:~RS Couldn't open web page file!!\n",1);
  return;
}

/* Set up html stuff..... */
fprintf(fp,"<html><head><title>Users on the Crypt</title>\n<meta http-equiv=refresh content=30></head>\n<body background=b_silk.jpg TEXT=F0F0F0 VLINK=ADFF2F ALINK=F0A0A0 link=77EE22 bgcolor=000011>\n<!--- Automatically generated web page...  by Mish and Werewolf 1996 -->");
fprintf(fp,"\n<center><img src=onlineusers.gif height=39 width=320 alt=\"Online Users\"><p>\n\n<p><h5>Current users as of %s, %d %s, %02d:%02d </h5><p></center>\n\n",day[twday],tmday,month[tmonth],thour,tmin);

fprintf(fp,"<table align=center border=1 width=100%><tr align=center valign=top>\n<th width=20%>Name</th><th width=16%>Level</th><th width=12%>Time On</th><th width=52%>Where</th></tr>\n\n");

for(u=user_first;u!=NULL;u=u->next) {
  if (u->type==CLONE_TYPE) continue;
  mins=(int)(time(0) - u->last_login)/60;
  ++total;
  sprintf(text,"<tr><td>%s</td><td align=left>%s</td><td align=right>%d mins</td><td align=center>%s</td></tr>\n",u->name,new_levels[u->sex][u->level],mins,u->ip_name);
  fprintf(fp,text);
}

sprintf(text,"</table><p>There are a total of <b>%d</b> users.<p><p>",total);
fprintf(fp,text);

fprintf(fp,"<center><img src=bloodbar.gif><p>\n<a href=index.html>Crypt Homepage</a></body></html>\n");

fclose(fp);

/* Make the file readable to browsers... not needed on many systems... */
#ifndef WIN_NT
chmod(WEB_PAGE_FILE, 0755);
#endif
}


/*** Tell telnet not to echo characters - for password entry ***/
echo_off(user)
UR_OBJECT user;
{
char seq[4];

if (password_echo) return;
sprintf(seq,"%c%c%c",255,251,1);
write_user(user,seq);
}


/*** Tell telnet to echo characters ***/
echo_on(user)
UR_OBJECT user;
{
char seq[4];

if (password_echo) return;
sprintf(seq,"%c%c%c",255,252,1);
write_user(user,seq);
}


/************ MISCELLANEOUS FUNCTIONS *************/

/*** Miscellaneous operations from user that are not speech or commands ***/
misc_ops(user,inpstr)
UR_OBJECT user;
char *inpstr;
{
switch(user->misc_op) {
 case 1: 
  if (toupper(inpstr[0])=='Y') talker_shutdown(user,"by user\n",0); 
  user->misc_op=0;  prompt(user);
  return 1;
  
 case 2:
  if (toupper(inpstr[0])=='E'
      || more(user,user->socket,user->page_file)!=1) {
    user->misc_op=0;  user->filepos=0;  user->page_file[0]='\0';
    prompt(user); 
  }
  return 1;
  
 case 3: /* writing on board */
 case 4: /* Writing mail */
 case 5: /* doing profile */
 case 8: /* Writing room desc */
  editor(user,inpstr);  return 1;
  
 case 6: /* Suicide */
  if (toupper(inpstr[0])=='Y') delete_user(user,1);
  else {
    user->misc_op=0;  prompt(user);
  }
  return 1;
  
 case 7:
  if (toupper(inpstr[0])=='Y') talker_shutdown(user,"by user\n",1);
  user->misc_op=0;  prompt(user);
  return 1;
  /* case 8: used for room desc editor */
}
return 0;
}


/*** The editor used for writing profiles, mail and messages on the boards ***/
editor(user,inpstr)
UR_OBJECT user;
char *inpstr;
{
int cnt,line;
char *edprompt="\n~FGSave~RS, ~FYredo~RS or ~FRabort~RS (s/r/a): ";
char *ptr;

if (user->edit_op) {
  switch(toupper(*inpstr)) {
  case 'S':
    switch(user->misc_op) {
    case 3: write_board(user,NULL,1);  break;
    case 4: smail(user,NULL,1);  break;
    case 5: enter_profile(user,1);  break;
    case 8: edit_room(user,1); break;
    }
    editor_done(user);
    return;
    
  case 'R':
    user->edit_op=0;
    user->edit_line=1;
    user->charcnt=0;
    user->malloc_end=user->malloc_start;
    *user->malloc_start='\0';
    sprintf(text,"\nRedo message...\n\n~FY%d>~RS",user->edit_line);
    write_user(user,text);
    return;
    
  case 'A':
    write_user(user,"\nMessage aborted.\n");
    editor_done(user);
    return;
    
  default:
    write_user(user,edprompt);
    return;
  }
}
if (user->malloc_start==NULL) {
  if ((user->malloc_start=(char *)malloc(MAX_LINES*81))==NULL) {
    sprintf(text,"%s: failed to allocate buffer memory.\n",syserror);
    write_user(user,text);
    write_syslog("ERROR: Failed to allocate memory in editor().\n",0);
    user->misc_op=0;
    prompt(user);
    return;
  }
  user->ignall_store=user->ignall;
  user->ignall=1; /* Don't want chat mucking up the edit screen */
  user->edit_line=1;
  user->charcnt=0;
  user->malloc_end=user->malloc_start;
  *user->malloc_start='\0';
  sprintf(text,"~FTMaximum of %d lines, end with a '.' on a line by itself.\n\n~FY1>~RS",MAX_LINES);
  write_user(user,text);
  return;
}

/* Check for empty line */
if (!word_count) {
  if (!user->charcnt) {
    sprintf(text,"~FY%d>~RS",user->edit_line);
    write_user(user,text);
    return;
  }
  *user->malloc_end++='\n';
  if (user->edit_line==MAX_LINES) goto END;
  sprintf(text,"~FY%d>~RS",++user->edit_line);
  write_user(user,text);
  user->charcnt=0;
  return;
}
/* If nothing carried over and a dot is entered then end */
if (!user->charcnt && !strcmp(inpstr,".")) goto END;

line=user->edit_line;
cnt=user->charcnt;

/* loop through input and store in allocated memory */
while(*inpstr) {
  *user->malloc_end++=*inpstr++;
  if (++cnt==80) {  user->edit_line++;  cnt=0;  }
  if (user->edit_line>MAX_LINES 
      || user->malloc_end - user->malloc_start>=MAX_LINES*81) goto END;
}
if (line!=user->edit_line) {
  ptr=(char *)(user->malloc_end-cnt);
  *user->malloc_end='\0';
  sprintf(text,"~FY%d>~RS%s",user->edit_line,ptr);
  write_user(user,text);
  user->charcnt=cnt;
  return;
}
else {
  *user->malloc_end++='\n';
  user->charcnt=0;
}
if (user->edit_line!=MAX_LINES) {
  sprintf(text,"~FY%d>~RS",++user->edit_line);
  write_user(user,text);
  return;
}

/* User has finished his message , prompt for what to do now */
END:
*user->malloc_end='\0';
if (*user->malloc_start) {
  write_user(user,edprompt);
  user->edit_op=1;  return;
}
write_user(user,"\nNo text.\n");
editor_done(user);
}


editor_done(user)
UR_OBJECT user;
{
user->misc_op=0;
user->edit_op=0;
user->edit_line=0;
free(user->malloc_start);
user->malloc_start=NULL;
user->malloc_end=NULL;
user->ignall=user->ignall_store;
prompt(user);
}


/*** Record speech and emotes in the room. It stores 2 lines of speech
     per room. ***/
record(rm,str)
RM_OBJECT rm;
char *str;
{
if (!rm) return;
strncpy(rm->conv_line[rm->cln],str,159);
rm->conv_line[rm->cln][159]='\n';
rm->conv_line[rm->cln][160]='\0';
rm->cln=(rm->cln+1)%CONV_LINES;
}

/*** Records tells and pemotes sent to the user. ***/
record_tell(user,str)
UR_OBJECT user;
char *str;
{
if (!user) return;
strncpy(user->revbuff[user->revline],str,REVIEW_LEN);
user->revbuff[user->revline][REVIEW_LEN]='\n';
user->revbuff[user->revline][REVIEW_LEN+1]='\0';
user->revline=(user->revline+1)%REVTELL_LINES;
}

/*** Set room access back to public if not enough users in room ***/
reset_access(rm)
RM_OBJECT rm;
{
UR_OBJECT u;
int cnt;

if (rm==NULL || rm->access==USER_ROOM || rm->access!=PRIVATE) return; 
cnt=0;
for(u=user_first;u!=NULL;u=u->next) if (u->room==rm) ++cnt;
if (cnt<min_private_users) {
  write_room(rm,"Room access returned to ~FGPUBLIC.\n");
  rm->access=PUBLIC;
  
  /* Reset any invites into the room & clear review buffer */
  for(u=user_first;u!=NULL;u=u->next) {
    if (u->invite_room==rm) u->invite_room=NULL;
  }
  clear_rbuff(rm);
}
}


/*** Exit cos of error during bootup ***/
boot_exit(code)
int code;
{
#ifdef WIN_NT
/* Shutdown winsock before exit */
WSACleanup();
#endif

switch(code) {
 case 1:
  write_syslog("BOOT FAILURE: Error while parsing configuration file.\n",0);
  exit(1);
  
 case 2:
  write_syslog("BOOT FAILURE: Can't open main port listen socket.\n",0);
  perror("NUTS: Can't open main listen socket");
  exit(2);
  
 case 3:
  write_syslog("BOOT FAILURE: Can't open wiz port listen socket.\n",0);
  perror("NUTS: Can't open wiz listen socket");
  exit(3);
  
 case 4:
  write_syslog("BOOT FAILURE: Couldn't set up Winsock.\n",0);
  perror("Crypt: Can't set up Winsock.\n");
  exit(4);

 case 5:
  write_syslog("BOOT FAILURE: Can't bind to main port.\n",0);
  perror("NUTS: Can't bind to main port");
  exit(5);
  
 case 6:
  write_syslog("BOOT FAILURE: Can't bind to wiz port.\n",0);
  perror("NUTS: Can't bind to wiz port");
  exit(6);

 case 7:
  write_syslog("BOOT FAILURE: Couldn't start timer thread.\n",0);
  perror("Crypt: Couldn't start timer thread");
  exit(7);
  
 case 8:
  write_syslog("BOOT FAILURE: Listen error on main port.\n",0);
  perror("NUTS: Listen error on main port");
  exit(8);
  
 case 9:
  write_syslog("BOOT FAILURE: Listen error on wiz port.\n",0);
  perror("NUTS: Listen error on wiz port");
  exit(9);
  
 case 11:
  write_syslog("BOOT FAILURE: Failed to fork.\n",0);
  perror("NUTS: Failed to fork");
  exit(11);
}
}

/*** User prompt ***/
prompt(user)
UR_OBJECT user;
{
int hr,min;

if (no_prompt) return;

if (!user->prompt || user->misc_op) return;
hr=(int)(time(0)-user->last_login)/3600;
min=((int)(time(0)-user->last_login)%3600)/60;

/* Different prompt types */
switch(user->prompt) {
 case 1:
  sprintf(text,"~FM<%02d:%02d, %02d:%02d, ~FY%s~FM",thour,tmin,hr,min,user->name);
  break;
 case 2:
  sprintf(text,"~FM<%02d:%02d, ~FY%s~FM",thour,tmin,user->name);
  break;
 case 3:
  if (user->old_tell[0]) 
    sprintf(text,"~FM<%02d:%02d, ~FY%s~FM",thour,tmin,user->old_tell);
  else
    sprintf(text,"~FM<%02d:%02d, ~FYNo-one~FM",thour,tmin);
}
if (!user->vis)
  strcat(text,", ~FB(Invisible)~FM");
if (user->muzzled)
  strcat(text,", ~FR(Muzzled)~FM");
if (user->command_mode && !user->misc_op)  
  strcat(text,", EW-Too mode>\n");  
else
  strcat(text,">\n");

write_user(user,text);
}



/*** Page a file out to user. Colour commands in files will only work if the
  user!=NULL since if NULL we dont know if his terminal can support colour
  or not.
  Return value 0=cannot find file, 1= found file, 2=found and finished ***/
more(user,sock,filename)
UR_OBJECT user;
int sock;
char *filename;
{
int i,buffpos,num_chars,lines,retval,len;
char buff[OUT_BUFF_SIZE],*str,*fname;
FILE *fp;
int bold_on=0,is_mail=0,is_news=0;

if (!(fp=fopen(filename,"r"))) {
  if (user!=NULL) user->filepos=0;
  return 0;
}

/* The /r method of saving times into board and mail files doesn't work
   in windows so this check is used instead */
if (strlen(filename)>2) {
  fname=filename+strlen(filename)-2;
  if (!strncmp(fname,".B",2))
    is_news=1;
  
  if (!strncmp(fname,".M",2))
    is_mail=1;
}

/* jump to reading posn in file */
if (user!=NULL) fseek(fp,user->filepos,0);

text[0]='\0';
buffpos=0;
num_chars=0;
retval=1;
lines=0;
fgets(text,sizeof(text)-1,fp);

/* Go through file */
while(!feof(fp) && (lines<23 || user==NULL)) {
  
  /* Check for board files... */
  if (is_news) {
    if (!strncmp(text,"PT: ",4)) {
      num_chars+=strlen(text);
      fgets(text,sizeof(text)-1,fp);
      continue;
    }
  }
  
  /* Mail files always start with timestamp so ignore it */
  if (is_mail && user->filepos==0) {
    is_mail=0;
    num_chars+=strlen(text);
    fgets(text,sizeof(text)-1,fp);
    continue;
  }
  
  str=text;
  
  /* Process line from file */
  while(*str) {
    if (*str=='\n') {
      if (buffpos>OUT_BUFF_SIZE-6) {
	WRITE_S(sock,buff,buffpos);  buffpos=0;
      }
      /* Reset terminal before every newline */
      if (user!=NULL && user->colour) {
	memcpy(buff+buffpos,"\033[0m",4);  buffpos+=4;
      }
      *(buff+buffpos)='\n';  *(buff+buffpos+1)='\r';
      buffpos+=2;  ++str;
    }
    else {
      /* Process colour commands in the file */
      if (*str=='~') {
	if (buffpos>OUT_BUFF_SIZE-6) {
	  WRITE_S(sock,buff,buffpos);  buffpos=0;
	}
	++str;
	for(i=0;i<NUM_COLS;++i) {
	  if (!strncmp(str,colcom[i],2)) {
	    if (user!=NULL && user->colour) {
	      memcpy(buffpos+buff,colcode[i],strlen(colcode[i]));
	      buffpos+=strlen(colcode[i])-1;
	    }
	    else buffpos--;
	    ++str;
	    goto CONT;
	  }
	}
	--str;  *(buff+buffpos)=*str;
      }
      else
	/* Mish - Check for 'old style' bold text */
	if (*str=='^') {
	  if (buffpos>OUT_BUFF_SIZE-6) {
	    WRITE_S(sock,buff,buffpos);  buffpos=0;
	  }
	  
	  /* If colour isn't turned on then continue... */
	  if (!user->colour) {
	    buffpos--;
	    goto CONT;
	  }
	  
	  if (*str=='^' && !bold_on) {
	    memcpy(buff+buffpos, colcode[1], strlen(colcode[1]));
	    buffpos+=strlen(colcode[1])-1; 
	    bold_on=1;
	  }
	  else if (*str=='^' && bold_on) { 
	      memcpy(buff+buffpos, colcode[0], strlen(colcode[0]));
	      buffpos+=strlen(colcode[0])-1; 
	      bold_on=0;
	    }
	}
      
	else *(buff+buffpos)=*str;

    CONT:
      ++buffpos;   ++str;
    }
    if (buffpos==OUT_BUFF_SIZE) {
      WRITE_S(sock,buff,OUT_BUFF_SIZE);  buffpos=0;
    }
  }
  len=strlen(text);
  num_chars+=len;
  lines+=len/80+(len<80);
  fgets(text,sizeof(text)-1,fp);
}
if (buffpos && sock!=-1) WRITE_S(sock,buff,buffpos);

/* if user is logging in don't page it */
if (user==NULL) {  fclose(fp);  return 2;  };
if (feof(fp)) {
  user->filepos=0;  no_prompt=0;  retval=2;
}
else  {
  /* store file position and file name */
  user->filepos+=num_chars;
  strcpy(user->page_file,filename);
  write_user(user,"~FB*** ~FTPRESS ~FG<RETURN>~FT FOR MORE, ~FRE<RETURN>~FT TO EXIT ~FB***");
  no_prompt=1;
}
fclose(fp);
return retval;
}


/*** Set global vars. hours,minutes,seconds,date,day,month ***/
set_date_time()
{
struct tm *tm_struct; /* structure is defined in time.h */
time_t tm_num;

/* Set up the structure */
time(&tm_num);
tm_struct=localtime(&tm_num);

/* Get the values */
tday=tm_struct->tm_yday;
tmonth=tm_struct->tm_mon;
tmday=tm_struct->tm_mday;
twday=tm_struct->tm_wday;
thour=tm_struct->tm_hour;
tmin=tm_struct->tm_min;
tsec=tm_struct->tm_sec;
}


/*** Return pos. of second word in inpstr ***/
char *remove_first(inpstr)
char *inpstr;
{
char *pos=inpstr;
while(*pos<33 && *pos) ++pos;
while(*pos>32) ++pos;
while(*pos<33 && *pos) ++pos;
return pos;
}


/*** Returns 1 if string is a positive number ***/
isnumber(str)
char *str;
{
while(*str) if (!isdigit(*str++)) return 0;
return 1;
}


/*** Get user struct pointer from name ***/
UR_OBJECT get_user(name)
char *name;
{
UR_OBJECT u;

name[0]=toupper(name[0]);
for(u=user_first;u!=NULL;u=u->next) {
  if (u->type==CLONE_TYPE || u->login) continue;
  if (!strncmp(u->name,name,strlen(name)))  return u;
}
return NULL;
}


/*** Get user struct pointer from full name (no abbrevs allowed) ***/
UR_OBJECT get_user_by_full(name)
char *name;
{
UR_OBJECT u;

name[0]=toupper(name[0]);
for(u=user_first;u!=NULL;u=u->next) {
  if (u->type==CLONE_TYPE || u->login) continue;
  if (!strcmp(u->name,name))  return u;
}
return NULL;
}


/*** Get room struct pointer from abbreviated name ***/
RM_OBJECT get_room(name)
char *name;
{
RM_OBJECT rm;

for(rm=room_first;rm!=NULL;rm=rm->next)
  if (!strncmp(rm->name,name,strlen(name))) return rm;
return NULL;
}


/*** Return level value based on level name ***/
get_level(name)
char *name;
{
int i;

/* MISH - Now have to check each type of user rank... */

i=0;
while(new_levels[0][i][0]!='*') {
  if (!strcmp(level_name[i],name)) return i;
  ++i;
}
while(new_levels[1][i][0]!='*') {
  if (!strcmp(level_name[i],name)) return i;
  ++i;
}
while(new_levels[2][i][0]!='*') {
  if (!strcmp(level_name[i],name)) return i;
  ++i;
}

return -1;
}


/*** See if user has unread mail, mail file has last read time on its
  first line ***/
has_unread_mail(user)
UR_OBJECT user;
{
FILE *fp;
int tm;
char filename[80];

sprintf(filename,"%s/%s.M",USERMAIL,user->name);
if (!(fp=fopen(filename,"r"))) return 0;
fscanf(fp,"%d",&tm);
fclose(fp);
if (tm>(int)user->read_mail) return 1;
return 0;
}


/*** This is function that sends mail to other users ***/
send_mail(user,to,ptr)
UR_OBJECT user;
char *to,*ptr;
{
FILE *infp,*outfp;
char d,filename[80],line[DNL+1];
char mailbuf[ARR_SIZE*2];

if (!(outfp=fopen("tempfile","w"))) {
  write_user(user,"Error in mail delivery.\n");
  write_syslog("ERROR: Couldn't open tempfile in send_mail().\n",0);
  return;
}

/* Write current time on first line of tempfile */
fprintf(outfp,"%d\n",(int)time(0));
sprintf(filename,"%s/%s.M",USERMAIL,to);
if (infp=fopen(filename,"r")) {
  /* Discard first line of mail file. */
  fgets(line,DNL,infp);
  
  /* Copy rest of file */
  d=getc(infp);
  while(!feof(infp)) {  putc(d,outfp);  d=getc(infp);  }
  fclose(infp);
}

if (user!=NULL)
  fprintf(outfp,"~OLFrom:~RS ~FT%s~RS, %s %d %s, %02d:%02d\n",user->name,day[twday],tmday,month[tmonth],thour,tmin);
else
  fprintf(outfp,"~OLFrom:~RS ~FTMAILER~RS, %s %d %s, %02d:%02d\n",day[twday],tmday,month[tmonth],thour,tmin);

fputs(ptr,outfp);
fputs("\n",outfp);
fclose(outfp);
unlink(filename); /* Bug fix so mail dir can work over symbolic link in solaris */
rename("tempfile",filename);
if (strlen(mailbuf)>64)
  sprintf(mailbuf,"You send mail to ~OL%s~RS:\n%s\n",to,ptr);
else
  sprintf(mailbuf,"You send mail to ~OL%s~RS: %s",to,ptr);
write_user(user,mailbuf);
write_user(get_user(to),"\07~OL~LI** YOU HAVE ~FGNEW~RS~OL~LI MAIL **\n");
}



/*** Convert string to upper case ***/
strtoupper(str)
char *str;
{
while(*str) {  *str=toupper(*str);  str++; }
}


/*** Convert string to lower case ***/
strtolower(str)
char *str;
{
while(*str) {  *str=tolower(*str);  str++; }
}


/*** Clear the review buffer in the room ***/
clear_rbuff(rm)
RM_OBJECT rm;
{
int c;
for(c=0;c<CONV_LINES;++c) rm->conv_line[c][0]='\0';
rm->cln=0;
}



/*** See if string contains any swearing ***/
contains_swearing(str)
char *str;
{
char *s;
int i;

if ((s=(char *)malloc(strlen(str)+1))==NULL) return 0;
strcpy(s,str);
strtoupper(s);
i=0;
while(swear_words[i][0]!='*') {
  if (strstr(s,swear_words[i])) {  free(s);  return 1;  }
  ++i;
}
free(s);
return 0;
}


/*** Count the number of colour commands in a string ***/
colour_com_count(str)
char *str;
{
char *s;
int i,cnt;

s=str;  cnt=0;
while(*s) {
  /* Mish - For old style bold text */
  if (*s=='^') {
    ++cnt;
    ++s;
    continue;
  }
  if (*s=='~') {
    ++s;
    for(i=0;i<NUM_COLS;++i) {
      if (!strncmp(s,colcom[i],2)) {
	cnt=cnt+3;  s++;  continue;
      }
    }
    continue;
  }
  ++s;
}
return cnt;
}


/************ OBJECT FUNCTIONS ************/

/*** Construct user/clone object ***/
UR_OBJECT create_user()
{
UR_OBJECT user;
int i;

if ((user=(UR_OBJECT)malloc(sizeof(struct user_struct)))==NULL) {
  write_syslog("~FRCONSTRUCT: ~RSMemory allocation failure.\n",0);
  write_room(NULL,"~FY~OLSYSTEM:~RS Failed to allocate memory in create_user()");
  return NULL;
}

/* Append object into linked list. */
if (user_first==NULL) { 
  user_first=user;  user->prev=NULL;  user->next=NULL;
}
else {  
  user_last->next=user;  user->next=NULL;  user->prev=user_last;
}
user_last=user;

/* initialise users - general */
user->type=USER_TYPE;
user->name[0]='\0';
user->desc[0]='\0';
user->in_phrase[0]='\0'; 
user->out_phrase[0]='\0';   
user->pass[0]='\0';
user->site[0]='\0';
user->last_site[0]='\0';
user->page_file[0]='\0';
user->mail_to[0]='\0';
user->buff[0]='\0';  
user->buffpos=0;
user->filepos=0;
user->read_mail=time(0);
user->room=NULL;
user->invite_room=NULL;
user->port=0;
user->login=0;
user->socket=-1;
user->attempts=0;
user->command_mode=command_mode_def;
user->level=0;
user->vis=1;
user->ignall=0;
user->ignall_store=0;
user->ignshout=0;
user->igntell=0;
user->muzzled=0;
user->last_input=time(0);
user->last_login=time(0);
user->last_login_len=0;
user->total_login=0;
user->prompt=prompt_def;
user->charmode_echo=0;
user->misc_op=0;
user->edit_op=0;
user->edit_line=0;
user->charcnt=0;
user->warned=0;
user->accreq=0;
user->afk=0;
user->colour=colour_def;
user->clone_hear=CLONE_HEAR_ALL;
user->malloc_start=NULL;
user->malloc_end=NULL;
user->owner=NULL;
user->old_tell[0]='\0';
user->ip_name[0]='\0';
user->tell=0;
user->licked=0;
user->been_licked=0;
user->sex=0; /* An 'it'! */
user->autologout=0;
user->site_port=0;
user->termtype=0; /* Colour xterm */
user->xterm=1; /* Xterm titles on */
user->figlet=0;
user->revline=0;
user->auth_addr=0;
user->vis_email=0;
user->examined=0;
user->email[0]='\0';
user->www[0]='\0';
user->logout_phrase[0]='\0';
user->rank[0]='\0';
user->pre_desc[0]='\0';
user->afk_mesg[0]='\0';
user->ip_num[0]='\0';
for(i=0; i<REVTELL_LINES; ++i) user->revbuff[i][0]='\0';
return user;
}



/*** Destruct a user object. ***/
destruct_user(user)
UR_OBJECT user;
{
/* Remove from linked list */
if (user!=user_first) {
  user->prev->next=user->next;
  if (user!=user_last) user->next->prev=user->prev;
  else { user_last=user->prev; user_last->next=NULL; }
}
else {
  user_first=user->next;
  if (user!=user_last) user_first->prev=NULL;
  else user_last=NULL; 
}
free(user);
destructed=1;
}


/*** Construct room object ***/
RM_OBJECT create_room()
{
RM_OBJECT room;
int i;

if ((room=(RM_OBJECT)malloc(sizeof(struct room_struct)))==NULL) {
  write_syslog("~FRCONSTRUCT: ~RSMemory allocation failure.\n",0);
  write_room(NULL,"~FY~OLSYSTEM:~RS Failed to allocate memory in create_room()");
  return NULL;
}
room->name[0]='\0';
room->label[0]='\0';
room->desc[0]='\0';
room->topic[0]='\0';
room->access=-1;
room->cln=0;
room->mesg_cnt=0;
room->tlock=0;
room->prev=NULL;
room->next=NULL;
for(i=0;i<MAX_LINKS;++i) {
  room->link_label[i][0]='\0';  room->link[i]=NULL;
}
for(i=0;i<CONV_LINES;++i) room->conv_line[i][0]='\0';

/* Add room into linked list */
if (room_first==NULL) { 
  room_first=room;  room->prev=NULL;  room->next=NULL;
}
else {  
  room_last->next=room;  room->next=NULL;  room->prev=room_last;
}
room_last=room;
 
return room;
}


/*** Destruct a room object. ***/
destruct_room(name)
char *name;
{
RM_OBJECT room;
UR_OBJECT u;

/* Find the room to be destroyed */
for(room=room_first;room!=NULL;room=room->next) {
  if (!strncmp(room->name,name,strlen(room->name))) { 

    /* Remove others in this room */
    for(u=user_first;u!=NULL;u=u->next)
      if (u->room==room || !u->room) 
	move_user(u,room_first,1);

    /* Remove from linked list */
    if (room!=room_first) {
      room->prev->next=room->next;
      if (room!=room_last) room->next->prev=room->prev;
      else { room_last=room->prev; room_last->next=NULL; }
    }
    else {
      room_first=room->next;
      if (room!=room_last) room_first->prev=NULL;
      else room_last=NULL; 
    }
    free(room);
    return;
  }
}
}


/*** Destroy all clones belonging to given user ***/
destroy_user_clones(user)
UR_OBJECT user;
{
UR_OBJECT u;

for(u=user_first;u!=NULL;u=u->next) {
  if (u->type==CLONE_TYPE && u->owner==user) {
    sprintf(text,"~FBThe clone of %s shimmers and vanishes.\n",u->name);
    write_room(u->room,text);
    destruct_user(u);
  }
}

}


/************ START OF COMMAND FUNCTIONS AND THEIR SUBSIDS ************/

/*** Deal with user input ***/
exec_com(user,inpstr)
UR_OBJECT user;
char *inpstr;
{
int i,len;
char *comword;

com_num=-1;
if (word[0][0]=='.') comword=(word[0]+1);
else comword=word[0];
if (!comword[0]) {
  write_user(user,"Unknown command.\n");  return;
}

/* Sort out command aliases */
switch(inpstr[0]) {
 case '>':
  if (inpstr[1]=='>') {
    user->tell=1;
    inpstr[1]=' ';
  }
  else {
    user->tell=0;
    if (inpstr[1]!=' ') {
      namecpy(word[1],inpstr+1);
      word_count++;
    }
    else
      inpstr=remove_first(inpstr);
  }
  
  strcpy(word[0],"tell");
  break;
  
 case '<':
  if (inpstr[1]=='<') {
    user->tell=1;
    inpstr[1]=' ';
  }
  else {
    user->tell=0;
    if (inpstr[1]!=' ') {
      namecpy(word[1],inpstr+1);
      word_count++;
    }
    else
      inpstr=remove_first(inpstr);
  }
  
  strcpy(word[0],"pemote");
  break;
  
 case '-':
  if (inpstr[1]!=' ') {
    inpstr++;
    word_count++;
  }
  else
    inpstr=remove_first(inpstr);
  
  strcpy(word[0],"echo");
  break;
  
 case '!':
  if (inpstr[1]!=' ') {
    inpstr++;
    word_count++;
  }
  else
    inpstr=remove_first(inpstr);
  
  strcpy(word[0],"shout");
  break;
  
 case '\"':
  strcpy(word[0],"say");
  inpstr++;
  word_count++;
  break;
  
 case ':':
 case ';':
  strcpy(word[0],"emote");
  break;

 case '#':
  if (inpstr[1]!=' ') {
    inpstr++;
    word_count++;
  }
  else
    inpstr=remove_first(inpstr);
  
  strcpy(word[0],"semote");
  break;

 case ',':
  if (inpstr[1]!=' ') {
    namecpy(word[1],inpstr+1);
    word_count++;
  }
  else
    inpstr=remove_first(inpstr);
  strcpy(word[0],"dsay");
  break;
  
 default:
  inpstr=remove_first(inpstr);
}

i=0;
len=strlen(comword);
while(command[i][0]!='*') {
  if (!strncmp(command[i],comword,len)) {  com_num=i;  break;  }
  ++i;
}

if (user->room!=NULL && (com_num==-1 || com_level[com_num] > user->level)) {
  write_user(user,"Unknown command.\n");  return;
}

/* Main switch */
switch(com_num) {
  /* General user commands */
 case QUIT: disconnect_user(user);  break;
 case LOOK: look(user);  break;  
 case SAY :
   if (word_count<2) {
     write_user(user,"Say what?\n");  return;
   }
   say(user,inpstr);
   break;
 case SHOUT : shout(user,inpstr);  break;
 case TELL  : tell(user,inpstr);   break;
 case EMOTE : emote(user,inpstr);  break;
 case SEMOTE: semote(user,inpstr); break;
 case PEMOTE: pemote(user,inpstr); break;
 case ECHO  : echo(user,inpstr);   break;
 case BCAST  : bcast(user,inpstr);  break;
 case ACCREQ: account_request(user,inpstr);  break;
 case AFK   : afk(user, inpstr); break;
 case CLS:
   for(i=0;i<5;++i) write_user(user,"\n\n\n\n\n\n\n\n\n\n");
   break;
 case SUICIDE : suicide(user);  break;
 case SOS: sos(user); break;
 case MYXTERM : my_xterm(user, inpstr); break;
 case REVTELL: revtell(user); break;  
 case FIGLET: figlet(user,inpstr); break;
 case DSAY: dsay(user,inpstr); break;
 case BEEP: beep(user,inpstr); break;
   
   /* Files */
 case NEWS:
 case MAP:
 case RANKS:
 case FAQ:
 case TALKERS:
 case RULES:
   page_file(user); break;
   
   /* Boards */	  
 case READ  : read_board(user);  break;
 case WRITE : write_board(user,inpstr,0);  break;
 case WIPE  : wipe_board(user);  break;
 case SEARCH: search_boards(user);  break;
   
   /* Info */
 case WHO    : who(user,0);  break;
 case SWHO: swho(user); break;
 case PEOPLE : who(user,1);  break;
 case REVIEW: review(user);  break;
 case HELP  : help(user);  break;
 case STATUS: status(user);  break;
 case EXAMINE : examine(user);  break;
 case WHERE : where(user); break;
   
   /* User info stuff */
 case ENTPRO  : enter_profile(user,0);  break;
 case SETRANK: set_rank(user,inpstr); break;
 case PASSWD  : change_pass(user);  break;
 case PROMPT: toggle_prompt(user);  break;
 case PDESC: set_pre_desc(user,inpstr); break;
 case DESC  : set_desc(user,inpstr);  break;
 case INPHRASE : 
 case OUTPHRASE: 
   set_iophrase(user,inpstr);  break; 
 case LOGIN: set_login(user,inpstr); break;
 case LOGOUT: set_logout(user, inpstr); break;
 case EMAIL: set_email(user); break;
 case VEMAIL: set_vemail(user); break;
 case WWW: set_www(user); break;
 case COLOUR  : toggle_colour(user);  break;
 case IGNFIG: ignore_figlet(user); break;
 case IGNALL: toggle_ignall(user);  break;
 case IGNSHOUT: toggle_ignshout(user);  break;
 case IGNTELL : toggle_igntell(user);  break;
 case EWTOO: ewtoo_mode(user); break;
 case NUTS: nuts_mode(user); break;
 case MODE: toggle_mode(user);  break;
 case SEX : sex(user); break;
 case TERMTYPE: set_term(user); break;
 case VIS     : visibility(user,1);  break;
 case INVIS   : visibility(user,0);  break;
 case CHARECHO : charecho(user);  break;
   
   /* Mail */
 case RMAIL   : rmail(user);  break;
 case SMAIL   : smail(user,inpstr,0);  break;
 case DMAIL   : dmail(user);  break;
 case FROM    : mail_from(user);  break;
   
   /* Room stuff */
 case RMST    : rooms(user);  break;
 case FIX      : change_room_fix(user,1);  break;
 case UNFIX    : change_room_fix(user,0);  break;
 case REVCLR: revclr(user);  break;
 case PUBCOM :
 case PRIVCOM: set_room_access(user);  break;
 case LETMEIN: letmein(user);  break;
 case INVITE : invite(user);   break;
 case TOPIC  : set_topic(user,inpstr);  break;
 case TLOCK: tlock(user); break;
 case JOIN: join(user); break;
 case GO    : go(user);  break;
 case MOVE   : move(user);  break;
 case HOME: home(user); break;
 case EDIT: edit_room(user,0); break;   
 case BOOT: boot(user); break;

   /* Admin stuff */
 case KILL    : kill_user(user);  break;
 case PROMOTE : promote(user);  break;
 case DEMOTE  : demote(user);  break;
 case LISTBANS: listbans(user);  break;
 case BAN     : ban(user);  break;
 case UNBAN   : unban(user);  break;
 case SITE    : site(user);  break;
 case WAKE    : wake(user);  break;
 case WIZSHOUT: wizshout(user,inpstr);  break;
 case MUZZLE  : muzzle(user);  break;
 case UNMUZZLE: unmuzzle(user);  break;
 case VIEWLOG  : viewlog(user); break;
 case THP: thp(user); break;
 case SU: su(user,inpstr); break;
 case AUTH: auth_user(user); break;
 case CLEARLINE: clearline(user);  break;
 case ALLXTERM : all_xterm(inpstr); break;
 case NEWUSER: newuser(user); break;
 case BSX : bsx(user); break;
 case SINFO: sinfo(user,inpstr); break;

   /* Clones stuff */
 case CREATE: create_clone(user);  break;
 case DESTROY: destroy_clone(user);  break;
 case MYCLONES: myclones(user);  break;
 case ALLCLONES: allclones(user);  break;
 case SWITCH: clone_switch(user);  break;
 case CSAY  : clone_say(user,inpstr);  break;
 case CEMOTE: clone_emote(user,inpstr); break;
 case CHEAR : clone_hear(user);  break;
   	
   /* Fun stuff :) */
 case BANNER : banner(user, inpstr); break;
 case SING : sing(user, inpstr); break;
 case THINK : think(user, inpstr); break;
 case LOTTERY : lottery(user); break;
 case FLOWERS : flowers(user, inpstr); break;
 case LICK : lick(user); break;
 case NUMPTY: numpty(user); break;
 case WHORE: whore(user); break;
 case GP: godpidgeon(user,inpstr); break;
 case GPEMOTE: gp_emote(user,inpstr); break;
 case SHARK: shark(user); break;
 case HUG: hug(user); break;
 case HP: hp(user,inpstr); break;
 case POKE: poke(user); break;

   /* System Stuff */
 case SYSTEM : system_details(user);  break;
 case SWBAN : swban(user);  break;
 case ATMOS: atmos_onoff(user); break;
 case BACKUP: do_backup(1); break;
 case DOWEB: do_web(1); break;
 case DELETE_C : delete_user(user,0);  break;
 case REBOOT :
   write_user(user,"\n\07~FR~OL~LI*** WARNING - This will reboot the talker! ***\n\nAre you sure about this (y/n)? ");
   user->misc_op=7;  no_prompt=1;
   break;
 case SHUTDOWN:
   write_user(user,"\n\07~FR~OL~LI*** WARNING - This will shutdown the talker! ***\n\nAre you sure about this (y/n)? ");
   user->misc_op=1;  no_prompt=1;
   break;
 case LOGGING  : logging(user); break;
 case MINLOGIN : minlogin(user);  break;
 case VER:
   sprintf(text,"~FRC~FMr~FGy~FTp~FYt~RS Talker version ~FB%s~RS (Based on Nuts v3.2.1)\n",VERSION);
   write_user(user,text);  break;
 case WEBPAGE: onoffweb_page(); break;
  
 default: write_user(user,"Command not executed in exec_com().\n");
 }
}


/*** Page a file out to the user ***/
page_file(user)
UR_OBJECT user;
{
char filename[80];

switch (com_num) {
 case NEWS: sprintf(filename,"%s/%s",DATAFILES,NEWSFILE); break;
 case MAP: sprintf(filename,"%s/%s",DATAFILES,MAPFILE); break;
 case RANKS: sprintf(filename,"%s/%s",DATAFILES,RANKS_FILE); break;
 case FAQ: sprintf(filename,"%s/%s",DATAFILES,FAQ_FILE); break;
 case TALKERS: sprintf(filename,"%s/%s",DATAFILES,TALKERS_FILE); break;
 case RULES: sprintf(filename,"%s/%s",DATAFILES,RULES_FILE); break;  
}

switch(more(user,user->socket,filename)) {
 case 0: 
  sprintf(text,"Hmmm, '%s' file missing!\n",filename);
  write_user(user,text);  break;
 case 1: user->misc_op=2;
 }
}


/*** Afk ***/
afk(user,inpstr)
UR_OBJECT user;
char *inpstr;
{
if (word_count<2) {
  if (user->vis) {
    sprintf(text,"~FG%s goes AFK...~RS\n",user->name);
    write_room_except(user->room,text,user);
  }
  sprintf(text,"No message set\n");
}
else {
  if (strlen(inpstr)>80) {
    write_user(user,"AFK message too long.\n");
    return;
  }
  if (user->vis) {
    sprintf(text,"~FG(AFK) %s %s\n",user->name,inpstr);
    write_room(user->room,text);
  }
  sprintf(text,"%s %s\n",user->name,inpstr);
}

strcpy(user->afk_mesg,text);
write_user(user,"You are now AFK, press <RETURN> to resume.\n");
user->afk=1;
}


/*** View the system log ***/
viewlog(user)
UR_OBJECT user;
{
FILE *fp;
char c,*emp="\nThe system log is empty.\n";
int lines,cnt,cnt2;

if (word_count==1) {
  write_user(user,"\n~FB*** ~FTSystem Log~FB ***\n\n");
  switch(more(user,user->socket,SYSLOG)) {
  case 0: write_user(user,emp);  return;
  case 1: user->misc_op=2;
  }
  return;
}
if (!isnumber(word[1])) {
  write_user(user,"Usage: viewlog [<lines from the end>]\n");  return;
}
/* Count total lines */
if (!(fp=fopen(SYSLOG,"r"))) {  write_user(user,emp);  return;  }
cnt=0;
lines=atoi(word[1]);

c=getc(fp);
while(!feof(fp)) {
  if (c=='\n') ++cnt;
  c=getc(fp);
}
if (cnt<lines) {
  sprintf(text,"There are only ~FG%d~RS lines in the log.\n",cnt);
  write_user(user,text);
  fclose(fp);
  return;
}
if (cnt==lines) {
  write_user(user,"\n~FB*** ~FTSystem Log~FB ***\n\n");
  fclose(fp);  more(user,user->socket,SYSLOG);  return;
}

/* Find line to start on */
fseek(fp,0,0);
cnt2=0;
c=getc(fp);
while(!feof(fp)) {
  if (c=='\n') ++cnt2;
  c=getc(fp);
  if (cnt2==cnt-lines) {
    sprintf(text,"\n~FB*** ~FTSystem Log (last ~FG%d~FT lines)~FB ***\n\n",lines);
    write_user(user,text);
    user->filepos=ftell(fp)-1;
    fclose(fp);
    if (more(user,user->socket,SYSLOG)!=1) user->filepos=0;
    else user->misc_op=2;
    return;
  }
}
fclose(fp);
sprintf(text,"~OL~FRSYSTEM: ~RSLine count error.\n");
write_user(user,text);
write_syslog("~OL~FRERROR: ~RSLine count error in viewlog().\n",0);
}


/*** Display details of room ***/
look(user)
UR_OBJECT user;
{
RM_OBJECT rm;
UR_OBJECT u;
char temp[81],null[1],*ptr;
char *afk="~FG(AFK)";
int i,exits,users;

rm=user->room;
sprintf(text,"\n~FTRoom: ~FG%s\n\n",rm->name);
write_user(user,text);
write_user(user,user->room->desc);
exits=0;  null[0]='\0';
strcpy(text,"\n~FTExits are:");
for(i=0;i<MAX_LINKS;++i) {
  if (rm->link[i]==NULL) break;
  if (rm->link[i]->access & 1) sprintf(temp,"  ~FR%s",rm->link[i]->name);
  else sprintf(temp,"  ~FG%s",rm->link[i]->name);
  strcat(text,temp);
  ++exits;
}

if (!exits) strcpy(text,"\n~FTThere are no exits.");
strcat(text,"\n\n");
write_user(user,text);

users=0;
for(u=user_first;u!=NULL;u=u->next) {
  if (u->room!=rm || u==user || (!u->vis && u->level>user->level)) 
    continue;
  if (!users++) write_user(user,"~FTYou can see:\n");
  if (u->afk) ptr=afk; else ptr=null;
  
  if (!u->vis) 
    sprintf(text,"     ~FR*~RS%s~RS %s %s~RS %s\n",u->pre_desc,u->name,u->desc,ptr);
  else 
    sprintf(text,"     %s~RS %s %s~RS  %s\n",u->pre_desc,u->name,u->desc,ptr);
  
  write_user(user,text);
}
if (!users) write_user(user,"~FTYou are all alone here.\n");
write_user(user,"\n");

strcpy(text,"Room access is ");
switch(rm->access) {
 case PUBLIC:  strcat(text,"set to ~FGPUBLIC~RS");  break;
 case PRIVATE: strcat(text,"set to ~FRPRIVATE~RS");  break;
 case FIXED_PUBLIC:  strcat(text,"~FRfixed~RS to ~FGPUBLIC~RS");  break;
 case FIXED_PRIVATE: strcat(text,"~FRfixed~RS to ~FRPRIVATE~RS");  break;
 case USER_ROOM: strcat(text,"set to ~FYROOM OWNER ONLY~RS"); break;
 }
sprintf(temp," and there are ~FM%d~RS messages on the board.\n",rm->mesg_cnt);
strcat(text,temp);
write_user(user,text);
if (rm->topic[0]) {
  sprintf(text,"Room topic: %s\n",rm->topic);
  write_user(user,text);
  if (rm->tlock) {
    sprintf(text,"~FR(Topic locked at level: ~FM%s~FR)\n",level_name[rm->tlock]);
    write_user(user,text);
  }
  return;
}

/* write_user(user,"No room topic has been set.\n"); */
}


/*** Switch between command and speech mode ***/
toggle_mode(user)
UR_OBJECT user;
{
if (user->command_mode) {
  write_user(user,"Now in ~FRSPEECH ~FG(Nuts)~RS mode.\n");
  user->command_mode=0;  return;
}
write_user(user,"Now in ~FRCOMMAND ~FG(EW-Too)~RS mode.\n");
user->command_mode=1;
}

ewtoo_mode(user)
UR_OBJECT user;
{
write_user(user,"Now in ~FRCOMMAND ~FG(EW-Too)~RS mode.\n");
user->command_mode=1;
}

nuts_mode(user)
UR_OBJECT user;
{
write_user(user,"Now in ~FRSPEECH ~FG(Nuts)~RS mode.\n");
user->command_mode=0;
}


/*** Shutdown the talker ***/
talker_shutdown(user,str,reboot)
UR_OBJECT user;
char *str;
int reboot;
{
UR_OBJECT u;
int i;
char *ptr;

#ifdef WIN_NT
PROCESS_INFORMATION p_info;
STARTUPINFO s_info;
char *args=strdup(progname); strcat(args," "); strcat(args,confile);
#else
char *args[]={
progname,confile,NULL
};
#endif

if (user!=NULL) ptr=user->name; else ptr=str;
if (reboot) {
  write_room(NULL,"\07\n~OLSYSTEM:~FR~LI Rebooting now!!\n\n");
  sprintf(text,"*** ~FRREBOOT~RS initiated by %s ***\n",ptr);

#ifdef WIN_NT
  GetStartupInfo(&s_info);
#endif
}
else {
  write_room(NULL,"\07\n~OLSYSTEM:~FR~LI Shutting down now!!\n\n");
  sprintf(text,"*** ~FRSHUTDOWN~RS initiated by %s ***\n",ptr);
}
write_syslog(text,0);

for(u=user_first;u!=NULL;u=u->next) disconnect_user(u);
for(i=0;i<2;++i) CLOSE(listen_sock[i]);

#ifdef WIN_NT
/* Shutdown winsock + timer thread before exit */
WSACleanup();
TerminateThread(hThread,0);
#endif

if (reboot) {
  sprintf(text,"*** Server exit at %02d:%02d:%02d ***\n\n",thour,tmin,tsec);
  write_syslog(text,0);
  
  /* If someone has changed the binary or the config filename while this
     prog has been running this won't work */
#ifdef WIN_NT
  CreateProcess(progname,args,NULL,NULL,0,
		DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | NORMAL_PRIORITY_CLASS,
		NULL, NULL, &s_info, &p_info);
#else
  execvp(progname,args);
#endif
  
  /* If we get this far it hasn't worked */
  sprintf(text,"*** ~FRREBOOT~RS failed at %02d:%02d:%02d: %s ***\n\n",thour,tmin,tsec,sys_errlist[errno]);
  write_syslog(text,0);
  exit(12);
}

sprintf(text,"*** ~FRSHUTDOWN~RS complete at %02d:%02d:%02d ***\n\n",thour,tmin,tsec);
write_syslog(text,0);
exit(0);
}


/*** Dsay shortcut ***/
dsay(user,inpstr)
UR_OBJECT user;
char *inpstr;
{
UR_OBJECT u;
char *name;

if (user->muzzled) {
  write_user(user,"You are muzzled, you cannot speak.\n");  return;
}
if (word_count<2) {
  write_user(user,"Usage: .dsay user text\n");
  return;
}
if (word_count<3) {
  write_user(user,"Say what and to who?\n");
  return;
}
if (!(u=get_user(word[1]))) {
  write_user(user,notloggedon);  return;
}
if (u->room!=user->room) {
  write_user(user,"They are not here.\n");
  return;
}

inpstr=remove_first(inpstr);

if (user->vis) name=user->name; else name=invisname;
sprintf(text,"%s says to %s: %s\n",name,u->name,inpstr);
write_room_except(user->room,text,user);
record(user->room,text);
sprintf(text,"You say to %s: %s\n",u->name,inpstr);
write_user(user,text);
}


/*** Say user speech. ***/
say(user,inpstr)
UR_OBJECT user;
char *inpstr;
{
char type[10],*name;

if (user->muzzled) {
  write_user(user,"You are muzzled, you cannot speak.\n");  return;
}
if ((word_count<2 && user->command_mode) || inpstr[0]<32) {
  write_user(user,"Say what?\n");  return;
}
switch(inpstr[strlen(inpstr)-1]) {
 case '?': strcpy(type,"ask");  break;
 case '!': strcpy(type,"exclaim");  break;
 default : strcpy(type,"say");
 }
if (user->type==CLONE_TYPE) {
  sprintf(text,"Clone of %s %ss: %s\n",user->name,type,inpstr);
  write_room(user->room,text);
  record(user->room,text);
  return;
}
if (ban_swearing && contains_swearing(inpstr)) {
  write_user(user,noswearing);  return;
}
sprintf(text,"You %s: %s\n",type,inpstr);
write_user(user,text);
if (user->vis) name=user->name; else name=invisname;
sprintf(text,"%s %ss: %s\n",name,type,inpstr);
write_room_except(user->room,text,user);
record(user->room,text);
}


/*** Shout something ***/
shout(user,inpstr)
UR_OBJECT user;
char *inpstr;
{
char *name;

if (user->muzzled) {
  write_user(user,"You are muzzled, you cannot shout.\n");  return;
}
if (word_count<2 || inpstr[0]<32) {
  write_user(user,"Shout what?\n");  return;
}
if (ban_swearing && contains_swearing(inpstr)) {
  write_user(user,noswearing);  return;
}
sprintf(text,"~OLYou shout:~RS %s\n",inpstr);
write_user(user,text);
if (user->vis) name=user->name; else name=invisname;
sprintf(text,"~OL%s shouts:~RS %s\n",name,inpstr);
write_room_except(NULL,text,user);
record(room_first,text);
}


/*** Tell another user something ***/
tell(user,inpstr)
UR_OBJECT user;
char *inpstr;
{
UR_OBJECT u;
char type[10],type2[10],*name;
int len;

if (user->muzzled) {
  write_user(user,"You are muzzled, you cannot tell anyone anything.\n");
  user->tell=0;
  return;
}
if (word_count<3 && user->tell==0) {
  write_user(user,"Tell who what?\n");  return;
}

/* Catch use of >> before > */
if (user->old_tell[0]=='\0' && user->tell==1) {
  write_user(user,"Tell who what?\n");
  user->tell=0;
  return;
}
if (user->tell)
  u=get_user(user->old_tell);
else
  u=get_user(word[1]);

user->tell=0;

if (!u) {
  write_user(user,notloggedon);  return;
}
if (u==user) {
  write_user(user,"Talking to yourself is the first sign of madness.\n");
  return;
}

/* Make user u the subject of future >> */
strcpy(user->old_tell, u->name);

if (u->afk) {
  sprintf(text,"%s is ~FRAFK~RS at the moment.\nMessage is: ~FY%s",u->name,u->afk_mesg);
  write_user(user,text);
  return;
}
if (u->ignall && (user->level<WIZ || u->level>user->level)) {
  if (u->malloc_start!=NULL)
    sprintf(text,"%s is using the editor at the moment.\n",u->name);
  else sprintf(text,"%s is ignoring everyone at the moment.\n",u->name);
  write_user(user,text);
  return;
}
if (u->igntell && (user->level<WIZ || u->level>user->level)) {
  sprintf(text,"%s is ignoring tells at the moment.\n",u->name);
  write_user(user,text);
  return;
}
inpstr=remove_first(inpstr);

/* Old version - No Smile/grin stuff:
if (inpstr[strlen(inpstr)-1]=='?') strcpy(type,"ask");
else strcpy(type,"tell"); 
*/

len=strlen(inpstr);

switch (inpstr[len-1]) {
 case '?': 
  strcpy(type,"ask");
  strcpy(type2,"asks");
  break;
 case ')': 
  if (inpstr[len-2]==':') {
    strcpy(type,"smile at");
    strcpy(type2,"smiles at");
  }
  else
    if (inpstr[len-2]==';') {
      strcpy(type,"grin at");
      strcpy(type2,"grins at");
    }
    else {
      strcpy(type,"tell");
      strcpy(type2,"tells");
    }
  break;
 default: 
  strcpy(type,"tell");
  strcpy(type2,"tells");
}

sprintf(text,"~OLYou %s %s:~RS %s\n",type,u->name,inpstr);
write_user(user,text);
record_tell(user,text);
if (user->vis) name=user->name; else name=invisname;
sprintf(text,"~OL%s %s you:~RS %s\n",name,type2,inpstr);
write_user(u,text);
record_tell(u,text);
}


/*** Emote something ***/
emote(user,inpstr)
UR_OBJECT user;
char *inpstr;
{
char *name;

if (user->muzzled) {
  write_user(user,"You are muzzled, you cannot emote.\n");  return;
}
if (word_count<2 && inpstr[1]<33) {
  write_user(user,"Emote what?\n");  return;
}
if (ban_swearing && contains_swearing(inpstr)) {
  write_user(user,noswearing);  return;
}
if (user->vis) name=user->name; else name=invisname;

if (inpstr[0]==';' || inpstr[0]==':') {
  if (inpstr[1]==' ' || inpstr[1]=='\'')
    sprintf(text,"%s%s\n",name,inpstr+1);
  else
    sprintf(text,"%s %s\n",name,inpstr+1);
}
else sprintf(text,"%s %s\n",name,inpstr);

write_room(user->room,text);
record(user->room,text);
}


/*** Do a shout emote ***/
semote(user,inpstr)
UR_OBJECT user;
char *inpstr;
{
char *name;

if (user->muzzled) {
  write_user(user,"You are muzzled, you cannot emote.\n");  return;
}
if (word_count<2 || inpstr[0]<32) {
  write_user(user,"Shout emote what?\n");  return;
}
if (ban_swearing && contains_swearing(inpstr)) {
  write_user(user,noswearing);  return;
}
if (user->vis) name=user->name; else name=invisname;

if (inpstr[0]==' ' || inpstr[0]=='\'')
  sprintf(text,"~OL!!~RS %s%s\n",name,inpstr);
else
  sprintf(text,"~OL!!~RS %s %s\n",name,inpstr);

write_room(NULL,text);
record(room_first,text);
}


/*** Do a private emote ***/
pemote(user,inpstr)
UR_OBJECT user;
char *inpstr;
{
char *name;
UR_OBJECT u;

if (user->muzzled) {
  write_user(user,"You are muzzled, you cannot emote.\n");
  user->tell=0;
  return;
}
if (word_count<3 && user->tell==0) {
  write_user(user,"Private emote what and to who?\n");  return;
}
if (user->old_tell[0]=='\0' && user->tell==1) {
  write_user(user,"Private emote what and to who?\n");
  user->tell=0;
  return;
}
word[1][0]=toupper(word[1][0]);
if (!strcmp(word[1],user->name)) {
  write_user(user,"Emoting to yourself is the second sign of madness.\n");
  return;
}
if (user->tell)
  u=get_user(user->old_tell);
else
  u=get_user(word[1]);

user->tell=0;

if (!u) {
  write_user(user,notloggedon);  return;
}
if (u==user) {
  write_user(user,"Emoting to yourself is the second sign of madness.\n");
  return;
}

/* Make user u the subject of future >> */
strcpy(user->old_tell, u->name);

if (u->afk) {
  sprintf(text,"%s is ~FRAFK~RS at the moment.\nMessage is: ~FY%s",u->name,u->afk_mesg);
  write_user(user,text);
  return;
}
if (u->ignall && (user->level<WIZ || u->level>user->level)) {
  if (u->malloc_start!=NULL)
    sprintf(text,"%s is using the editor at the moment.\n",u->name);
  else sprintf(text,"%s is ignoring everyone at the moment.\n",u->name);
  write_user(user,text);  return;
}
if (u->igntell && (user->level<WIZ || u->level>user->level)) {
  sprintf(text,"%s is ignoring private emotes at the moment.\n",u->name);
  write_user(user,text);
  return;
}
if (user->vis) name=user->name; else name=invisname;
inpstr=remove_first(inpstr);

if (inpstr[0]=='\'')
  sprintf(text,"~OL(To %s)~RS %s%s\n",u->name,name,inpstr);
else
  sprintf(text,"~OL(To %s)~RS %s %s\n",u->name,name,inpstr);
write_user(user,text);
record_tell(user,text);
if (inpstr[0]=='\'')
  sprintf(text,"~OL(To you)~RS %s%s\n",name,inpstr);
else
  sprintf(text,"~OL(To you)~RS %s %s\n",name,inpstr);
write_user(u,text);
record_tell(u,text);
}


/*** Echo something to screen ***/
echo(user,inpstr)
UR_OBJECT user;
char *inpstr;
{
if (user->muzzled) {
  write_user(user,"You are muzzled, you cannot echo.\n");  return;
}
if (word_count<2 || inpstr[0]<32) {
  write_user(user,"Echo what?\n");  return;
}
sprintf(text,"(%s) ",user->name);
write_wiz_at_room(ARCH,text,NULL,user->room);
sprintf(text,"- %s\n",inpstr);
write_room(user->room,text);
record(user->room,text);
}


/*** Switch ignoring all on and off ***/
toggle_ignall(user)
UR_OBJECT user;
{
if (!user->ignall) {
  write_user(user,"You are now ignoring everyone.\n");
  sprintf(text,"%s is now ignoring everyone.\n",user->name);
  write_room_except(user->room,text,user);
  user->ignall=1;
  return;
}
write_user(user,"You will now hear everyone again.\n");
sprintf(text,"%s is listening again.\n",user->name);
write_room_except(user->room,text,user);
user->ignall=0;
}


/*** Switch prompt on and off ***/
toggle_prompt(user)
UR_OBJECT user;
{
int new_prompt;
  
if (word_count<2) {
  write_user(user,"Usage: prompt [0|1|2|3] ~FG(prompt 0 is prompt off)\n");
  return;
}
new_prompt=atoi(word[1]);
if (new_prompt>3) {
  write_user(user,"Usage: prompt [0|1|2|3]\n");
  return;
}
if (!new_prompt) {
  write_user(user,"Prompt ~FROFF~RS.\n");
  user->prompt=0;  return;
}

user->prompt=new_prompt;

sprintf(text,"Prompt type ~FG%d~RS selected.\n",new_prompt);
write_user(user,text);
}


/*** Set user description ***/
set_desc(user,inpstr)
UR_OBJECT user;
char *inpstr;
{
int tot_len;

if (word_count<2) {
  sprintf(text,"Your current description is: %s\n",user->desc);
  write_user(user,text);
  return;
}
if (strstr(word[1],"(CLONE)")) {
  write_user(user,"You cannot have that description.\n");  return;
}

/* get current length of post+pre desc + user name */
tot_len=(strlen(inpstr)+strlen(user->pre_desc)+strlen(user->name))-colour_com_count(inpstr)-colour_com_count(user->pre_desc);

if (tot_len>=USER_DESC_LEN || strlen(inpstr)>77) {
  if (user->pre_desc[0]!='\0')
    write_user(user,"Description too long.  Shorten your .pdesc if neccessary.\n");
  else
    write_user(user,"Description too long.\n");  return;
}
strcpy(user->desc,inpstr);

if (user->pre_desc[0]!='\0')
  sprintf(text,"Description set to: %s~RS %s %s\n",user->pre_desc,user->name,user->desc);
else
  sprintf(text,"Description set to: %s %s\n",user->name,user->desc);

write_user(user,text);

if (user->vis) {
  sprintf(text,"%s enters a new description.\n",user->name);
  write_room_except(user->room,text,user);
}
}


/*** Set user pre-description ***/
set_pre_desc(user,inpstr)
UR_OBJECT user;
char *inpstr;
{
int tot_len;

if (word_count<2) {
  if (!user->pre_desc[0])
    sprintf(text,"You don't currently have a pre-description.\n");
  else
    sprintf(text,"You current pre-description is: %s (Type ~FG'.pdesc none'~RS to remove)\n",user->pre_desc);
  write_user(user,text);
  return;
}
if (!strcmp(word[1],"none")) {
  user->pre_desc[0]='\0';
  write_user(user,"Predesc removed.\n");
  return;
}

/* get current length of post+pre desc+name */
tot_len=(strlen(inpstr)+strlen(user->desc)+strlen(user->name))-colour_com_count(inpstr)-colour_com_count(user->desc);

if (tot_len>=USER_DESC_LEN || strlen(inpstr)>77) {
  write_user(user,"Description too long.  Reduce your post or pre desc.\n");  return;
}
strcpy(user->pre_desc,inpstr);

sprintf(text,"Description set to: %s~RS %s %s\n",user->pre_desc,user->name,user->desc);
write_user(user,text);

if (user->vis) {
  sprintf(text,"%s enters a new description.\n",user->name);
  write_room_except(user->room,text,user);
}

}


/*** Move to another room ***/
go(user)
UR_OBJECT user;
{
RM_OBJECT rm;
int i;

if (word_count<2) {
  write_user(user,"Go where?\n");  return;
}
if ((rm=get_room(word[1]))==NULL) {
  write_user(user,nosuchroom);  return;
}
if (rm==user->room) {
  sprintf(text,"You are already in the room ~FG'%s'~RS!\n",rm->name);
  write_user(user,text);
  return;
}
/* Home room */
if (!strncmp(rm->name,user->name,strlen(rm->name))) {
  move_user(user,rm,3);  
  return;
}
/* Users can always go straight to invited rooms */
if (user->invite_room==rm) {
  move_user(user,rm,0);  
  return;
}

if (((rm->access==PRIVATE || rm->access==USER_ROOM) && user->invite_room!=rm)
    || (rm->access==FIXED_PRIVATE && user->level<WIZ)) { 
  write_user(user,"That room is currently private.\n");
  return;
}

/* See if link from current room */
for(i=0;i<MAX_LINKS;++i) {
  if (user->room->link[i]==rm) {
    move_user(user,rm,0);  return;
  }
}
if (user->level<WIZ) {
  sprintf(text,"The room ~FG'%s'~RS is not adjoined to here.\n",rm->name);
  write_user(user,text);
  return;
}
move_user(user,rm,1);
}


/*** Called by go() and join() ***/
move_user(user,rm,type)
UR_OBJECT user;
RM_OBJECT rm;
int type;
{
RM_OBJECT old_room;

old_room=user->room;
/* Ignore gatecrash level if room is FIXED to private 'cos this may be one
   of the wiz rooms so let any user of WIZ and above in */
if (type!=2
    && (rm->access & 1) 
    && user->level<gatecrash_level 
    && user->invite_room!=rm
    && !((rm->access & 2) && user->level>=WIZ)) {
  write_user(user,"That room is currently private, you cannot enter.\n");  
  return;
}

/* Reset invite room if in it */
if (user->invite_room==rm) user->invite_room=NULL;
if (!user->vis) {
  write_room(rm,invisenter);
  write_room_except(user->room,invisleave,user);
  goto SKIP;
}

switch(type) {
 case 1:
  sprintf(text,"~FT%s appears in an explosion of blue magic!\n",user->name);
  write_room(rm,text);
  record(rm,text);
  sprintf(text,"~FT%s chants a spell and vanishes into a magical blue vortex!\n",user->name);
  write_room_except(old_room,text,user);
  record(old_room,text);
  break;
 
 case 2:
  write_user(user,"\n~FTA giant hand grabs you and pulls you into a magical blue vortex!\n");
  sprintf(text,"~FT%s falls out of a magical blue vortex!\n",user->name);
  write_room_except(rm,text,user);
  record(rm,text);
  sprintf(text,"~FTA giant hand grabs %s who is pulled into a magical blue vortex!\n",user->name);
  write_room_except(old_room,text,user);
  record(old_room,text);
  break;

 case 3:
  switch (user->sex) {
  case 1: 
    sprintf(text,"%s %s~RS to his home room.\n",user->name,user->out_phrase);
    break;
  case 2: 
    sprintf(text,"%s %s~RS to her home room.\n",user->name,user->out_phrase); 
    break;
  default: 
    sprintf(text,"%s %s~RS to it's home room.\n",user->name,user->out_phrase); 
    break;
  }
  write_room_except(user->room,text,user);
  record(user->room,text);
  sprintf(text,"%s %s~RS.\n",user->name,user->in_phrase);
  write_room(rm,text);
  record(rm,text);
  break;

 default:
  sprintf(text,"%s %s~RS.\n",user->name,user->in_phrase);
  write_room(rm,text);
  record(rm,text);
  sprintf(text,"%s %s~RS to the room ~FG'%s'~RS.\n",user->name,user->out_phrase,rm->name);
  write_room_except(user->room,text,user);
  record(user->room,text);
  break;
}
 SKIP:
user->room=rm;
look(user);
reset_access(old_room);
}


/*** Join another user ***/
join(user)
UR_OBJECT user;
{
UR_OBJECT u;

if (word_count<2) {
  write_user(user,"Join who?\n");
  return;
}
if (!(u=get_user(word[1]))) {
  write_user(user,notloggedon);  return;
}
if (u==user) {
  write_user(user,"You cannot join yourself!\n");
  return;
}
if (u->room==user->room) {
  sprintf(text,"%s is here!\n",u->name);
  write_user(user,text);
  return;
}
if (((u->room->access==PRIVATE || u->room->access==USER_ROOM) && user->invite_room!=u->room)
    || (u->room->access==FIXED_PRIVATE && user->level<WIZ)) {
  write_user(user,"That room is currently private.\n");
  return;
}
move_user(user,u->room,0);
}


/*** Boot a user from a private room ***/
boot(user)
UR_OBJECT user;
{
UR_OBJECT u;
RM_OBJECT rm;

rm=get_room(user->name);
if (rm!=user->room) {
  write_user(user,"You do not own this room - you cannot boot someone out of it.\n");
  return;
}
if (word_count<2) {
  write_user(user,"Who do you want to boot out of this room?\n");
  return;
}
if (!(u=get_user(word[1]))) {
  write_user(user,notloggedon);  return;
}
if (u==user) {
  write_user(user,"You cannot boot yourself!\n");
  return;
}
if (u->room!=rm) {
  sprintf(text,"%s is not in this room.\n",u->name);
  write_user(user,text);
  return;
}
sprintf(text,"%s boots %s out of this room!\n",user->name,u->name);
write_room_except2(user->room,text,u,user);
record(user->room,text);
sprintf(text,"%s boots YOU out of this room!\n",user->name);
write_user(u,text);
sprintf(text,"You boot %s out of this room!\n",u->name);
write_user(user,text);
move_user(u,room_first,0);
}


/*** Set in and out phrases ***/
set_iophrase(user,inpstr)
UR_OBJECT user;
char *inpstr;
{
if (strlen(inpstr)>PHRASE_LEN) {
  write_user(user,"Phrase too long.\n");  return;
}
if (com_num==INPHRASE) {
  if (word_count<2) {
    sprintf(text,"Your current in phrase is: %s %s\n",user->name,user->in_phrase);
    write_user(user,text);
    return;
  }
  strcpy(user->in_phrase,inpstr);
  sprintf(text,"In phrase set to: %s %s\n",user->name,user->in_phrase);
  write_user(user,text);
  return;
}
if (word_count<2) {
  sprintf(text,"Your current out phrase is: %s %s~RS to the ~FG(room name)\n",user->name,user->out_phrase);
  write_user(user,text);
  return;
}
strcpy(user->out_phrase,inpstr);
sprintf(text,"Out phrase set to: %s %s\n",user->name,user->out_phrase);
write_user(user,text);
}


/*** Set rooms to public or private ***/
set_room_access(user)
UR_OBJECT user;
{
UR_OBJECT u;
RM_OBJECT rm;
char *name;
int cnt;

rm=user->room;
/* Check for owner of user room */
if (isupper(rm->name[0])) {
  rm=get_room(user->name);
  if (rm!=user->room) {
    write_user(user,"You cannot change the access as you do not own this room.\n");
    return;
  }
}
if (rm->access==FIXED_PRIVATE || rm->access==FIXED_PUBLIC) {
  write_user(user,"Access to this room is fixed.\n");  return;
}
if (com_num==PUBCOM && rm->access==PUBLIC) {
  write_user(user,"The room is already public.\n");  return;
}
if (user->vis) name=user->name; else name=invisname;
if (com_num==PRIVCOM) {
  if (rm->access==PRIVATE || rm->access==USER_ROOM) {
    write_user(user,"The room is already private.\n");  return;
  }
  cnt=0;
  for(u=user_first;u!=NULL;u=u->next) if (u->room==rm) ++cnt;

  /* Check for user room */
  if (isupper(rm->name[0])) {
    write_user(user,"Room set to ~FYROOM OWNER ONLY~RS.\n");
    sprintf(text,"%s has set the room to ~FYROOM OWNER ONLY~RS.\n",name);
    write_room_except(rm,text,user);
    record(rm,text);
    rm->access=USER_ROOM;
    return;
  }
  if (cnt<min_private_users && user->level<ignore_mp_level) {
    sprintf(text,"You need at least ~FG%d~RS people in a room before it can be made private.\n",min_private_users);
    write_user(user,text);
    return;
  }
  write_user(user,"Room set to ~FRPRIVATE.\n");
  sprintf(text,"%s has set the room to ~FRPRIVATE.\n",name);
  write_room_except(user->room,text,user);
  record(rm,text);
  user->room->access=PRIVATE;
  return;
}
write_user(user,"Room set to ~FGPUBLIC.\n");
sprintf(text,"%s has set the room to ~FGPUBLIC.\n",name);
write_room_except(rm,text,user);
record(rm,text);
rm->access=PUBLIC;

/* Reset any invites into the room & clear review buffer */
for(u=user_first;u!=NULL;u=u->next) {
  if (u->invite_room==rm) u->invite_room=NULL;
}
clear_rbuff(rm);
}


/*** Ask to be let into a private room ***/
letmein(user)
UR_OBJECT user;
{
RM_OBJECT rm;

if (word_count<2) {
  write_user(user,"Let you into where?\n");  return;
}
if ((rm=get_room(word[1]))==NULL) {
  write_user(user,nosuchroom);  return;
}
if (rm==user->room) {
  sprintf(text,"You are already in the %s!\n",rm->name);
  write_user(user,text);
  return;
}
if (rm->access==PUBLIC || rm->access==FIXED_PUBLIC) {
  sprintf(text,"The %s is currently public.\n",rm->name);
  write_user(user,text);
  return;
}
sprintf(text,"You shout asking to be let into the room ~FG'%s'~RS.\n",rm->name);
write_user(user,text);
sprintf(text,"%s shouts into this room asking to be let in.\n",user->name);
write_room(rm,text);
record(rm,text);
}


/*** Invite a user into a private room ***/
invite(user)
UR_OBJECT user;
{
UR_OBJECT u;
RM_OBJECT rm;
char *name;

if (word_count<2) {
  write_user(user,"Invite who?\n");  return;
}
rm=user->room;
if (rm->access==PUBLIC || rm->access==FIXED_PUBLIC) {
  write_user(user,"This room is currently public.\n");
  return;
}
if (!(u=get_user(word[1]))) {
  write_user(user,notloggedon);  return;
}
if (u==user) {
  write_user(user,"Inviting yourself to somewhere is the third sign of madness.\n");
  return;
}
if (u->room==rm) {
  sprintf(text,"%s is already here!\n",u->name);
  write_user(user,text);
  return;
}
if (u->invite_room==rm) {
  sprintf(text,"%s has already been invited into here.\n",u->name);
  write_user(user,text);
  return;
}
sprintf(text,"You invite %s in.\n",u->name);
write_user(user,text);
if (user->vis) name=user->name; else name=invisname;
sprintf(text,"%s has invited you into the room ~FG'%s'~RS.\n",name,rm->name);
write_user(u,text);
record_tell(u,text);
u->invite_room=rm;
}


/*** Set the room topic ***/
set_topic(user,inpstr)
UR_OBJECT user;
char *inpstr;
{
RM_OBJECT rm;
char *name;

rm=user->room;
if (word_count<2) {
  if (!strlen(rm->topic)) {
    write_user(user,"No topic has been set yet.\n");  return;
  }
  sprintf(text,"Room topic: %s\n",rm->topic);
  write_user(user,text);
  if (rm->tlock) {
    sprintf(text,"~FR(Topic locked at level: ~FM%s~FR)\n",level_name[rm->tlock]);
    write_user(user,text);
  }
  return;
}
if (user->muzzled) {
  write_user(user,"You are muzzled, you cannot change the topic.\n");  
  return;
}
if (user->level<rm->tlock) {
  sprintf(text,"You cannot change the current room topic as it is locked at level: ~FG%s\n",level_name[rm->tlock]);
  write_user(user,text);
  return;
}
if (strlen(inpstr)>TOPIC_LEN) {
  write_user(user,"Topic too long.\n");  return;
}
sprintf(text,"Topic set to: %s\n",inpstr);
write_user(user,text);
if (user->vis) name=user->name; else name=invisname;
sprintf(text,"~OL%s~RS has set the room topic to: %s\n",name,inpstr);
write_room_except(rm,text,user);
record(rm,text);
strcpy(rm->topic,inpstr);
rm->tlock=0;
}


/*** Wizard moves a user to another room ***/
move(user)
UR_OBJECT user;
{
UR_OBJECT u;
RM_OBJECT rm;
char *name;

if (word_count<2) {
  write_user(user,"Usage: move <user> [<room>]\n");  return;
}
if (!(u=get_user(word[1]))) {
  write_user(user,notloggedon);  return;
}
if (word_count<3) rm=user->room;
else {
  if ((rm=get_room(word[2]))==NULL) {
    write_user(user,nosuchroom);  return;
  }
}
if (user==u) {
  write_user(user,"Trying to move yourself this way is the fourth sign of madness.\n");  return;
}
if (rm==u->room) {
  sprintf(text,"%s is already in the room ~FG'%s'~RS.\n",u->name,rm->name);
  write_user(user,text);
  return;
};
if (u->level>=user->level) {
  write_user(user,"You cannot move a user of equal or higher level than yourself.\n");
  return;
}
if (user->level<gatecrash_level || u->invite_room!=rm) {
  if (rm->access==FIXED_PRIVATE) {
    sprintf(text,"The room ~FG'%s'~RS is currently private, %s cannot be moved there.\n",rm->name,u->name);
    write_user(user,text);  
    return;
  }
  if (rm->access==USER_ROOM) {
    if (strncmp(u->name,rm->name,strlen(rm->name)))
      if (strncmp(user->name,rm->name,strlen(rm->name))) {
	write_user(user,"You don't own that room - you can't move someone there.\n");
	return;
      }
  }
}
write_user(user,"~FTYou chant an ancient spell...\n");
if (user->vis) name=user->name; else name=invisname;
sprintf(text,"~FT%s chants an ancient spell...\n",name);
write_room_except(user->room,text,user);
record(user->room,text);
move_user(u,rm,2);
prompt(u);
}


/*** Go to home room ***/
home(user)
UR_OBJECT user;
{
RM_OBJECT room;
char filename[80],line[81];
FILE *fp;

room=get_room(user->name);

if (room==NULL) {
  room=create_room();
  if (room==NULL)
    return;
  strcpy(room->name,user->name);
  strcpy(room->label,"aA");
  room->link[0]=room_first;
  room->access=USER_ROOM;
  
  sprintf(filename,"%s/%s.R",USERFILES,user->name);
  if (!(fp=fopen(filename,"r"))) {
    /* No room file on disk - create basic one */
    strcpy(room->desc,"A bare room - use ~FG'.edit'~RS to enter a description for it.\n");
  }
  else { 
    /* Room file supplied */
    fgets(line,80,fp);
    strcpy(room->desc,line);
    while (!feof(fp)) {
      line[0]='\0';
      fgets(line,80,fp);
      strcat(room->desc,line);
    }
    fclose(fp);
  }
}

if (room==user->room) {
  write_user(user,"You are already in your home room.\n");
  return;
}

move_user(user,room,3);
}


/*** Edit home room ***/
edit_room(user,done_editing)
UR_OBJECT user;
int done_editing;
{
FILE *fp;
char *c,filename[80];
RM_OBJECT rm;

rm=get_room(user->name);

if (!done_editing) {
  if (rm!=user->room) {
    write_user(user,"You must be in your home room to enter it's description.\n");
    return;
  }
  if (user->vis) {
    sprintf(text,"%s starts to enter a new home room description.\n",user->name);
    write_room_except(user->room,text,user);
  }
  write_user(user,"\n~FB** ~FTWriting Home Room Description~FB ***\n\n");
  user->misc_op=8;
  editor(user,NULL);
  return;
}
sprintf(filename,"%s/%s.R",USERFILES,user->name);
if (!(fp=fopen(filename,"w"))) {
  sprintf(text,"%s: couldn't save your room.\n",syserror);
  write_user(user,text);
  sprintf("ERROR: Couldn't open file %s to write in edit_room().\n",filename);
  write_syslog(text,0);
  return;
}
c=user->malloc_start;
while(c!=user->malloc_end) putc(*c++,fp);
fclose(fp);
write_user(user,"Room stored.\n");
strncpy(rm->desc,user->malloc_start,user->malloc_end-user->malloc_start);
rm->desc[user->malloc_end-user->malloc_start]='\0';
if (user->vis) {
  sprintf(text,"%s finishes writing a new room description.\n",user->name);
  write_room_except(user->room,text,user);
}
}


/*** Broadcast an important message ***/
bcast(user,inpstr)
UR_OBJECT user;
char *inpstr;
{
if (word_count<2) {
  write_user(user,"Usage: bcast <message>\n");  return;
}
force_listen=1;
if (user->vis) 
  sprintf(text,"\07\n~BR~FW*** Broadcast message from %s ***\n%s\n\n",user->name,inpstr);
else sprintf(text,"\07\n~BR~FW*** Broadcast message ***\n%s\n\n",inpstr);
write_room(NULL,text);
record(room_first,text);  
}


/*** Short who ***/
swho(user)
UR_OBJECT user;
{
UR_OBJECT u;
int c=0;

sprintf(text,"\n~FB*** ~FTCurrent users on %s, %d %s, %02d:%02d ~FB***\n",day[twday],tmday,month[tmonth],thour,tmin);
write_user(user,text);

for(u=user_first;u!=NULL;u=u->next) {
  if (u->type==CLONE_TYPE || u->login) continue;
  if (!u->vis)
    if (u->level>user->level) continue;

  if (c==0)
    write_user(user,"\n  ");

  sprintf(text,"%-12s",u->name);
  write_user(user,text);

  c++;
  if (c==6)
    c=0;
}

write_user(user,"\n\n");
}


/*** Show who is on ***/
who(user,people)
UR_OBJECT user;
int people;
{
UR_OBJECT u;
int cnt,cnt2,total,invis,mins,idle;
char line[USER_NAME_LEN+USER_DESC_LEN*2];
char rname[ROOM_NAME_LEN+1],portstr[5],idlestr[6],sockstr[3];

total=0;  invis=0;  
sprintf(text,"\n~FB*** ~FTCurrent users on %s, %d %s, %02d:%02d ~FB***\n\n",day[twday],tmday,month[tmonth],thour,tmin);
write_user(user,text);
if (people) write_user(user,"~UL~FTName         : Level   Line Ign Vis Idle Mins Port Site\n");
for(u=user_first;u!=NULL;u=u->next) {
  if (u->type==CLONE_TYPE) continue;
  mins=(int)(time(0) - u->last_login)/60;
  idle=(int)(time(0) - u->last_input)/60;
  
  if (u->port==port[0]) 
    strcpy(portstr,"MAIN");
  else 
    strcpy(portstr,"WIZ ");

  if (u->login) {
    if (!people) continue;
    sprintf(text,"~FY[Login - %d ] :  -       %2d  -    - %4d    -  %s %s\n",u->login,u->socket,idle,portstr,u->site);
    write_user(user,text);
    continue;
  }

  ++total;

  if (!u->vis) {
    ++invis;
    if (u->level>user->level) continue;
  }

  if (people) {
    if (u->afk) strcpy(idlestr," AFK");
    else sprintf(idlestr,"%4d",idle);

    sprintf(sockstr,"%2d",u->socket);

    sprintf(text,"%-12s : %-8s %s %s  %s%s %4d  %s %s\n",u->name,new_levels[u->sex][u->level],sockstr,noyes1[u->ignall],noyes1[u->vis],idlestr,mins,portstr,u->site);
    write_user(user,text);
    continue;
  } /* End of if (people) */

  sprintf(line,"  %s~RS %s %s",u->pre_desc,u->name,u->desc);

  if (!u->vis) line[0]='*';

  if (u->afk || !u->room)
    strcpy(rname,"<-AFK->");
  else
    strcpy(rname,u->room->name);
  rname[7]='\0';

  /* Count number of colour coms to be taken account of when formatting */
  cnt=colour_com_count(line);
  cnt2=colour_com_count(u->rank);
  sprintf(text,"%-*s~RS : %-*s~RS : %7s : %d mins\n",45+cnt,line,9+cnt2,u->rank,rname,mins);

  write_user(user,text);
}
sprintf(text,"\nThere are ~FG%d~RS visible, ~FR%d~RS invisible, total of ~FY%d~RS users.\n\n",num_of_users-invis,invis,total);
write_user(user,text);
}


/*** Read the message board ***/
read_board(user)
UR_OBJECT user;
{
RM_OBJECT rm;
char filename[80],*name;
int ret;

if (word_count<2) rm=user->room;
else {
  if ((rm=get_room(word[1]))==NULL) {
    write_user(user,nosuchroom);  return;
  }
  if (user->level<gatecrash_level && (rm->access!=PUBLIC && rm->access!=FIXED_PUBLIC)) {
    write_user(user,"That room is currently private, you cannot read the board remotely.\n");
    return;
  }
}
sprintf(text,"\n~FB*** ~FTThe ~FG%s~FT message board~FB ***\n\n",rm->name);
write_user(user,text);
sprintf(filename,"%s/%s.B",DATAFILES,rm->name);
if (!(ret=more(user,user->socket,filename)))
	write_user(user,"The board is empty.\n\n");
else if (ret==1) user->misc_op=2;
if (user->vis) name=user->name; else name=invisname;
if (rm==user->room) {
  sprintf(text,"%s reads the message board.\n",name);
  write_room_except(user->room,text,user);
}
}


/*** Write on the message board ***/
write_board(user,inpstr,done_editing)
UR_OBJECT user;
char *inpstr;
int done_editing;
{
FILE *fp;
int cnt,inp;
char *ptr,*name,filename[80];

if (user->muzzled) {
  write_user(user,"You are muzzled, you cannot write on the board.\n");  
  return;
}
if (!done_editing) {
  if (word_count<2) {
    write_user(user,"\n~FB*** ~FTWriting board message~FB ***\n\n");
    user->misc_op=3;
    editor(user,NULL);
    return;
  }
  ptr=inpstr;
  inp=1;
}
else {
  ptr=user->malloc_start;  inp=0;
}

sprintf(filename,"%s/%s.B",DATAFILES,user->room->name);
if (!(fp=fopen(filename,"a"))) {
  sprintf(text,"%s: cannot write to file.\n",syserror);
  write_user(user,text);
  sprintf(text,"ERROR: Couldn't open file %s to append in write_board().\n",filename);
  write_syslog(text,0);
  return;
}
if (user->vis) name=user->name; else name=invisname;
sprintf(text,"PT: %d\n~OLFrom: ~RS~FT%s~RS, %s %d %s, %02d:%02d\n",(int)(time(0)),name,day[twday],tmday,month[tmonth],thour,tmin);
fputs(text,fp);
cnt=0;
while(*ptr!='\0') {
  putc(*ptr,fp);
  if (*ptr=='\n') cnt=0; else ++cnt;
  if (cnt==80) { putc('\n',fp); cnt=0; }
  ++ptr;
}
if (inp) fputs("\n\n",fp); else putc('\n',fp);
fclose(fp);
write_user(user,"You write the message on the board.\n");
sprintf(text,"%s writes a message on the board.\n",name);
write_room_except(user->room,text,user);
user->room->mesg_cnt++;
}


/*** Wipe some messages off the board ***/
wipe_board(user)
UR_OBJECT user;
{
int num,cnt,valid;
char infile[80],line[82],id[82],*name;
FILE *infp,*outfp;
RM_OBJECT rm;

if (word_count<2 || ((num=atoi(word[1]))<1 && strcmp(word[1],"all"))) {
  write_user(user,"Usage: wipe <num>/all\n");  return;
}
rm=user->room;
if (user->vis) name=user->name; else name=invisname;
sprintf(infile,"%s/%s.B",DATAFILES,rm->name);
if (!(infp=fopen(infile,"r"))) {
  write_user(user,"The message board is empty.\n");
  return;
}
if (!strcmp(word[1],"all")) {
  fclose(infp);
  unlink(infile);
  write_user(user,"All messages deleted.\n");
  sprintf(text,"%s wipes the message board.\n",name);
  write_room_except(rm,text,user);
  sprintf(text,"%s wiped all messages from the board in the %s.\n",user->name,rm->name);
  write_syslog(text,1);
  rm->mesg_cnt=0;
  return;
}
if (!(outfp=fopen("tempfile","w"))) {
  sprintf(text,"%s: couldn't open tempfile.\n",syserror);
  write_user(user,text);
  write_syslog("ERROR: Couldn't open tempfile in wipe_board().\n",0);
  fclose(infp);
  return;
}
cnt=0; valid=1;
fgets(line,82,infp); /* max of 80+newline+terminator = 82 */
while(!feof(infp)) {
  if (cnt<=num) {
    if (*line=='\n') valid=1;
    sscanf(line,"%s",id);
    if (valid && !strcmp(id,"PT:")) {
      if (++cnt>num) fputs(line,outfp);
      valid=0;
    }
  }
  else fputs(line,outfp);
  fgets(line,82,infp);
}
fclose(infp);
fclose(outfp);
unlink(infile);
if (cnt<num) {
  unlink("tempfile");
  sprintf(text,"There were only %d messages on the board, all now deleted.\n",cnt);
  write_user(user,text);
  sprintf(text,"%s wipes the message board.\n",name);
  write_room_except(rm,text,user);
  sprintf(text,"%s wiped all messages from the board in the %s.\n",user->name,rm->name);
  write_syslog(text,1);
  rm->mesg_cnt=0;
  return;
}
if (cnt==num) {
  unlink("tempfile"); /* cos it'll be empty anyway */
  write_user(user,"All messages deleted.\n");
  user->room->mesg_cnt=0;
  sprintf(text,"%s wiped all messages from the board in the %s.\n",user->name,rm->name);
}
else {
  rename("tempfile",infile);
  sprintf(text,"%d messages deleted.\n",num);
  write_user(user,text);
  user->room->mesg_cnt-=num;
  sprintf(text,"%s wiped %d messages from the board in the %s.\n",user->name,num,rm->name);
}
write_syslog(text,1);
sprintf(text,"%s wipes the message board.\n",name);
write_room_except(rm,text,user);
}

	

/*** Search all the boards for the words given in the list. Rooms fixed to
  private will be ignore if the users level is less than gatecrash_level ***/
search_boards(user)
UR_OBJECT user;
{
RM_OBJECT rm;
FILE *fp;
char filename[80],line[82],buff[(MAX_LINES+1)*82],w1[81];
int w,cnt,message,yes,room_given;

if (word_count<2) {
  write_user(user,"Usage: search <word list>\n");  return;
}
/* Go through rooms */
cnt=0;
for(rm=room_first;rm!=NULL;rm=rm->next) {
  sprintf(filename,"%s/%s.B",DATAFILES,rm->name);
  if (!(fp=fopen(filename,"r"))) continue;
  if (user->level<gatecrash_level) {  fclose(fp);  continue;  }
  
  /* Go through file */
  fgets(line,81,fp);
  yes=0;  message=0;  
  room_given=0;  buff[0]='\0';
  while(!feof(fp)) {
    if (*line=='\n') {
      if (yes) {  strcat(buff,"\n");  write_user(user,buff);  }
      message=0;  yes=0;  buff[0]='\0';
    }
    if (!message) {
      w1[0]='\0';  
      sscanf(line,"%s",w1);
      if (!strcmp(w1,"PT:")) {  
	message=1;  
	strcpy(buff,remove_first(remove_first(line)));
      }
    }
    else strcat(buff,line);
    for(w=1;w<word_count;++w) {
      if (!yes && strstr(line,word[w])) {  
	if (!room_given) {
	  sprintf(text,"~FB*** ~FT%s~FB ***\n\n",rm->name);
	  write_user(user,text);
	  room_given=1;
	}
	yes=1;  cnt++;  
      }
    }
    fgets(line,81,fp);
  }
  if (yes) {  strcat(buff,"\n");  write_user(user,buff);  }
  fclose(fp);
}
if (cnt) {
  sprintf(text,"Total of ~FG%d~RS matching messages.\n\n",cnt);
  write_user(user,text);
}
else write_user(user,"No occurences found.\n");
}


/*** See review of conversation ***/
review(user)
UR_OBJECT user;
{
RM_OBJECT rm;
int i,line;

if (word_count<2) rm=user->room;
else {
  if ((rm=get_room(word[1]))==NULL) {
    write_user(user,nosuchroom);  return;
  }
  if (((rm->access==PRIVATE || rm->access==USER_ROOM)
      && user->level<gatecrash_level)
      || (rm->access==FIXED_PRIVATE && user->level<WIZ)) {
    write_user(user,"That room is currently private, you cannot review the conversation.\n");
    return;
  }
}
sprintf(text,"~FB~OL*** Review buffer for room ~FG'%s'~FB ***\n",rm->name);
write_user(user,text);
for(i=0;i<CONV_LINES;++i) {
  line=(rm->cln+i)%CONV_LINES;
  if (rm->conv_line[line][0])
    write_user(user,rm->conv_line[line]); 
}
write_user(user,"~FB~OL*** End ***\n");
}


/*** Do the help ***/
help(user)
UR_OBJECT user;
{
int ret;
char filename[80], *c;
  
if (word_count<2) {
  if (user->level==NEW) {
    sprintf(filename,"%s/help.new",HELPFILES);
    more(user,user->socket,filename);
    return;
  }
  
  sprintf(filename,"%s/help.user",HELPFILES);
  if (!(ret=more(user,user->socket,filename))) {
    /* If new help file missing - show old commands list */
    help_commands(user);
    return;
  }
 
  /* Now display additional helpfiles depending on rank... */
  if (user->level>=WIZ) {
    sprintf(filename,"%s/help.wiz",HELPFILES);
    more(user,user->socket,filename);
  }
  if (user->level>=ARCH) {
	  sprintf(filename,"%s/help.arch",HELPFILES);
	  more(user,user->socket,filename);
	}
  if (user->level>=GOD) {
    sprintf(filename,"%s/help.god",HELPFILES);
    more(user,user->socket,filename);
  }

  if (user->level>=UBERGOTH) {
    sprintf(filename,"%s/help.ubergoth",HELPFILES);
    more(user,user->socket,filename);
  }
    
  /* And end part... All users get this */
  sprintf(filename,"%s/help.all",HELPFILES);
  more(user,user->socket,filename);
	
  return;
}

if (!strcmp(word[1],"commands")) {
  help_commands(user);  return;
}
if (!strcmp(word[1],"credits")) {
  sprintf(text,"\n~FB*** ~FMCrypt version %s ~FY- ~FTThe Credits! ~FB***\n\n",VERSION);
  write_user(user,text);
  
  write_user(user,"This talker system is based on ~FRCrypt v5.0~RS code, which is itself based on ~FYNuts   v3.2.1~RS code by Neil Robertson (Type ~FG'.help  neil'~RS for Neil's original credits   page).\n\nThe system is basically a massively upgraded Nuts system featuring many new     commands, features and bug fixes from Nuts, including support for Windows 95/NT servers.  ~FMThe Crypt~RS has ran for over a year and all user comments and           suggestions have been incorporated in that time :)\n\n");
  
  write_user(user,"The code has been upgraded by ~FGBryan McPhail ~FM(Mish)~RS with some useful code        contributions from ~FTScott MacKenzie~RS,~FT Marty Greenwell~RS, ~FTChris Jackson~RS &~FT Thomas     Neill~RS.\n\nThis package includes code from Figlet v2.1.1 and GNU crypt().  See the file    COPYRIGHT for full information.\n\nThe Crypt web page can be found at ~FGhttp://www.deathsdoor.com/~crypt\nThe Crypt source code can be found at ~FMhttp://www.tendril.force9.co.uk/crypt\n\n"); 
  
  return;
}

/* Check for any illegal crap in searched for filename so they cannot list 
   out the /etc/passwd file for instance. */
c=word[1];
while(*c) {
  if (*c=='.' || *c=='/') {
    write_user(user,"Sorry, there is no help on that topic!\n");
    return;
  }
  ++c;
}
sprintf(filename,"%s/%s",HELPFILES,word[1]);
if (!(ret=more(user,user->socket,filename)))
  write_user(user,"Sorry, there is no help on that topic.\n");
if (ret==1) user->misc_op=2;
}


/*** Show the command available ***/
help_commands(user)
UR_OBJECT user;
{
int com,cnt,lev;
char temp[20];

sprintf(text,"\n~FB*** ~FTCommands available for level: ~FG%s~FB ***\n\n",new_levels[user->sex][user->level]);
write_user(user,text);

for(lev=NEW;lev<=user->level;++lev) {
  sprintf(text,"~FT(%s)\n",new_levels[user->sex][lev]);
  write_user(user,text);
  com=0;  cnt=0;  text[0]='\0';
  while(command[com][0]!='*') {
    if (com_level[com]!=lev) {  com++;  continue;  }
    if (!strcmp("admin",command[com])) {
      com++;
      continue;
    }

    sprintf(temp,"%-10s ",command[com]);
    strcat(text,temp);
    if (cnt==6) {  
      strcat(text,"\n");  
      write_user(user,text);  
      text[0]='\0';  cnt=-1;  
    }
    com++; cnt++;
  }
  if (cnt) {
    strcat(text,"\n");  write_user(user,text);
  }
}

write_user(user,"Type '~FG.help <command name>~RS' for specific help on a command or '~FG.help credits~RS'   for information.\n");
}


/*** Show some user stats ***/
status(user)
UR_OBJECT user;
{
UR_OBJECT u;
char ir[ROOM_NAME_LEN+1], tmp[10];
int days,hours,mins;

if (word_count<2 || user->level<WIZ) {
  u=user;
  write_user(user,"\n~FB*** ~FTYour Status~FB ***\n\n");
}
else {
  if (!(u=get_user(word[1]))) {
    write_user(user,notloggedon);  return;
  }
  if (u->level>=user->level) {
    write_user(user,"You cannot stat a user of equal or higher level than yourself.\n");
    return;
  }
  if (u->pre_desc[0])
    sprintf(text,"\n~FB*** ~FT%s~FT %s's status~FB ***\n\n",u->pre_desc, u->name);
  else
    sprintf(text,"\n~FB*** ~FT%s's status ~FB***\n\n",u->name);
  write_user(user,text);
}
if (u->invite_room==NULL) strcpy(ir,"<nowhere>");
else strcpy(ir,u->invite_room->name);

sprintf(text,"Level       : %s\t\t\tIgnoring all: %s\n",new_levels[u->sex][u->level],noyes2[u->ignall]);
write_user(user,text);
sprintf(text,"Ign. shouts : %s\t\t\tIgn. tells  : %s\n",noyes2[u->ignshout],noyes2[u->igntell]);
write_user(user,text);
sprintf(text,"Muzzled     : %s\t\t\tUnread mail : %s\n",noyes2[(u->muzzled>0)],noyes2[has_unread_mail(u)]);
write_user(user,text);
sprintf(text,"Char echo   : %s\t\t\tColour      : ~FM%s\n",noyes2[u->charmode_echo],offon[u->colour]);
write_user(user,text);

strcpy(tmp,sex_name[u->sex]);
tmp[0]=(char)toupper((int)tmp[0]);
sprintf(text,"Sex         : %s\t\t\t", tmp);
write_user(user, text);

if (u->figlet)
  write_user(user,"Figlets     : ~FRIgnored\n");
else
  write_user(user,"Figlets     : ~FGAccepted\n");

sprintf(text,"Invited to  : %s\t\t\t",ir);
write_user(user,text);

if (u->old_tell[0]=='\0')
  sprintf(ir,"<no-one>");
else
  strcpy(ir, u->old_tell);

sprintf(text,"<< or >> at : %s\n", ir);
write_user(user,text);

if (u->command_mode)
  sprintf(ir,"~FMEW-Too");
else
  sprintf(ir,"~FTNuts");

sprintf(text,"Mode        : %s~RS\t\t\tExamined    : ~FY%d\n", ir,u->examined);
write_user(user,text);
sprintf(text,"Visible     : %s\t\t\tPrompt      : ~FR%d\n",noyes2[u->vis],u->prompt);
write_user(user,text);

if (u->pre_desc[0])
  sprintf(text,"Description : %s~RS %s %s\nIn phrase   : %s\nOut phrase  : %s\n",u->pre_desc,u->name,u->desc,u->in_phrase,u->out_phrase);
else
  sprintf(text,"Description : %s %s\nIn phrase   : %s\nOut phrase  : %s\n",u->name,u->desc,u->in_phrase,u->out_phrase);
write_user(user,text);

sprintf(text,"Logout      : %s.\nLogin       : %s.\n", u->logout_phrase, u->login_phrase);
write_user(user,text);

mins=(int)(time(0) - u->last_login)/60;
sprintf(text,"Online for  : ~FM%d~RS minutes\n",mins);
days=u->total_login/86400;
hours=(u->total_login%86400)/3600;
mins=(u->total_login%3600)/60;
sprintf(text,"Total login : ~FR%d~RS days, ~FM%d~RS hours, ~FT%d~RS minutes (~FY%d~RS minutes total).\n",days,hours,mins,(u->total_login)/60);
write_user(user,text);
sprintf(text,"Where       : %s",u->ip_name);
write_user(user,text);
if (u->vis_email)
  sprintf(text,"Email       : %s ~FY(Visible)\n", u->email);
else
  sprintf(text,"Email       : %s ~FY(Private)\n", u->email);
write_user(user,text);
sprintf(text,"Homepage    : %s\n",u->www);
write_user(user,text);
sprintf(text,"Terminal    : %s.\n\n", term_names[u->termtype]);
write_user(user,text);
}


/*** Read your mail ***/
rmail(user)
UR_OBJECT user;
{
FILE *infp,*outfp;
int ret;
char c,filename[80],line[DNL+1];

sprintf(filename,"%s/%s.M",USERMAIL,user->name);
if (!(infp=fopen(filename,"r"))) {
  write_user(user,"You have no mail.\n");  return;
}
/* Update last read / new mail recieved time at head of file */
if (outfp=fopen("tempfile","w")) {
  fprintf(outfp,"%d\n",(int)(time(0)));
  /* skip first line of mail file */
  fgets(line,DNL,infp);
  
  /* Copy rest of file */
  c=getc(infp);
  while(!feof(infp)) {  putc(c,outfp);  c=getc(infp);  }
  
  fclose(outfp);
  rename("tempfile",filename);
}
user->read_mail=time(0);
fclose(infp);
write_user(user,"\n~FB*** ~FTYour Mail~FB ***\n\n");
ret=more(user,user->socket,filename);
if (ret==1) user->misc_op=2;
}


/*** Send mail message ***/
smail(user,inpstr,done_editing)
UR_OBJECT user;
char *inpstr;
int done_editing;
{
FILE *fp;
char filename[80];

if (user->muzzled) {
  write_user(user,"You are muzzled, you cannot mail anyone.\n");  return;
}
if (done_editing) {
  send_mail(user,user->mail_to,user->malloc_start);
  user->mail_to[0]='\0';
  return;
}
if (word_count<2) {
  write_user(user,"Smail who?\n");  return;
}

word[1][0]=toupper(word[1][0]);

sprintf(filename,"%s/%s.D",USERFILES,word[1]);
if (!(fp=fopen(filename,"r"))) {
  write_user(user,nosuchuser);  return;
}
fclose(fp);

if (word_count>2) {
  strcpy(text,inpstr);
  strcat(text,"\n");
  send_mail(user,word[1],remove_first(text));
  return;
}

write_user(user,"\n~FB*** ~OLWriting mail message~RS~FB ***\n\n");
user->misc_op=4;
strcpy(user->mail_to,word[1]);
editor(user,NULL);
}


/*** Delete some or all of your mail. A problem here is once we have deleted
  some mail from the file do we mark the file as read? If not we could
  have a situation where the user deletes all his mail but still gets
  the YOU HAVE UNREAD MAIL message on logging in if the idiot forgot to
  read it first. ***/
dmail(user)
UR_OBJECT user;
{
FILE *infp,*outfp;
int num,cnt;
char filename[80],w1[ARR_SIZE],line[ARR_SIZE];

if (word_count<2 || ((num=atoi(word[1]))<1 && strcmp(word[1],"all"))) {
  write_user(user,"Usage: dmail <number of messages>/all\n");  return;
}
sprintf(filename,"%s/%s.M",USERMAIL,user->name);
if (!(infp=fopen(filename,"r"))) {
  write_user(user,"You have no mail to delete.\n");  return;
}
if (!strcmp(word[1],"all")) {
  fclose(infp);
  unlink(filename);
  write_user(user,"All mail deleted.\n");
  return;
}
if (!(outfp=fopen("tempfile","w"))) {
  sprintf(text,"%s: couldn't open tempfile.\n",syserror);
  write_user(user,text);
  write_syslog("ERROR: Couldn't open tempfile in dmail().\n",0);
  fclose(infp);
  return;
}
fprintf(outfp,"%d\n",(int)time(0));
user->read_mail=time(0);
cnt=0; 
fgets(line,DNL,infp); /* Get header date */
fgets(line,ARR_SIZE-1,infp);
while(!feof(infp)) {
  if (cnt<=num) {
    sscanf(line,"%s",w1);
    if (!strcmp(w1,"~OLFrom:~RS"))
      if (++cnt>num) fputs(line,outfp);
  }
  else fputs(line,outfp);
  fgets(line,ARR_SIZE-1,infp);
}
fclose(infp);
fclose(outfp);
unlink(filename);
if (cnt<num) {
  unlink("tempfile");
  sprintf(text,"There were only ~FG%d~RS messages in your mailbox, all now deleted.\n",cnt);
  write_user(user,text);
  return;
}
if (cnt==num) {
  unlink("tempfile"); /* cos it'll be empty anyway */
  write_user(user,"All messages deleted.\n");
  user->room->mesg_cnt=0;
}
else {
  rename("tempfile",filename);
  sprintf(text,"~FR%d~RS messages deleted.\n",num);
  write_user(user,text);
}
}


/*** Show list of people your mail is from without seeing the whole lot ***/
mail_from(user)
UR_OBJECT user;
{
FILE *fp;
int cnt;
char w1[ARR_SIZE],line[ARR_SIZE],filename[80];

sprintf(filename,"%s/%s.M",USERMAIL,user->name);
if (!(fp=fopen(filename,"r"))) {
  write_user(user,"You have no mail.\n");  return;
}
write_user(user,"\n~FB*** ~FTMail From~FB ***\n\n");
cnt=0;
fgets(line,DNL,fp);
fgets(line,ARR_SIZE-1,fp);
while(!feof(fp)) {
  sscanf(line,"%s",w1);
  if (!strcmp(w1,"~OLFrom:~RS")) {
    write_user(user,remove_first(line));
    cnt++; 
  }
  fgets(line,ARR_SIZE-1,fp);
}
fclose(fp);
sprintf(text,"\nTotal of ~FG%d~RS messages.\n\n",cnt);
write_user(user,text);
}


/*** Enter user profile ***/
enter_profile(user,done_editing)
UR_OBJECT user;
int done_editing;
{
FILE *fp;
char *c,filename[80];

if (!done_editing) {
  if (user->vis) {
    sprintf(text,"%s starts to enter a new profile.\n",user->name);
    write_room_except(user->room,text,user);
  }
  
  write_user(user,"\n~FB** ~FTWriting Profile~FB ***\n\n");
  user->misc_op=5;
  editor(user,NULL);
  return;
}
sprintf(filename,"%s/%s.P",USERFILES,user->name);
if (!(fp=fopen(filename,"w"))) {
  sprintf(text,"%s: couldn't save your profile.\n",syserror);
  write_user(user,text);
  sprintf("ERROR: Couldn't open file %s to write in enter_profile().\n",filename);
  write_syslog(text,0);
  return;
}
c=user->malloc_start;
while(c!=user->malloc_end) putc(*c++,fp);
fclose(fp);
write_user(user,"Profile stored.\n");
if (user->vis) {
  sprintf(text,"%s has entered a new profile!\n",user->name);
  write_room_except(user->room,text,user);
}
}


/*** Examine a user ***/
examine(user)
UR_OBJECT user;
{
UR_OBJECT u;
FILE *fp;
char filename[80],line[82],afk[6],tmp[10], last_site[82];
int last_login,total_login,last_read,new_mail,level,loglen;
int days,hours,mins,ago,onfor,days2,hours2,mins2,idle,sex;
int tmpp,colour,figs, semail,exam,cnt=0;
char pd[81],email[81],www[81],desc[81],rank[21];

if (word_count<2) {
  write_user(user,"Examine who?\n");  return;
}

/* If logged on inform user they have been examined */
if ((u=get_user(word[1])) && (u!=user)) {
  sprintf(text,"~OL%s~RS examines you with a ~FRbeady~RS eye!\n",user->name);
  write_user(u,text);
  u->examined++;
	
  if (!save_newbies) {
    if (u->level==NEW) {
      sprintf(text,"%s does not have an account here, tell them to get one!\n",u->name);
      write_user(user,text);
      return;
    }
  }
}

if (!strcmp("Me",word[1]) || !strcmp("ME",word[1]))
  strcpy(word[1],user->name);
else
  if (u)
    strcpy(word[1],u->name);

word[1][0]=toupper(word[1][0]);
sprintf(filename,"%s/%s.D",USERFILES,word[1]);

if (!(fp=fopen(filename,"r"))) {
	write_user(user,"There is no such user!\n");
	return;
	}
else fscanf(fp,"%s\n%d %d %d %d %d",line,&last_login,&total_login,&loglen,&last_read,&level);
					
fscanf(fp,"%d %d %d %d %d %d %d %d %d %d %d\n",&tmpp,&tmpp,&tmpp,&tmpp,&colour,&sex,&tmpp,&tmpp,&figs,&semail,&exam);
fscanf(fp,"%s\n",last_site);

pd[0]='\0';
fgets(line,80,fp);
line[strlen(line)-1]=0;
strcpy(pd,line);
fgets(line,80,fp);
line[strlen(line)-1]=0;
strcpy(desc,line);
fgets(line,PHRASE_LEN+2,fp);
fgets(line,PHRASE_LEN+2,fp);
fgets(line,LOG_PHRASE_LEN+2,fp);
fgets(line,LOG_PHRASE_LEN+2,fp);
fscanf(fp,"%s\n",email);
fscanf(fp,"%s\n",www);
fgets(line,37,fp);
line[strlen(line)-1]=0;
strcpy(rank,line);
fclose(fp);

if (!strncmp("none",pd,4))
  pd[0]='\0';

sprintf(filename,"%s/%s.M",USERMAIL,word[1]);
if (!(fp=fopen(filename,"r"))) new_mail=0;
else {
  fscanf(fp,"%d",&new_mail);
  fclose(fp);
}

/* If user isn't logged in at the moment... */
if (!(u=get_user(word[1])) || u->login) {

  if (pd[0])
    sprintf(text,"\n~FB*** ~FT%s~RS~FT %s %s~RS ~FB***\n\n",pd,word[1],desc);
  else
    sprintf(text,"\n~FB*** ~FT%s %s~RS ~FB***\n\n",word[1],desc);
  write_user(user,text);

  sprintf(filename,"%s/%s.P",USERFILES,word[1]);
  if (!(fp=fopen(filename,"r"))) 
    write_user(user,"No profile - Ask them to use ~FG.entpro~RS\n");
  else {
    fgets(line,81,fp);
    while(!feof(fp)) {
      write_user(user,line);
      fgets(line,81,fp);
    }
    fclose(fp);
  }

  days=total_login/86400;
  hours=(total_login%86400)/3600;
  mins=(total_login%3600)/60;
  ago=(int)(time(0)-last_login);
  days2=ago/86400;
  hours2=(ago%86400)/3600;
  mins2=(ago%3600)/60;
  
  strcpy(tmp,sex_name[sex]);
  tmp[0]=(char)toupper((int)tmp[0]);
  
  if (strcmp(new_levels[sex][level],rank)) {
    sprintf(line,"%s (%s~RS)",new_levels[sex][level],rank);
    cnt=colour_com_count(rank)+3;
  }
  else 
    sprintf(line,"%s",new_levels[sex][level]);

    sprintf(text,"\nLevel       : %-*s Sex         : %s\n",cnt+25,line,tmp);

  write_user(user,text);
  
  if (figs)
    write_user(user,"Figlets     : ~FRIgnored\t\t\t");
  else
    write_user(user,"Figlets     : ~FGAccepted\t\t\t");
  
  sprintf(text,"Colour      : ~FT%s\n",offon[colour]);
  write_user(user,text); 
  
  sprintf(text,"Examined    : ~FM%d~RS times\n",exam);
  write_user(user,text);
	
  sprintf(text,"Last login  : %s",ctime((time_t *)&last_login));
  write_user(user,text);
  
  sprintf(text,"Which was   : ~FY%d~RS days, ~FR%d~RS hours, ~FT%d~RS minutes ago\n",days2,hours2,mins2);
  write_user(user,text);
  sprintf(text,"Was on for  : ~FG%d~RS hours, ~FM%d~RS minutes\nTotal login : ~FR%d~RS days, ~FM%d~RS hours, ~FG%d~RS minutes (~FY%d~RS minutes total).\n",loglen/3600,(loglen%3600)/60,days,hours,mins,total_login/60);
  write_user(user,text);
  
  if (user->level>=GOD) {
    if (semail)
      sprintf(text,"Email       : %s ~FY(Visible)\n", email);
    else
      sprintf(text,"Email       : %s ~FY(Private)\n", email);
  }
  else
    if (semail)
      sprintf(text,"Email       : %s\n", email);
    else
      sprintf(text,"Email       : <Hidden>\n");
  
  write_user(user,text);
  
  sprintf(text,"Homepage    : %s\n",www);
  write_user(user,text);
  
  if (user->level>=GOD) {
    sprintf(text,"Last site   : %s\n",last_site);
    write_user(user,text);
  }
  
  if (new_mail>last_read) {
    sprintf(text,"%s has ~OLunread~RS mail.\n",word[1]);
    write_user(user,text);
  }
  
  write_user(user,"\n");
  
  /* Update examined user */
  if ((u=create_user())==NULL) {
    sprintf(text,"%s: unable to create temporary user object.\n",syserror);
    write_user(user,text);
    write_syslog("ERROR: Unable to create temporary user object in examine().\n",0);
    return;
  }
  
  strcpy(u->name,word[1]);
  if (!load_user_details(u)) {
    write_user(user,nosuchuser);
    destruct_user(u);
    destructed=0;
    return;
  }
  
  u->examined++;
  u->socket=-2;
  strcpy(u->site,u->last_site);
  save_user_details(u,0);
  destruct_user(u);
  destructed=0;
  
  return;
}

/* User is currently logged in... */
if (u->pre_desc[0])
  sprintf(text,"\n~FB*** ~FT%s~RS~FT %s %s~RS ~FB***\n\n",u->pre_desc,word[1],u->desc);
else
  sprintf(text,"\n~FB*** ~FT%s %s~RS ~FB***\n\n",word[1],u->desc);
write_user(user,text);

sprintf(filename,"%s/%s.P",USERFILES,word[1]);
if (!(fp=fopen(filename,"r"))) 
  write_user(user,"No profile - Ask them to use ~FG.entpro~RS\n");
else {
  fgets(line,81,fp);
  while(!feof(fp)) {
    write_user(user,line);
    fgets(line,81,fp);
  }
  fclose(fp);
}

days=u->total_login/86400;
hours=(u->total_login%86400)/3600;
mins=(u->total_login%3600)/60;
onfor=(int)(time(0) - u->last_login);
hours2=(onfor%86400)/3600;
mins2=(onfor%3600)/60;
if (u->afk) strcpy(afk,"~FY(~FRAFK~FY)"); else afk[0]='\0';
idle=(int)(time(0) - u->last_input)/60;

strcpy(tmp,sex_name[u->sex]);
tmp[0]=(char)toupper((int)tmp[0]);

if (strcmp(new_levels[u->sex][u->level],u->rank)) {
  sprintf(line,"%s (%s~RS)",new_levels[u->sex][u->level],u->rank);
  cnt=colour_com_count(u->rank)+3;
}
else 
  sprintf(line,"%s",new_levels[u->sex][u->level]);

sprintf(text,"\nLevel       : %-*s Sex         : %s\n",cnt+25,line,tmp);
write_user(user,text);

if (u->figlet)
  write_user(user,"Figlets     : ~FRIgnored\t\t\t");
else
  write_user(user,"Figlets     : ~FGAccepted\t\t\t");

sprintf(text,"Colour      : ~FT%s\n",offon[u->colour]);
write_user(user,text); 
sprintf(text,"Ign. shouts : %s\t\t\tIgn. tells  : %s\n",noyes2[u->ignshout],noyes2[u->igntell]);
write_user(user,text);
sprintf(text,"Ignoring all: %s\t\t\tExamined    : ~FY%d~RS times\n",noyes2[u->ignall],u->examined);
write_user(user,text);

if (u==user || user->level>=GOD) {
  if (u->vis_email)
    sprintf(text,"Email       : %s ~FY(Visible)\n", u->email);
  else
    sprintf(text,"Email       : %s ~FY(Private)\n", u->email);
}
else
  if (u->vis_email)
    sprintf(text,"Email       : %s\n", u->email);
  else
    sprintf(text,"Email       : <Hidden>\n");

write_user(user,text);

sprintf(text,"Homepage    : %s\n",u->www);
write_user(user,text);

sprintf(text,"Where       : %s",u->ip_name);
write_user(user,text);  

if (u==user || user->level>=GOD) {
  sprintf(text,"Site        : %s\n",u->site);
  write_user(user,text);
}

sprintf(text,"On since    : %sOn for      : ~FM%d~RS hours, ~FR%d~RS minutes\t",ctime((time_t *)&u->last_login),hours2,mins2);
write_user(user,text);
sprintf(text,"Idle for    : ~FG%d~RS minutes ~FR%s~RS\nTotal login : ~FR%d~RS days, ~FM%d~RS hours, ~FG%d~RS minutes (~FY%d~RS minutes total).\n",idle,afk,days,hours,mins,(u->total_login)/60);
write_user(user,text);

if (new_mail>u->read_mail) {
  sprintf(text,"%s has ~OLunread~RS mail.\n",word[1]);
  write_user(user,text);
}
write_user(user,"\n");
}


/*** Show talker rooms ***/
rooms(user)
UR_OBJECT user;
{
RM_OBJECT rm;
UR_OBJECT u;
char access[9];
int cnt;

write_user(user,"\n~FB*** ~FTRooms data~FB ***\n\n~ULRoom name      : Access Users Mesgs  Topic\n");

for(rm=room_first;rm!=NULL;rm=rm->next) {
  switch (rm->access) {
  case PRIVATE: 
  case FIXED_PRIVATE: 
    strcpy(access," ~FRPRIV"); break;
  case PUBLIC: 
  case FIXED_PUBLIC:
    strcpy(access,"  ~FGPUB"); break;
  default:
    strcpy(access," ~FMUSER"); break;
  }

  if (rm->access & 2) access[0]='*';
  cnt=0;
  for(u=user_first;u!=NULL;u=u->next)
    if (u->room==rm) ++cnt;
  
  sprintf(text,"%-14s : %9s~RS   %3d   %3d  %s\n",rm->name,access,cnt,rm->mesg_cnt,rm->topic);
  
  write_user(user,text);
}
write_user(user,"\n");
}


/*** Change users password. Only Ubergoths :) can change another users 
  password and they do this by specifying the user at the end. When this is 
  done the old password given can be anything, the wiz doesnt have to know it
  in advance. ***/
change_pass(user)
UR_OBJECT user;
{
UR_OBJECT u;

if (word_count<3) {
  write_user(user,"Usage: passwd <old password> <new password> [<user>]\n");
  return;
}
if (strlen(word[2])<3) {
  write_user(user,"New password too short.\n");  return;
}
if (strlen(word[2])>PASS_LEN) {
  write_user(user,"New password too long.\n");  return;
}

/* Change own password */
if (word_count==3) {
  if (strcmp((char *)crypt(word[1],"NU"),user->pass)) {
    write_user(user,"Old password incorrect.\n");  return;
  }
  if (!strcmp(word[1],word[2])) {
    write_user(user,"Old and new passwords are the same.\n");  return;
  }
  strcpy(user->pass,(char *)crypt(word[2],"NU"));
  save_user_details(user,0);
  sprintf(text,"Password changed to \"%s\".\n",word[2]);
  write_user(user,text);
  return;
}
/* Change someone elses */
if (user->level<=GOD) {
  write_user(user,"You are not a high enough level to use the <user> option.\n");  
  return;
}
word[3][0]=toupper(word[3][0]);
if (!strcmp(word[3],user->name)) {
  /* security feature  - prevents someone coming to a wizes terminal and 
     changing his password since he wont have to know the old one */
  write_user(user,"You cannot change your own password using the <user> option.\n");
  return;
	}
if (u=get_user(word[3])) {
  if (u->level>=user->level) {
    write_user(user,"You cannot change the password of a user of equal or higher level than yourself!\n");
    return;
  }
  strcpy(u->pass,(char *)crypt(word[2],"NU"));
  sprintf(text,"%s's password changed to \"%s\".\n",word[3],word[2]);
  write_user(user,text);
  return;
}
if ((u=create_user())==NULL) {
  sprintf(text,"%s: unable to create temporary user object.\n",syserror);
  write_user(user,text);
  write_syslog("ERROR: Unable to create temporary user object in change_pass().\n",0);
  return;
	}
strcpy(u->name,word[3]);
if (!load_user_details(u)) {
  write_user(user,nosuchuser);   
  destruct_user(u);
  destructed=0;
  return;
}
if (u->level>=user->level) {
  write_user(user,"You cannot change the password of a user of equal or higher level than yourself!\n");
  destruct_user(u);
  destructed=0;
  return;
}
strcpy(u->pass,(char *)crypt(word[2],"NU"));
save_user_details(u,0);
destruct_user(u);
destructed=0;
sprintf(text,"%s's password changed to \"%s\".\n",word[3],word[2]);
write_user(user,text);
}


/*** Kill a user ***/
kill_user(user)
UR_OBJECT user;
{
UR_OBJECT victim;
RM_OBJECT rm;
char *name;

if (word_count<2) {
  write_user(user,"Usage: kill user\n");  return;
}
if (!(victim=get_user_by_full(word[1]))) {
  write_user(user,notloggedon);  return;
}
if (user==victim) {
  write_user(user,"Trying to commit suicide this way is the sixth sign of madness.\n");
  return;
}
if (victim->level>=user->level) {
  write_user(user,"You cannot kill a user of equal or higher level than yourself!\n");
  sprintf(text,"~OL%s~RS tried to kill you!\n",user->name);
  write_user(victim,text);
  return;
}
sprintf(text,"%s ~FRKILLED~RS %s.\n",user->name,victim->name);
write_syslog(text,1);

if (user->vis) name=user->name; else name=invisname;

/* Personalised kill's... */
if (!strcmp(user->name,"Werewolf")) {
  sprintf(text,"~FM%s growls and snarls...\n",name);
  write_room_except(user->room,text,user);
  write_user(user,"~FMYou growl and snarl...\n");
  write_user(victim,"~FMYour head is ripped from you body, and crushed into the ground by Werewolf!!!\n");
  sprintf(text,"~FM%s's head is ripped from their body, and crushed into the ground by Werewolf!!!\n",victim->name);
  rm=victim->room;
  write_room_except(rm,text,victim);
  victim->autologout=2;
  disconnect_user(victim);
  write_room(NULL,"~FMWerewolf grins and snarls evily at the decapitated body...\n");
  return;
}

if (!strcmp(user->name,"Funky")) {
  sprintf(text,"~FM%s gets his razor edged guitar out...\n",name);
  write_room_except(user->room,text,user);
  write_user(user,"~FMYou get your razor edged guitar out...\n");
  write_user(victim,"~FMYou get power chorded out of existance!!!\n");
  sprintf(text,"~FM%s gets power chorded out of existance!!!\n",victim->name);
  rm=victim->room;
  write_room_except(rm,text,victim);
  victim->autologout=2;
  disconnect_user(victim);
  write_room(NULL,"~FMFunky restrings for the next kill...\n");
  return;
}

if (!strcmp(user->name,"Mish")) {
  sprintf(text,"~FM%s produces a large ~OLGothic Axe~RS~FM...\n",name);
  write_room_except(user->room,text,user);
  write_user(user,"~FMYou get your gothic axe out...\n");
  write_user(victim,"~FMMish cleaves your skull with his Gothic Axe!!!\n");
  sprintf(text,"~FM%s gets their skull cleaved open by Mish's Gothic Axe!!!\n",victim->name);
  rm=victim->room;
  write_room_except(rm,text,victim);
  victim->autologout=2;
  disconnect_user(victim);
  write_room(NULL,"~FMMish wipes the rapidly congealing blood from his Axe...\n");
  return;
}

if (!strcmp(user->name,"Uggi")) {
  sprintf(text,"~FM%s's hair stands on end...\n",name);
  write_room_except(user->room,text,user);
  write_user(user,"~FMYour hair stands on end...\n");
  write_user(victim,"~FMUggi gores you to death on her shiny tusks then tramples your mangled remains into the ground under her four woolly feet!!!\n");
  sprintf(text,"~FM%s is gored to death by Uggi's shiny tusks then trampled into the ground under her woolly feet!!!\n",victim->name); 
  rm=victim->room;
  write_room_except(rm,text,victim);
  victim->autologout=2;
  disconnect_user(victim);
  write_room(NULL,"~FMUggi stomps off...\n");
  return;
}

sprintf(text,"~FM%s chants an evil incantation...\n",name);
write_room_except(user->room,text,user);
write_user(user,"~FMYou chant an evil incantation...\n");
write_user(victim,"~FM~OLA shrieking furie rises up out of the ground, and devours you!!!\n");
sprintf(text,"~FMA shrieking furie rises up out of the ground, devours %s and vanishes!!!\n",victim->name);
rm=victim->room;
write_room_except(rm,text,victim);
victim->autologout=2;
disconnect_user(victim);
write_room(NULL,"~FMYou hear insane laughter from the beyond the grave...\n");
}


/*** Promote a user ***/
promote(user)
UR_OBJECT user;
{
UR_OBJECT u;
char text2[80];

if (word_count<2) {
  write_user(user,"Usage: promote <user>\n");  return;
}
/* See if user is on atm */
if ((u=get_user(word[1]))!=NULL) {
  if (u->level>=user->level) {
    write_user(user,"You cannot promote a user to a level higher than your own.\n");
    return;
  }

  if ((u->level==USER || u->level==WIZ) && user->level==ARCH) {
    write_user(user,"Users of your level can only promote people to user level.\n");
    return;
  }

  if (!strcmp(new_levels[u->sex][u->level],u->rank))
    strcpy(u->rank,new_levels[u->sex][u->level+1]);

  u->level++;
  sprintf(text,"~FGYou promote %s to level: ~RS~OL%s.\n",u->name,new_levels[u->sex][u->level]);
  write_user(user,text);

  sprintf(text,"~FG%s promotes %s to level:~RS~OL %s.\n",user->name,u->name,new_levels[u->sex][u->level]);
  write_room_except2(user->room,text,u,user);
  
  sprintf(text,"~FG~OL%s has promoted you to level: ~RS~OL%s!\n",user->name,new_levels[u->sex][u->level]);
  write_user(u,text);

  if (u->level==USER) {
    write_user(u,"Type ~FG'.help newuser'~RS for information on setting up your account.\n");
    save_user_details(u);
  }
  
  sprintf(text,"%s ~FGPROMOTED~RS %s to level %s.\n",user->name,u->name,new_levels[u->sex][u->level]);
  write_syslog(text,1);
  return;
}
/* Create a temp session, load details, alter , then save. This is inefficient
   but its simpler than the alternative */
if ((u=create_user())==NULL) {
  sprintf(text,"%s: unable to create temporary user object.\n",syserror);
  write_user(user,text);
  write_syslog("ERROR: Unable to create temporary user object in promote().\n",0);
  return;
}
strcpy(u->name,word[1]);
if (!load_user_details(u)) {
  write_user(user,nosuchuser);
  destruct_user(u);
  destructed=0;
  return;
}
if (u->level>=user->level) {
  write_user(user,"You cannot promote a user to a level higher than your own.\n");
  destruct_user(u);
  destructed=0;
  return;
}
if ((u->level==USER || u->level==WIZ) && user->level==ARCH) {
  write_user(user,"Users of your level can only promote people to user level.\n");
  return;
}

if (!strcmp(new_levels[u->sex][u->level],u->rank))
  strcpy(u->rank,new_levels[u->sex][u->level+1]);
u->level++;
u->socket=-2;
strcpy(u->site,u->last_site);
save_user_details(u,0);
sprintf(text,"~FGYou promote %s to level: ~RS~OL%s.\n",u->name,new_levels[u->sex][u->level]);
write_user(user,text);
sprintf(text2,"~FG~OLYou have been promoted to level: ~RS~OL%s.\n",new_levels[u->sex][u->level]);
send_mail(user,word[1],text2);
if (u->level==1) {
  sprintf(text,"Type ~FG'.help newuser'~RS for information on setting up your account.\n");
  send_mail(user,word[1],text2);
}

sprintf(text,"%s ~FGPROMOTED~RS %s to level %s.\n",user->name,word[1],new_levels[u->sex][u->level]);
write_syslog(text,1);
destruct_user(u);
destructed=0;
}


/*** Demote a user ***/
demote(user)
UR_OBJECT user;
{
UR_OBJECT u;
char text2[80];

if (word_count<2) {
	write_user(user,"Usage: demote <user>\n");  return;
	}
/* See if user is on atm */
if ((u=get_user(word[1]))!=NULL) {
  if (u->level==NEW) {
    write_user(user,"You cannot demote a user of level NEW.\n");
    return;
  }
  if (u==user) {
    if (!strcmp(new_levels[u->sex][u->level],u->rank))
      strcpy(u->rank,new_levels[u->sex][u->level-1]);
    user->level--;
    sprintf(text,"You demote yourself to level:~OL %s\n",new_levels[u->sex][u->level]);
    write_user(user,text);
    return;
  }
  if (u->level>=user->level) {
    write_user(user,"You cannot demote a user of an equal or higher level than yourself.\n");
    return;
  }

  if (!strcmp(new_levels[u->sex][u->level],u->rank))
    strcpy(u->rank,new_levels[u->sex][u->level-1]);

  u->level--;
  sprintf(text,"~FRYou demote %s to level: ~RS~OL%s.\n",u->name,new_levels[u->sex][u->level]);
  write_user(user,text);

  sprintf(text,"~FR%s demotes %s to level: ~RS~OL%s.\n",user->name,u->name,new_levels[u->sex][u->level]);
  write_room_except2(user->room,text,u,user);

  sprintf(text,"~FR~OL%s has demoted you to level: ~RS~OL%s!\n",user->name,new_levels[u->sex][u->level]);
  write_user(u,text);
  sprintf(text,"%s ~FRDEMOTED~RS %s to level %s.\n",user->name,u->name,new_levels[u->sex][u->level]);
  write_syslog(text,1);
  return;
}

/* User not logged on */
if ((u=create_user())==NULL) {
  sprintf(text,"%s: unable to create temporary user object.\n",syserror);
  write_user(user,text);
  write_syslog("ERROR: Unable to create temporary user object in demote().\n",0);
  return;
}
strcpy(u->name,word[1]);
if (!load_user_details(u)) {
  write_user(user,nosuchuser);
  destruct_user(u);
  destructed=0;
  return;
}
if (u->level==NEW) {
  write_user(user,"You cannot demote a user of level NEW.\n");
  destruct_user(u);
  destructed=0;
  return;
}
if (u->level>=user->level) {
  write_user(user,"You cannot demote a user of an equal or higher level than yourself.\n");
  destruct_user(u);
  destructed=0;
  return;
}
if (!strcmp(new_levels[u->sex][u->level],u->rank))
  strcpy(u->rank,new_levels[u->sex][u->level-1]);
u->level--;
u->socket=-2;
strcpy(u->site,u->last_site);
save_user_details(u,0);
sprintf(text,"~FRYou demote %s to level: ~RS~OL%s.\n",u->name,new_levels[u->sex][u->level]);
write_user(user,text);
sprintf(text2,"~FR~OLYou have been demoted to level: ~RS~OL%s.\n",new_levels[u->sex][u->level]);
send_mail(user,word[1],text2);
sprintf(text,"%s ~FRDEMOTED~RS %s to level %s.\n",user->name,word[1],new_levels[u->sex][u->level]);
write_syslog(text,1);
destruct_user(u);
destructed=0;
}


/*** List banned sites or users ***/
listbans(user)
UR_OBJECT user;
{
char filename[80];
int i=0;

if (!strcmp(word[1],"partial")) {
  write_user(user,"\n~FB*** ~FTPartially banned sites/domains~FB ***\nAccount users can log in from here but new users cannot be created.\n\n");
  sprintf(filename,"%s/%s",DATAFILES,PARTIAL_SITEBAN);
  switch(more(user,user->socket,filename)) {
  case 0:
    write_user(user,"There are no partially banned sites/domains.\n\n");
    return;
    
  case 1: user->misc_op=2;
  }
  return;
}

if (!strcmp(word[1],"sites")) {
  write_user(user,"\n~FB*** ~FTBanned sites/domains~FB ***\nSee also partial bans.\n\n"); 
  sprintf(filename,"%s/%s",DATAFILES,SITEBAN);
  switch(more(user,user->socket,filename)) {
  case 0:
    write_user(user,"There are no banned sites/domains.\n\n");
    return;
    
  case 1: user->misc_op=2;
  }
  return;
}
if (!strcmp(word[1],"users")) {
  write_user(user,"\n~FB*** ~FTBanned users~FB ***\n\n");
  sprintf(filename,"%s/%s",DATAFILES,USERBAN);
  switch(more(user,user->socket,filename)) {
  case 0:
    write_user(user,"There are no banned users.\n\n");
    return;
    
  case 1: user->misc_op=2;
  }
  return;
}

if (!strcmp(word[1],"words")) {
  write_user(user,"\n~FB*** ~FTBanned words~FB ***\n\n");

  if (ban_swearing)
    sprintf(text,"Swearing ban currently switched: ~FRON\n");
  else
    sprintf(text,"Swearing ban currently switched: ~FGOFF\n");
  
  write_user(user,text);
  write_user(user,"Current banned words are: ");
  while(swear_words[i][0]!='*') {
    sprintf(text,"~FR%s ", swear_words[i]);
    write_user(user,text);
    i++;
  }
  write_user(user,"\n");
  return;
}

write_user(user,"Usage: listbans sites/partial/users/words\n"); 
}


/*** Ban a site (or domain) or user ***/
ban(user)
UR_OBJECT user;
{
char *usage="Usage: ban site/partial/user <site/site/user name>\n";

if (word_count<3) {
  write_user(user,usage);  return;
}
if (!strcmp(word[1],"site")) {  ban_site(user);  return;  }
if (!strcmp(word[1],"user")) {  ban_user(user);  return;  }
if (!strcmp(word[1],"partial")) {  ban_partial(user);  return;  }
write_user(user,usage);
}

/** Ban site ***/
ban_site(user)
UR_OBJECT user;
{
FILE *fp;
char filename[80],host[81],site[80];

gethostname(host,80);
if (!strcmp(word[2],host)) {
  write_user(user,"You cannot ban the machine that this program is running on.\n");
  return;
}
sprintf(filename,"%s/%s",DATAFILES,SITEBAN);

/* See if ban already set for given site */
if (fp=fopen(filename,"r")) {
  fscanf(fp,"%s",site);
  while(!feof(fp)) {
    if (!strcmp(site,word[2])) {
      write_user(user,"That site/domain is already banned.\n");
      fclose(fp);  return;
    }
    fscanf(fp,"%s",site);
  }
  fclose(fp);
}

/* Write new ban to file */
if (!(fp=fopen(filename,"a"))) {
  sprintf(text,"%s: Can't open file to append.\n",syserror);
  write_user(user,text);
  write_syslog("ERROR: Couldn't open file to append in ban_site().\n",0);
  return;
}
fprintf(fp,"%s\n",word[2]);
fclose(fp);
write_user(user,"Site/domain banned.\n");
sprintf(text,"%s ~FRBANNED~RS site/domain %s\n",user->name,word[2]);
write_syslog(text,1);
sprintf(text,"~OLSYSTEM:~RS %s bans connections from %s\n",user->name,word[2]);
write_room_except(NULL,text,user);
}


/*** Partial ban ***/
ban_partial(user)
UR_OBJECT user;
{
FILE *fp;
char filename[80],host[81],site[80];

sprintf(filename,"%s/%s",DATAFILES,PARTIAL_SITEBAN);

/* See if ban already set for given site */
if (fp=fopen(filename,"r")) {
  fscanf(fp,"%s",site);
  while(!feof(fp)) {
    if (!strcmp(site,word[2])) {
      write_user(user,"That site/domain is already banned.\n");
      fclose(fp);  return;
    }
    fscanf(fp,"%s",site);
  }
  fclose(fp);
}

/* Write new ban to file */
if (!(fp=fopen(filename,"a"))) {
  sprintf(text,"%s: Can't open file to append.\n",syserror);
  write_user(user,text);
  write_syslog("ERROR: Couldn't open file to append in ban_site().\n",0);
  return;
}
fprintf(fp,"%s\n",word[2]);
fclose(fp);
write_user(user,"Site/domain banned.\n");
sprintf(text,"%s ~FRPARTIALLY BANNED~RS site/domain %s\n",user->name,word[2]);
write_syslog(text,1);
sprintf(text,"~OLSYSTEM:~RS %s partially bans connections from %s\n",user->name,word[2]);
write_room_except(NULL,text,user);
}


/*** Ban user ***/
ban_user(user)
UR_OBJECT user;
{
UR_OBJECT u;
FILE *fp;
char filename[80],filename2[80],p[20],name[USER_NAME_LEN+1];
int a,b,c,d,level;

word[2][0]=toupper(word[2][0]);
if (!strcmp(user->name,word[2])) {
  write_user(user,"Trying to ban yourself is the seventh sign of madness.\n");
  return;
}

/* See if ban already set for given user */
sprintf(filename,"%s/%s",DATAFILES,USERBAN);
if (fp=fopen(filename,"r")) {
  fscanf(fp,"%s",name);
  while(!feof(fp)) {
    if (!strcmp(name,word[2])) {
      write_user(user,"That user is already banned.\n");
      fclose(fp);  return;
    }
    fscanf(fp,"%s",name);
  }
  fclose(fp);
}

/* See if already on */
if ((u=get_user(word[2]))!=NULL) {
  if (u->level>=user->level) {
    write_user(user,"You cannot ban a user of equal or higher level than yourself.\n");
    return;
  }
}
else {
  /* User not on so load up his data */
  sprintf(filename2,"%s/%s.D",USERFILES,word[2]);
  if (!(fp=fopen(filename2,"r"))) {
    write_user(user,nosuchuser);  return;
  }
  fscanf(fp,"%s\n%d %d %d %d %d",p,&a,&b,&c,&d,&level);
  fclose(fp);
  if (level>=user->level) {
    write_user(user,"You cannot ban a user of equal or higher level than yourself.\n");
    return;
  }
}

/* Write new ban to file */
if (!(fp=fopen(filename,"a"))) {
  sprintf(text,"%s: Can't open file to append.\n",syserror);
  write_user(user,text);
  write_syslog("ERROR: Couldn't open file to append in ban_user().\n",0);
  return;
}
fprintf(fp,"%s\n",word[2]);
fclose(fp);
write_user(user,"User banned.\n");
sprintf(text,"%s ~FRBANNED~RS user %s.\n",user->name,word[2]);
write_syslog(text,1);
sprintf(text,"~OLSYSTEM:~RS %s bans %s from this talker.\n",user->name,word[2]);
write_room_except(NULL,text,user);
if (u!=NULL) {
  write_user(u,"\n\07~FR~OL~LIYou have been banned from here!\n\n");
  disconnect_user(u);
}
}

	
/*** unban a site (or domain) or user ***/
unban(user)
UR_OBJECT user;
{
char *usage="Usage: unban site/partial/user site/site/user name>\n";

if (word_count<3) {
  write_user(user,usage);  return;
}
if (!strcmp(word[1],"site")) {  unban_site(user);  return;  }
if (!strcmp(word[1],"user")) {  unban_user(user);  return;  }
if (!strcmp(word[1],"partial")) {  unban_partial(user);  return;  }
write_user(user,usage);
}

/*** Unban a site ***/
unban_site(user)
UR_OBJECT user;
{
FILE *infp,*outfp;
char filename[80],site[80];
int found,cnt;

sprintf(filename,"%s/%s",DATAFILES,SITEBAN);
if (!(infp=fopen(filename,"r"))) {
  write_user(user,"That site/domain is not currently banned.\n");
  return;
}
if (!(outfp=fopen("tempfile","w"))) {
  sprintf(text,"%s: Couldn't open tempfile.\n",syserror);
  write_user(user,text);
  write_syslog("ERROR: Couldn't open tempfile to write in unban_site().\n",0);
  fclose(infp);
  return;
}
found=0;   cnt=0;
fscanf(infp,"%s",site);
while(!feof(infp)) {
  if (strcmp(word[2],site)) {  
    fprintf(outfp,"%s\n",site);  cnt++;  
  }
  else found=1;
  fscanf(infp,"%s",site);
}
fclose(infp);
fclose(outfp);
if (!found) {
  write_user(user,"That site/domain is not currently banned.\n");
  unlink("tempfile");
  return;
}
if (!cnt) {
  unlink(filename);  unlink("tempfile");
}
else rename("tempfile",filename);
write_user(user,"Site ban removed.\n");
sprintf(text,"%s ~FGUNBANNED~RS site/domain %s\n",user->name,word[2]);
write_syslog(text,1);
sprintf(text,"~OLSYSTEM:~RS %s unbans connections from %s\n",user->name,word[2]);
write_room_except(NULL,text,user);
}


/*** Unban a site from new logins ***/
unban_partial(user)
UR_OBJECT user;
{
FILE *infp,*outfp;
char filename[80],site[80];
int found,cnt;

sprintf(filename,"%s/%s",DATAFILES,PARTIAL_SITEBAN);
if (!(infp=fopen(filename,"r"))) {
  write_user(user,"That site/domain is not currently banned.\n");
  return;
}
if (!(outfp=fopen("tempfile","w"))) {
  sprintf(text,"%s: Couldn't open tempfile.\n",syserror);
  write_user(user,text);
  write_syslog("ERROR: Couldn't open tempfile to write in unban_partial().\n",0);
  fclose(infp);
  return;
}
found=0;   cnt=0;
fscanf(infp,"%s",site);
while(!feof(infp)) {
  if (strcmp(word[2],site)) {  
    fprintf(outfp,"%s\n",site);  cnt++;  
  }
  else found=1;
  fscanf(infp,"%s",site);
}
fclose(infp);
fclose(outfp);
if (!found) {
  write_user(user,"That site/domain is not currently banned.\n");
  unlink("tempfile");
  return;
}
if (!cnt) {
  unlink(filename);  unlink("tempfile");
}
else rename("tempfile",filename);
write_user(user,"Site ban removed.\n");
sprintf(text,"%s ~FGUNBANNED~RS site/domain %s\n",user->name,word[2]);
write_syslog(text,1);
sprintf(text,"~OLSYSTEM:~RS %s unbans connections from %s\n",user->name,word[2]);
write_room_except(NULL,text,user);
}


/*** Ban a user ***/
unban_user(user)
UR_OBJECT user;
{
FILE *infp,*outfp;
char filename[80],name[USER_NAME_LEN+1];
int found,cnt;

sprintf(filename,"%s/%s",DATAFILES,USERBAN);
if (!(infp=fopen(filename,"r"))) {
  write_user(user,"That user is not currently banned.\n");
  return;
}
if (!(outfp=fopen("tempfile","w"))) {
  sprintf(text,"%s: Couldn't open tempfile.\n",syserror);
  write_user(user,text);
  write_syslog("ERROR: Couldn't open tempfile to write in unban_user().\n",0);
  fclose(infp);
  return;
}
found=0;  cnt=0;
word[2][0]=toupper(word[2][0]);
fscanf(infp,"%s",name);
while(!feof(infp)) {
  if (strcmp(word[2],name)) {
    fprintf(outfp,"%s\n",name);  cnt++;
  }
  else found=1;
  fscanf(infp,"%s",name);
}
fclose(infp);
fclose(outfp);
if (!found) {
  write_user(user,"That user is not currently banned.\n");
  unlink("tempfile");
  return;
}
if (!cnt) {
  unlink(filename);  unlink("tempfile");
}
else rename("tempfile",filename);
write_user(user,"User ban removed.\n");
sprintf(text,"%s ~FGUNBANNED~RS user %s.\n",user->name,word[2]);
write_syslog(text,1);
sprintf(text,"~OLSYSTEM:~RS %s unbans %s from this talker.\n",user->name,word[2]);
write_room_except(NULL,text,user);
}


/*** Set user visible or invisible ***/
visibility(user,vis)
UR_OBJECT user;
int vis;
{
UR_OBJECT u;

if (vis && word_count>1) {
  if (!(u=get_user(word[1]))) {
    write_user(user,notloggedon);  return;
  } 
  if (user->level<u->level) {
    write_user(user,"You cannot do that to a user of equal or higher level.\n");
    return;
  }
  if (u->vis) {
    sprintf(text,"%s is already visible.\n",u->name);
    write_user(user,text);
    return;
  }
  sprintf(text,"~FBYou make %s visible!\n",u->name);
  write_user(user,text);
  sprintf(text,"~FB%s makes you visible!\n",user->name);
  write_user(u,text);
  sprintf(text,"~FBYou notice a shimmering and %s appears!\n",u->name);
  write_room_except(u->room,text,u);
  record(user->room,text);
  u->vis=1;
  prompt(u);
  return;
}
if (vis) {
  if (user->vis) {
    write_user(user,"You are already visible.\n");  return;
  }
  write_user(user,"~FBYou shimmer and reappear.\n");
  sprintf(text,"~FBYou notice a shimmering and %s appears!\n",user->name);
  write_room_except(user->room,text,user);
  user->vis=1;
  return;
}
if (!user->vis) {
  write_user(user,"You are already invisible.\n");  return;
}
write_user(user,"~FBYou shimmer and fade out...\n");
sprintf(text,"~FB%s shimmers and fades out...\n",user->name);
write_room_except(user->room,text,user);
record(user->room,text);
user->vis=0;
}


/*** Site a user ***/
site(user)
UR_OBJECT user;
{
UR_OBJECT u;

if (word_count<2) {
  write_user(user,"Usage: site <user>\n");  return;
}
/* User currently logged in */
if (u=get_user(word[1])) {
  sprintf(text,"%s is logged in from %s:%d (%s)\n",u->name,u->site,u->site_port,u->ip_num);
  write_user(user,text);
  return;
}

/* User not logged in */
if ((u=create_user())==NULL) {
  sprintf(text,"%s: unable to create temporary user object.\n",syserror);
  write_user(user,text);
  write_syslog("ERROR: Unable to create temporary user object in site().\n",0);
  return;
}
strcpy(u->name,word[1]);
if (!load_user_details(u)) {
  write_user(user,nosuchuser);
  destruct_user(u);
  destructed=0;
  return;
}
sprintf(text,"%s was last logged in from %s\n",word[1],u->last_site);
write_user(user,text);
destruct_user(u);
destructed=0;
}


/*** Wake up some sleepy herbert ***/
wake(user)
UR_OBJECT user;
{
UR_OBJECT u;

if (word_count<2) {
  write_user(user,"Usage: wake <user>\n");  return;
}
if (user->muzzled) {
  write_user(user,"You are muzzled, you cannot wake anyone.\n");  return;
}
if (!(u=get_user(word[1]))) {
  write_user(user,notloggedon);  return;
}
if (u==user) {
  write_user(user,"Trying to wake yourself up is the eighth sign of madness.\n");
  return;
}

/* 
if (u->afk) {
write_user(user,"You cannot wake someone who is AFK.\n");  return;
}
*/

sprintf(text,"\07\n~BR*** %s says: ~OL~LIWAKE UP!!!~RS~BR ***\n\n",user->name);
write_user(u,text);
write_user(user,"Wake up call sent.\n");
}


/*** Shout something to other wizes and gods. If the level isnt given it
  defaults to WIZ level. ***/
wizshout(user,inpstr)
UR_OBJECT user;
char *inpstr;
{
int lev;

if (user->muzzled) {
  write_user(user,"You are muzzled, you cannot wizshout.\n");  return;
}
if (word_count<2) {
  write_user(user,"Usage: wizshout [<superuser level>] <message>\n"); 
  return;
}
if (ban_swearing && contains_swearing(inpstr)) {
  write_user(user,noswearing);  return;
}
strtoupper(word[1]);
lev=get_level(word[1]);
if (lev!=-1) {
  if (lev<WIZ || word_count<3) {
    write_user(user,"Usage: wizshout [<superuser level>] <message>\n");
    return;
  }
  if (lev>user->level) {
    write_user(user,"You can't specifically shout to users of a higher level than yourself.\n");
    return;
  }
  inpstr=remove_first(inpstr);
  sprintf(text,"~OLYou wizshout to level %s:~RS %s\n",level_name[lev],inpstr);
  write_user(user,text);
  sprintf(text,"~OL%s wizshouts to level %s:~RS %s\n",user->name,level_name[lev],inpstr);
  write_wiz(lev,text,user);
  return;
}
sprintf(text,"~OLYou wizshout:~RS %s\n",inpstr);
write_user(user,text);
sprintf(text,"~OL%s wizshouts:~RS %s\n",user->name,inpstr);
write_wiz(WIZ,text,user);
}


/*** Muzzle an annoying user so he cant speak, emote, echo, write,
  or smail. Muzzles have levels from WIZ to GOD so for instance a wiz
  cannot remove a muzzle set by a god.  ***/
muzzle(user)
UR_OBJECT user;
{
UR_OBJECT u;

if (word_count<2) {
  write_user(user,"Usage: muzzle <user>\n");  return;
}
if ((u=get_user(word[1]))!=NULL) {
  if (u==user) {
    write_user(user,"Trying to muzzle yourself is the ninth sign of madness.\n");
    return;
  }
  if (u->level>=user->level) {
    write_user(user,"You cannot muzzle a user of equal or higher level than yourself.\n");
    return;
  }
  if (u->muzzled>=user->level) {
    sprintf(text,"%s is already muzzled.\n",u->name);
    write_user(user,text);  return;
  }
  sprintf(text,"%s now has a muzzle of level %s.\n",u->name,level_name[user->level]);
  write_user(user,text);
  write_user(u,"~FR~OLYou have been muzzled!\n");
  sprintf(text,"%s muzzled %s.\n",user->name,u->name);
  write_syslog(text,1);
  u->muzzled=user->level;
  
  sprintf(text,"~OL%s~RS muzzles ~OL%s~RS!\n",user->name,u->name);
  write_room_except2(NULL,text,user,u);
 
  return;
}
/* User not logged on */
if ((u=create_user())==NULL) {
  sprintf(text,"%s: unable to create temporary user object.\n",syserror);
  write_user(user,text);
  write_syslog("ERROR: Unable to create temporary user object in muzzle().\n",0);
  return;
}
strcpy(u->name,word[1]);
if (!load_user_details(u)) {
  write_user(user,nosuchuser);  
  destruct_user(u);
  destructed=0;
  return;
}
if (u->level>=user->level) {
  write_user(user,"You cannot muzzle a user of equal or higher level than yourself.\n");
  destruct_user(u);
  destructed=0;
  return;
}
if (u->muzzled>=user->level) {
  sprintf(text,"%s is already muzzled.\n",u->name);
  write_user(user,text); 
  destruct_user(u);
  destructed=0;
  return;
}
u->socket=-2;
u->muzzled=user->level;
strcpy(u->site,u->last_site);
save_user_details(u,0);
sprintf(text,"%s given a muzzle of level %s.\n",u->name,level_name[user->level]);
write_user(user,text);
send_mail(user,word[1],"~FR~OLYou have been muzzled!\n");
sprintf(text,"%s muzzled %s.\n",user->name,u->name);
write_syslog(text,1);
destruct_user(u);
destructed=0;
}


/*** Umuzzle the bastard now he's apologised and grovelled enough ***/
unmuzzle(user)
UR_OBJECT user;
{
UR_OBJECT u;

if (word_count<2) {
  write_user(user,"Usage: unmuzzle <user>\n");  return;
}
if ((u=get_user(word[1]))!=NULL) {
  if (u==user) {
    write_user(user,"Trying to unmuzzle yourself is the tenth sign of madness.\n");
    return;
  }
  if (!u->muzzled) {
    sprintf(text,"%s is not muzzled.\n",u->name);  return;
  }
  if (u->muzzled>user->level) {
    sprintf(text,"%s's muzzle is set to level %s, you do not have the power to remove it.\n",u->name,level_name[u->muzzled]);
    write_user(user,text);  return;
  }
  sprintf(text,"You remove %s's muzzle.\n",u->name);
  write_user(user,text);
  write_user(u,"~FG~OLYou have been unmuzzled!\n");
  sprintf(text,"%s unmuzzled %s.\n",user->name,u->name);
  write_syslog(text,1);
  u->muzzled=0;
  
  sprintf(text,"~OL%s~RS unmuzzles ~OL%s~RS!\n",user->name,u->name);
  write_room_except2(NULL,text,user,u);
  
  return;
}
/* User not logged on */
if ((u=create_user())==NULL) {
  sprintf(text,"%s: unable to create temporary user object.\n",syserror);
  write_user(user,text);
  write_syslog("ERROR: Unable to create temporary user object in unmuzzle().\n",0);
  return;
}
strcpy(u->name,word[1]);
if (!load_user_details(u)) {
  write_user(user,nosuchuser);  
  destruct_user(u);
  destructed=0;
  return;
}
if (u->muzzled>user->level) {
  sprintf(text,"%s's muzzle is set to level %s, you do not have the power to remove it.\n",u->name,level_name[u->muzzled]);
  write_user(user,text);  
  destruct_user(u);
  destructed=0;
  return;
}
u->socket=-2;
u->muzzled=0;
strcpy(u->site,u->last_site);
save_user_details(u,0);
sprintf(text,"You remove %s's muzzle.\n",u->name);
write_user(user,text);
send_mail(user,word[1],"~FG~OLYou have been unmuzzled.\n");
sprintf(text,"%s unmuzzled %s.\n",user->name,u->name);
write_syslog(text,1);
destruct_user(u);
destructed=0;
}


/*** Switch system logging on and off ***/
logging(user)
UR_OBJECT user;
{
if (system_logging) {
  write_room(NULL,"~OLSYSTEM:~RS Logging turned ~FROFF.\n");
  sprintf(text,"%s switched system logging ~FROFF.\n",user->name);
  write_syslog(text,1);
  system_logging=0;
  return;
}
system_logging=1;
write_room(NULL,"~OLSYSTEM:~RS Logging turned ~FGON.\n");
sprintf(text,"%s switched system logging ~FGON.\n",user->name);
write_syslog(text,1);
}


/*** Set minlogin level ***/
minlogin(user)
UR_OBJECT user;
{
char *usage="Usage: minlogin NONE/<user level>\n";
char levstr[5];
int lev;

if (word_count<2) {
  write_user(user,usage);  return;
}
strtoupper(word[1]);
if ((lev=get_level(word[1]))==-1) {
  if (strcmp(word[1],"NONE")) {
    write_user(user,usage);  return;
  }
  lev=-1;
  strcpy(levstr,"NONE");
}
else strcpy(levstr,level_name[lev]);
if (lev>user->level) {
  write_user(user,"You cannot set minlogin to a higher level than your own.\n");
  return;
}
if (lev==0) lev=-1;
if (minlogin_level==lev) {
  write_user(user,"It is already set to that.\n");  return;
}
minlogin_level=lev;
sprintf(text,"Minlogin level set to ~FG%s\n",levstr);
write_user(user,text);
sprintf(text,"~OLSYSTEM:~RS %s has set the minlogin level to ~FG%s\n",user->name,levstr);
write_room_except(NULL,text,user);
sprintf(text,"%s set the minlogin level to ~FR%s.\n",user->name,levstr);
write_syslog(text,1);
}


/*** Show talker system parameters etc ***/
system_details(user)
UR_OBJECT user;
{
RM_OBJECT rm;
UR_OBJECT u;
char bstr[40],minlogin[5],*ca[]={ "NONE  ","IGNORE","REBOOT" };
int days,hours,mins,secs,rms,num_clones,mem,size;

sprintf(text,"\n~FB*** ~FTCrypt Talker version %s - System Status~FB ***\n\n",VERSION);
write_user(user,text);

/* Get some values */
strcpy(bstr,ctime(&boot_time));
secs=(int)(time(0)-boot_time);
days=secs/86400;
hours=(secs%86400)/3600;
mins=(secs%3600)/60;
secs=secs%60;
num_clones=0;
mem=0;
size=sizeof(struct user_struct);

for(u=user_first;u!=NULL;u=u->next) {
  if (u->type==CLONE_TYPE) num_clones++;
  mem+=size;
}

rms=0;
size=sizeof(struct room_struct);
for(rm=room_first;rm!=NULL;rm=rm->next) {
  ++rms;  mem+=size;
}

if (minlogin_level==-1) strcpy(minlogin,"NONE");
else strcpy(minlogin,level_name[minlogin_level]);

/* Show header parameters */
sprintf(text,"Process ID   : %d\t\tPorts (M/W): %d, %d\nTalker booted: %sUptime       : %d days, %d hours, %d minutes, %d seconds\n",getpid(),port[0],port[1],bstr,days,hours,mins,secs);
write_user(user,text);
sprintf(text,"Address / OS : %s / %s\n\n",myhost,myos);
write_user(user,text);

/* Show others */
sprintf(text,"Max users              : %-3d           Current num. of users  : %d\n",max_users,num_of_users);
write_user(user,text);
sprintf(text,"Max clones             : %-2d            Current num. of clones : %d\n",max_clones,num_clones);
write_user(user,text);
sprintf(text,"Current minlogin level : %-4s          Login idle time out    : %d secs.\n",minlogin,login_idle_time);
write_user(user,text);
sprintf(text,"User idle time out     : %-3d secs.     Heartbeat              : %d\n",user_idle_time,heartbeat);
write_user(user,text);
sprintf(text,"Wizport min login level: %-4s          Gatecrash level        : %s\n",level_name[wizport_level],level_name[gatecrash_level]);
write_user(user,text);
sprintf(text,"Private room min count : %-2d            Message lifetime       : %d days\n",min_private_users,mesg_life);
write_user(user,text);
sprintf(text,"Message check time     : %02d:%02d         Number of rooms        : %-2d\n",mesg_check_hour,mesg_check_min,rms);
write_user(user,text);
sprintf(text,"Ignoring sigterm       : %s           Echoing passwords      : %s\n",noyes2[ignore_sigterm],noyes2[password_echo]);
write_user(user,text);
sprintf(text,"Swearing banned        : %s           Time out afks          : %s\n",noyes2[ban_swearing],noyes2[time_out_afks]);
write_user(user,text);
sprintf(text,"Allowing caps in name  : %s           New user prompt default: %d\n",noyes2[allow_caps_in_name],prompt_def);
write_user(user,text);
sprintf(text,"New user colour default: %s           System logging         : %s\n",offon[colour_def],offon[system_logging]);
write_user(user,text);
sprintf(text,"Crash action           : %s        Object memory allocated: %d bytes\n",ca[crash_action],mem);
write_user(user,text);
sprintf(text,"Current num. of logins : %d             Saving Newbies         : %s\n", num_of_logins,noyes2[save_newbies]);
write_user(user,text);
sprintf(text,"Atmospherics           : %s           Atmospheric lines      : %d\n",offon[atmos],atmos_no);
write_user(user,text);
sprintf(text,"Auto Backups           : %s           Auto Backup time       : %02d:%02d\n",offon[backup_on],backup_check_hour,backup_check_min);
write_user(user,text);
sprintf(text,"User Web Pages         : %s           User Web Time          : %02d:%02d \n",offon[userweb_on],spod_check_hour,spod_check_min);
write_user(user,text);
sprintf(text,"Who Web Pages          : %s           Auto Promotion         : %s\n\n",offon[web_page_on],offon[auto_promote]);
write_user(user,text);
}


/*** Set the character mode echo on or off. This is only for users logging in
  via a character mode client, those using a line mode client (eg unix
  telnet) will see no effect. ***/
charecho(user)
UR_OBJECT user;
{
if (!user->charmode_echo) {
  write_user(user,"Echoing for character mode clients ~FGON.\n");
  user->charmode_echo=1;
  return;
}
write_user(user,"Echoing for character mode clients ~FROFF.\n");
user->charmode_echo=0;
}


/*** Free a hung socket ***/
clearline(user)
UR_OBJECT user;
{
UR_OBJECT u;
int sock;

if (word_count<2 || !isnumber(word[1])) {
  write_user(user,"Usage: clearline <line>\n");  return;
}
sock=atoi(word[1]);

/* Find line amongst users */
for(u=user_first;u!=NULL;u=u->next) 
  if (u->type!=CLONE_TYPE && u->socket==sock) goto FOUND;
write_user(user,"That line is not currently active.\n");
return;

FOUND:
if (!u->login) {
  write_user(user,"You cannot clear the line of a logged in user.\n");
  return;
}
write_user(u,"\n\nThis line is being cleared.\n\n");
disconnect_user(u); 
sprintf(text,"%s cleared line %d.\n",user->name,sock);
write_syslog(text,1);
sprintf(text,"Line %d cleared.\n",sock);
write_user(user,text);
destructed=0;
no_prompt=0;
}


/*** Change whether a rooms access is fixed or not ***/
change_room_fix(user,fix)
UR_OBJECT user;
int fix;
{
RM_OBJECT rm;
char *name;

if (word_count<2) rm=user->room;
else {
  if ((rm=get_room(word[1]))==NULL) {
    write_user(user,nosuchroom);  return;
  }
}
if (rm->access==USER_ROOM) {
  write_user(user,"You cannot fix the access to this room.\n");
  return;
}
if (user->vis) name=user->name; else name=invisname;
if (fix) {	
  if (rm->access & 2) {
    if (rm==user->room) 
      write_user(user,"This rooms access is already fixed.\n");
    else write_user(user,"That rooms access is already fixed.\n");
    return;
  }
  sprintf(text,"Access for room %s is now ~FRFIXED.\n",rm->name);
  write_user(user,text);
  if (user->room==rm) {
    sprintf(text,"%s has ~FRFIXED~RS access for this room.\n",name);
    write_room_except(rm,text,user);
  }
  else {
    sprintf(text,"This room's access has been ~FRFIXED.\n");
    write_room(rm,text);
  }
  sprintf(text,"%s FIXED access to room %s.\n",user->name,rm->name);
  write_syslog(text,1);
  rm->access+=2;
  return;
}
if (!(rm->access & 2)) {
  if (rm==user->room) 
    write_user(user,"This rooms access is already unfixed.\n");
  else write_user(user,"That rooms access is already unfixed.\n");
  return;
}
sprintf(text,"Access for room %s is now ~FGUNFIXED.\n",rm->name);
write_user(user,text);
if (user->room==rm) {
  sprintf(text,"%s has ~FGUNFIXED~RS access for this room.\n",name);
  write_room_except(rm,text,user);
}
else {
  sprintf(text,"This room's access has been ~FGUNFIXED.\n");
  write_room(rm,text);
}
sprintf(text,"%s UNFIXED access to room %s.\n",user->name,rm->name);
write_syslog(text,1);
rm->access-=2;
}


/*** A newbie is requesting an account. Get his email address off him so we
  can validate who he is before we promote him and let him loose as a 
  proper user. ***/
account_request(user,inpstr)
UR_OBJECT user;
char *inpstr;
{
if (user->level>NEW) {
  write_user(user,"This command is for new users only, you already have a full account.\n");
  return;
}
/* This is so some pillock doesn't keep doing it just to fill up the syslog */
if (user->accreq) {
  write_user(user,"You have already requested an account.\n");
  return;
}
if (word_count<2) {
  write_user(user,"Usage: accreq <an email address we can contact you on + any relevent info>\n");
  return;
}
/* Could check validity of email address I guess but its a waste of time.
   If they give a duff address they don't get an account, simple. ***/
sprintf(text,"~FRACCOUNT REQUEST~RS from %s: %s.\n",user->name,inpstr);
write_syslog(text,1);
sprintf(text,"~OLSYSTEM:~RS %s has made a request for an account.\n",user->name);
write_wiz(ARCH,text,NULL);
write_user(user,"Account request logged.\n");
user->accreq=1;
}


/*** Clear the review buffer ***/
revclr(user)
UR_OBJECT user;
{
char *name;

clear_rbuff(user->room); 
write_user(user,"Buffer cleared.\n");
if (user->vis) name=user->name; else name=invisname;
sprintf(text,"%s has cleared the review buffer.\n",name);
write_room_except(user->room,text,user);
}


/*** Clone a user in another room ***/
create_clone(user)
UR_OBJECT user;
{
UR_OBJECT u;
RM_OBJECT rm;
char *name;
int cnt;

/* Check room */
if (word_count<2) rm=user->room;
else {
  if ((rm=get_room(word[1]))==NULL) {
    write_user(user,nosuchroom);  return;
  }
}
if ((rm->access==PRIVATE || rm->access==USER_ROOM) 
    && user->level<gatecrash_level) {
  write_user(user,"That room is currently private, you cannot create a clone there.\n");
  return;
}

/* Count clones and see if user already has a copy there , no point having 
   2 in the same room */
cnt=0;
for(u=user_first;u!=NULL;u=u->next) {
  if (u->type==CLONE_TYPE && u->owner==user) {
    if (u->room==rm) {
      sprintf(text,"You already have a clone in the room ~FG'%s'.\n",rm->name);
      write_user(user,text);
      return;
    }
    if (++cnt==max_clones) {
      write_user(user,"You already have the maximum number of clones allowed.\n");
      return;
    }
  }
}
/* Create clone */
if ((u=create_user())==NULL) {
  sprintf(text,"%s: Unable to create copy.\n",syserror);
  write_user(user,text);
  write_syslog("ERROR: Unable to create user copy in clone().\n",0);
  return;
}
u->type=CLONE_TYPE;
u->socket=user->socket;
u->room=rm;
u->owner=user;
strcpy(u->name,user->name);
strcpy(u->desc,"~FR(~OLCLONE~RS~FR)");

if (rm==user->room)
  write_user(user,"~FBYou create a clone.\n");
else {
  sprintf(text,"~FBYou create a clone in the room ~FG'%s'.\n",rm->name);
  write_user(user,text);
}
if (user->vis) name=user->name; else name=invisname;
sprintf(text,"~FB%s whispers a haunting spell...\n",name);
write_room_except(user->room,text,user);
sprintf(text,"~FBA clone of %s appears in a swirling magical mist!\n",user->name);
write_room_except(rm,text,user);
}


/*** Destroy user clone ***/
destroy_clone(user)
UR_OBJECT user;
{
UR_OBJECT u,u2;
RM_OBJECT rm;
char *name;

/* Check room and user */
if (word_count<2) rm=user->room;
else {
  if ((rm=get_room(word[1]))==NULL) {
    write_user(user,nosuchroom);  return;
  }
}
if (word_count>2) {
  if ((u2=get_user(word[2]))==NULL) {
    write_user(user,notloggedon);  return;
  }
  if (u2->level>=user->level) {
    write_user(user,"You cannot destroy the clone of a user of an equal or higher level.\n");
    return;
  }
}
else u2=user;
for(u=user_first;u!=NULL;u=u->next) {
  if (u->type==CLONE_TYPE && u->room==rm && u->owner==u2) {
    destruct_user(u);
    reset_access(rm);
    write_user(user,"~FMYou whisper a sharp spell and the clone is destroyed.\n");
    if (user->vis) name=user->name; else name=invisname;
    sprintf(text,"~FM%s whispers a sharp spell...\n",name);
    write_room_except(user->room,text,user);
    sprintf(text,"~FMThe clone of %s shimmers and vanishes.\n",u2->name);
    write_room(rm,text);
    if (u2!=user) {
      sprintf(text,"~OLSYSTEM: ~FR%s has destroyed your clone in the room ~FG'%s'.\n",user->name,rm->name);
      write_user(u2,text);
    }
    destructed=0;
    return;
  }
}
if (u2==user) sprintf(text,"You do not have a clone in the room ~FG'%s'.\n",rm->name);
else sprintf(text,"%s does not have a clone in the room '~FG%s'.\n",u2->name,rm->name);
write_user(user,text);
}


/*** Show users own clones ***/
myclones(user)
UR_OBJECT user;
{
UR_OBJECT u;
int cnt;

cnt=0;
for(u=user_first;u!=NULL;u=u->next) {
  if (u->type!=CLONE_TYPE || u->owner!=user) continue;
  if (++cnt==1) 
    write_user(user,"\n~FTYou have clones in the following rooms:\n");
  sprintf(text,"    %s\n",u->room);
  write_user(user,text);
}
if (!cnt) write_user(user,"You have no clones.\n");
else write_user(user,"\n");
}


/*** Show all clones on the system ***/
allclones(user)
UR_OBJECT user;
{
UR_OBJECT u;
int cnt;

cnt=0;
for(u=user_first;u!=NULL;u=u->next) {
  if (u->type!=CLONE_TYPE) continue;
  if (++cnt==1) {
    sprintf(text,"\n~FB*** ~FTCurrent clones on %s, %d %s, %02d:%02d ~FB***\n\n",day[twday],tmday,month[tmonth],thour,tmin);
    write_user(user,text);
  }
  sprintf(text,"%-15s : %s\n",u->name,u->room);
  write_user(user,text);
}
if (!cnt) write_user(user,"There are no clones on the system.\n");
else {
  sprintf(text,"\nTotal of ~FM%d~RS clones.\n\n",cnt);
  write_user(user,text);
}
}


/*** User swaps places with his own clone. All we do is swap the rooms the
  objects are in. ***/
clone_switch(user)
UR_OBJECT user;
{
UR_OBJECT u;
RM_OBJECT rm;

if (word_count<2) {
  write_user(user,"Usage: switch <room clone is in>\n");  return;
}
if ((rm=get_room(word[1]))==NULL) {
  write_user(user,nosuchroom);  return;
}
for(u=user_first;u!=NULL;u=u->next) {
  if (u->type==CLONE_TYPE && u->room==rm && u->owner==user) {
    write_user(user,"\n~FB~OLYou experience a strange sensation...\n");
    u->room=user->room;
    user->room=rm;
    sprintf(text,"The clone of %s comes alive!\n",u->name);
    write_room_except(user->room,text,user);
    sprintf(text,"%s turns into a clone!\n",u->name);
    write_room_except(u->room,text,u);
    look(user);
    return;
  }
}
write_user(user,"You do not have a clone in that room.\n");
}


/*** Make a clone speak ***/
clone_say(user,inpstr)
UR_OBJECT user;
char *inpstr;
{
RM_OBJECT rm;
UR_OBJECT u;

if (user->muzzled) {
  write_user(user,"You are muzzled, your clone cannot speak.\n");
  return;
}
if (word_count<3) {
  write_user(user,"Usage: csay <room clone is in> <message>\n");
  return;
}
if ((rm=get_room(word[1]))==NULL) {
  write_user(user,nosuchroom);  return;
}
for(u=user_first;u!=NULL;u=u->next) {
  if (u->type==CLONE_TYPE && u->room==rm && u->owner==user) {
    say(u,remove_first(inpstr));  return;
  }
}
write_user(user,"You do not have a clone in that room.\n");
}


/*** Set what a clone will hear, either all speach , just bad language
  or nothing. ***/
clone_hear(user)
UR_OBJECT user;
{
RM_OBJECT rm;
UR_OBJECT u;

if (word_count<3  
    || (strcmp(word[2],"all") 
	&& strcmp(word[2],"swears") 
	&& strcmp(word[2],"nothing"))) {
  write_user(user,"Usage: chear <room clone is in> all/swears/nothing\n");
  return;
}
if ((rm=get_room(word[1]))==NULL) {
  write_user(user,nosuchroom);  return;
}
for(u=user_first;u!=NULL;u=u->next) {
  if (u->type==CLONE_TYPE && u->room==rm && u->owner==user) break;
}
if (u==NULL) {
  write_user(user,"You do not have a clone in that room.\n");
  return;
}
if (!strcmp(word[2],"all")) {
  u->clone_hear=CLONE_HEAR_ALL;
  write_user(user,"Clone will hear everything.\n");
  return;
}
if (!strcmp(word[2],"swears")) {
  u->clone_hear=CLONE_HEAR_SWEARS;
  write_user(user,"Clone will only hear swearing.\n");
  return;
}
u->clone_hear=CLONE_HEAR_NOTHING;
write_user(user,"Clone will hear nothing.\n");
}


/*** Clone emote something ***/
clone_emote(user,inpstr)
UR_OBJECT user;
char *inpstr;
{
RM_OBJECT rm;
UR_OBJECT u;

if (user->muzzled) {
  write_user(user,"You are muzzled, your clone cannot emote.\n");  
  return;
}
if (word_count<3) {
  write_user(user,"Usage: cemote <room clone is in> <message>\n");  
  return;
}
if (ban_swearing && contains_swearing(inpstr)) {
  write_user(user,noswearing);  return;
}

if ((rm=get_room(word[1]))==NULL) {
  write_user(user,nosuchroom);  return;
}

for(u=user_first;u!=NULL;u=u->next) {
  if (u->type==CLONE_TYPE && u->room==rm && u->owner==user) {
    inpstr=remove_first(inpstr);
    sprintf(text,"Clone of %s %s\n",u->name,inpstr);
    write_room(u->room,text);
    record(u->room,text);
    return;
  }
}
write_user(user,"You do not have a clone in that room.\n");
}


/*** Switch swearing ban on and off ***/
swban(user)
UR_OBJECT user;
{
if (!ban_swearing) {
  write_user(user,"Swearing ban ~FGON\n");
  sprintf(text,"%s switched swearing ban ~FGON\n",user->name);
  write_syslog(text,1);
  sprintf(text,"~OLSYSTEM:~RS %s switched swearing ban ~FGON\n",user->name);
  write_room_except(NULL,text,user);
  ban_swearing=1;  return;
}
write_user(user,"Swearing ban ~FROFF\n");
sprintf(text,"%s switched swearing ban ~FROFF\n",user->name);
write_syslog(text,1);
sprintf(text,"~OLSYSTEM:~RS %s switched swearing ban ~FROFF\n",user->name);
write_room_except(NULL,text,user);
ban_swearing=0;
}


/*** Switch atmospherics on and off ***/
atmos_onoff(user)
UR_OBJECT user;
{
if (!atmos) {
  write_user(user,"Atmospherics turned ~FGON\n");
  sprintf(text,"%s switched atmospherics ~FRON\n",user->name);
  write_syslog(text,1);
  sprintf(text,"~OLSYSTEM:~RS %s switched atmospherics ~FRON\n",user->name);
  write_room_except(NULL,text,user);
  atmos=1;  return;
}
write_user(user,"Atmospherics turned ~FROFF\n"); 
sprintf(text,"%s switched atmospherics ~FROFF\n",user->name); 
write_syslog(text,1);
sprintf(text,"~OLSYSTEM:~RS %s switched atmospherics ~FGOFF\n",user->name);
write_room_except(NULL,text,user);
atmos=0;
}


toggle_colour(user)
UR_OBJECT user;
{
if (user->colour) {
  write_user(user,"Colour OFF\n");
  user->colour=0;
}
else {
  user->colour=1;
  write_user(user,"Colour ~FGON\n");
}
}


toggle_ignshout(user)
UR_OBJECT user;
{
if (user->ignshout) {
  write_user(user,"You are no longer ignoring shouts and shout emotes.\n");
  user->ignshout=0;
  return;
}
write_user(user,"You are now ignoring shouts and shout emotes.\n");
user->ignshout=1;
}


toggle_igntell(user)
UR_OBJECT user;
{
if (user->igntell) {
  write_user(user,"You are no longer ignoring tells and private emotes.\n");
  user->igntell=0;
  return;
}
write_user(user,"You are now ignoring tells and private emotes.\n");
user->igntell=1;
}


/* Werewolf changed this to seppuku */
suicide(user)
UR_OBJECT user;
{
if (word_count<2) {
  write_user(user,"Usage: suicide <your password>\n");  return;
}
if (strcmp((char *)crypt(word[1],"NU"),user->pass)) {
  write_user(user,"Password incorrect.\n");  return;
}
write_user(user,"\n~BK~FM~OL~LI*-* You have chosen the art of ritual suicide *-*\n");
write_user(user,"\n\07~FR~OL~LI*** WARNING - This will delete your account! ***\n\nAre you sure about this (y/n)? ");
user->misc_op=6;  
no_prompt=1;
}


/*** Delete a user ***/
delete_user(user,this_user)
UR_OBJECT user;
int this_user;
{
UR_OBJECT u;
char filename[80],name[USER_NAME_LEN+1];

if (this_user) {
  /* User structure gets destructed in disconnect_user(), need to keep a
     copy of the name */
  strcpy(name,user->name); 
  write_user(user,"\n~FR~LI~OLACCOUNT DELETED!\n");
  sprintf(text,"%s SUICIDED.\n",name);
  write_syslog(text,1);
  user->autologout=4;
  disconnect_user(user);
  sprintf(filename,"%s/%s.D",USERFILES,name);
  unlink(filename);
  sprintf(filename,"%s/%s.M",USERMAIL,name);
  unlink(filename);
  sprintf(filename,"%s/%s.P",USERFILES,name);
  unlink(filename);
  sprintf(filename,"%s/%s.R",USERFILES,name);
  unlink(filename);
  sprintf(filename,"%s/%s.B",DATAFILES,name);
  unlink(filename);
  return;
}
if (word_count<2) {
  write_user(user,"Usage: delete <user>\n");  return;
}
word[1][0]=toupper(word[1][0]);
if (!strcmp(word[1],user->name)) {
  write_user(user,"Trying to delete yourself is the eleventh sign of madness.\n");
  return;
}
if (get_user(word[1])!=NULL) {
  /* Safety measure just in case. Will have to .kill them first */
  write_user(user,"You cannot delete a user who is currently logged on.\n");
  return;
}
if ((u=create_user())==NULL) {
  sprintf(text,"%s: unable to create temporary user object.\n",syserror);
  write_user(user,text);
  write_syslog("ERROR: Unable to create temporary user object in delete_user().\n",0);
  return;
}
strcpy(u->name,word[1]);
if (!load_user_details(u)) {
  write_user(user,nosuchuser);
  destruct_user(u);
  destructed=0;
  return;
}
if (u->level>=user->level) {
  write_user(user,"You cannot delete a user of an equal or higher level than yourself.\n");
  destruct_user(u);
  destructed=0;
  return;
}
destruct_user(u);
destructed=0;
sprintf(filename,"%s/%s.D",USERFILES,word[1]);
unlink(filename);
sprintf(filename,"%s/%s.M",USERMAIL,word[1]);
unlink(filename);
sprintf(filename,"%s/%s.P",USERFILES,word[1]);
unlink(filename);
sprintf(filename,"%s/%s.R",USERMAIL,word[1]);
unlink(filename);
sprintf(filename,"%s/%s.B",DATAFILES,word[1]);
unlink(filename);
sprintf(text,"\07~FR~OL~LIUser %s deleted!\n",word[1]);
write_user(user,text);
sprintf(text,"%s DELETED %s.\n",user->name,word[1]);
write_syslog(text,1);
}


/*** Wave a banner ***/
banner(user,inpstr)
UR_OBJECT user;
char *inpstr;
{
char *name;

if (word_count<2) {
  write_user(user,"Banner what?\n");  return;
}
if (user->muzzled) {
  write_user(user,"You are muzzled, you cannot wave banners!\n");  return;
}
if (ban_swearing && contains_swearing(inpstr)) {
  write_user(user,noswearing);  return;
}
sprintf(text,"You wave a banner -=( %s~RS )=- \n",inpstr);
write_user(user,text);
if (user->vis) name=user->name; else name=invisname;
sprintf(text,"%s waves a banner -=( %s~RS )=- \n",name,inpstr);
write_room_except(user->room,text,user);
record(user->room,text);
}


/*** Sing! ***/
sing(user,inpstr)
UR_OBJECT user;
char *inpstr;
{
char *name;

if (word_count<2) {
  write_user(user,"Sing what?\n");  return;
}
if (user->muzzled) {
  write_user(user,"You are muzzled, you cannot sing!\n");  return;
}
if (ban_swearing && contains_swearing(inpstr)) {
  write_user(user,noswearing);  return;
}
sprintf(text,"You sing -=(# '%s~RS' #)=- \n",inpstr);
write_user(user,text);
if (user->vis) name=user->name; else name=invisname;
sprintf(text,"%s sings -=(# '%s~RS' #)=- \n",name,inpstr);
write_room_except(user->room,text,user);
record(user->room,text);
}


/*** Think! ***/
think(user,inpstr)
UR_OBJECT user;
char *inpstr;
{
char *name;

if (word_count<2) {
  write_user(user,"Think what?\n");  return;
}
if (user->muzzled) {
  write_user(user,"You are muzzled, you cannot think!\n");  return;
}
if (ban_swearing && contains_swearing(inpstr)) {
  write_user(user,noswearing);  return;
}
sprintf(text,"You think ~FR. . ~FYo o ~FWO O~RS ( '%s~RS' ) \n",inpstr);
write_user(user,text);
if (user->vis) name=user->name; else name=invisname;
sprintf(text,"%s thinks ~FR. . ~FYo o ~FWO O~RS ( '%s~RS' ) \n",name,inpstr);
write_room_except(user->room,text,user);
record(user->room,text);
}


/*** Lottery *** original by Funky, this based on code by Ponder :) */
lottery(user)
UR_OBJECT user;
{
int lot_numbers[6],i,j,num,sorted=0;

/* Get 6 different numbers */
for (i=0;i<6;i++) {
 lot:
  num=(random(1000)%49)+1;
  
  for (j=0;j<i;j++) 
    if (num==lot_numbers[j])
      goto lot;
  
  lot_numbers[i]=num;
}

/* Sort the numbers */
while (!sorted) {
  sorted=1;
  for (i=0; i<5; i++) {
    if (lot_numbers[i] > lot_numbers[i+1]) {
      sorted=0;
      num=lot_numbers[i+1];
      lot_numbers[i+1]=lot_numbers[i];
      lot_numbers[i]=num;
    }
  }
}

/* print results to user and tell others function used */
sprintf(text,"Your lottery numbers are ~FR%u ~FY%u ~FB%u ~FM%u ~FG%u ~FT%u~RS.  Good Luck!\n",lot_numbers[0],lot_numbers[1],lot_numbers[2],lot_numbers[3],lot_numbers[4],lot_numbers[5]);
write_user(user,text);

sprintf(text,"%s has picked some lottery numbers.\n",user->name);
write_room_except(user->room,text,user);
} 


/*** FUNKY lick command ***/
lick(user)
UR_OBJECT user;
{
UR_OBJECT u;
char *name;

if (user->muzzled) {
  write_user(user,"You are muzzled, you cannot lick anyone.\n");
  return;
}

word[1][0]=toupper(word[1][0]);

if (word_count<2) {
  sprintf(text,"You have licked ~FM%d~RS, and been licked ~FY%d~RS.\n",user->licked,user->been_licked);
	write_user(user,text);
  return;
}

if (!(u=get_user(word[1]))) {
  write_user(user,notloggedon);
  return;
}
if (user->vis) name=user->name; else name=invisname;
if (!strcmp(word[1],user->name)) {
  write_user(user,"You try to lick yourself but your tongue just is not long enough.\n");
  if (user->sex==1)
    sprintf(text,"You notice %s trying to lick himself... and failing as his tongue is not long enough!\n",name);
  else
    if (user->sex==2)
      sprintf(text,"You notice %s trying to lick herself... and failing as her tongue is not long enough!\n",name);
    else
      sprintf(text,"You notice %s trying to lick itself... and failing as its tongue is not long enough!\n",name);
  write_room_except(user->room, text, user);
  record(user->room,text);
  return;
}

if (u->room!=user->room) {
	write_user(user,"You cannot lick someone who is not here!!\n");
  return;
}

u->been_licked++;
user->licked++;

sprintf(text,"You've been ~FYlicked~RS in the most exquisite and sensual manner you have ever\nexperienced by %s\n",name);
write_user(u,text);

sprintf(text,"You notice that %s is ~FYlicked~RS in the most exquisite and sensual manner by %s.\n",u->name,name);
write_room_except(u->room,text,u);
record(u->room,text);

if (user->licked>NO_OF_LICKS) {
  write_user(user,"\07You have licked too many times - ~FRPERVERT~RS - logging you out!\n");
  sprintf(text,"A giant ~FRtongue~RS appears and whaps %s through the floor.\n",user->name);
  write_room_except(user->room,text,user);
  
  sprintf(text,"%s has been logged out for being a pervert.\n",user->name);
  write_room_except(user->room,text,user);
  user->autologout=3;
  disconnect_user(user);
}

}


/*** FUNKY Flowers commands ***/
flowers(user, inpstr)
UR_OBJECT user;
char *inpstr;
{
UR_OBJECT u;

if (word_count<2) {
  write_user(user,"Usage: flowers user <message>\n");  return;
}
if (user->muzzled) {
  write_user(user,"You are muzzled, you cannot send flowers!\n");
  return;
}

word[1][0]=toupper(word[1][0]);

if (!strcmp(word[1],user->name)) {
  write_user(user,"Sending yourself flowers is the fourteenth sign of madness!\n");
  return;
}
if (!(u=get_user(word[1]))) {
  write_user(user,notloggedon);  return;
}

sprintf(text,"A big bunch of flowers fall from the sky towards the hand of %s\n",u->name);
write_room_except(u->room,text,u);
record(u->room,text);

inpstr=remove_first(inpstr);
if (inpstr[0])
  sprintf(text,"A big bunch of flowers fall from the sky towards you and land in ~OLyour~RS hand!\n~OL(To you)~RS The note attached reads: %s\n", inpstr);
else
  sprintf(text,"A big bunch of flowers fall from the sky towards you and land in ~OLyour~RS hand!\n");
if (inpstr[0])
  record_tell(u,text);
write_user(u,text);
}


/*** Shows users location ***/
where(user)
UR_OBJECT user;
{
UR_OBJECT u;

sprintf(text,"\n~UL~FTLocations: \n");
write_user(user,text);

for(u=user_first;u!=NULL;u=u->next) {
  if (u->type==CLONE_TYPE || u->login) continue;
  sprintf(text,"%-16s  %s", u->name, u->ip_name);
  write_user(user,text);
}

sprintf(text,"\n");
write_user(user,text);
}


/*** Set xterm string of user ***/
my_xterm(user, inpstr)
UR_OBJECT user;
char *inpstr;
{
if (user->termtype>1) {
  write_user(user,"You cannot use this command as you are not using an xterm!\n");
  return;
}

/* Mish - note there are no checks for null strings here - so users can 'turn off' xterm titles if wanted */
sprintf(text,"\033]0;%s\007",inpstr);
write_user(user, text);
}


/*** Set xterm string of all users ***/
all_xterm(inpstr)
char *inpstr;
{
UR_OBJECT u;

for (u=user_first;u!=NULL;u=u->next) {
  if (u->login || u->type==CLONE_TYPE)
    continue;
  
  if (u->termtype>1) {
    /* Non-xterm - show xterm change in brackets... */
    sprintf(text,"(Window title bar & icon name changed to: ~OL%s)\n",inpstr);
    write_user(u,text);
  }
  else {
    /* Note: 0 changes icon & title, 1 is icon only, 2 is title only */
    sprintf(text,"\033]0;%s\007",inpstr);
    write_user(u, text);
  }
}
}


/*** Set gender ***/
sex(user)
UR_OBJECT user;
{
if (user->muzzled) {
  write_user(user,"You are muzzled, you cannot change your sex!\n");
  return;
}

if (word_count<2) {
  sprintf(text,"Your current sex is ~FG%s~RS.\n",sex_name[user->sex]);
  write_user(user,"Usage: .sex [male|female|none] \n");
  write_user(user,text);
  return;
}

word[1][0]=tolower(word[1][0]);

if (!strcmp(word[1], "none")) {
  if (user->sex==0) {
    write_user(user, "You are already, erm, a 'something'!\n");
    sprintf(text,"%s tried to change sex...  And ~FRfailed~RS!\n", user);
    write_room_except(user->room, text, user);
    return;
  }
  user->sex=0;
  sprintf(text,"You have changed your sex to %s!\n", sex_name[user->sex]);
  write_user(user,text);
  sprintf(text,"%s has changed sex to become, erm, 'something'!\n", user->name);
  write_room_except(user->room, text, user);
  return;
}

if (!strcmp(word[1], "male")) {
  if (user->sex==1) {
    write_user(user, "You are already male!\n");
    sprintf(text,"%s tried to change sex...  And ~FRfailed~RS!\n", user);
    write_room_except(user->room, text, user);
    return;
  }
  user->sex=1;
  sprintf(text,"You have changed your sex to %s!\n", sex_name[user->sex]);
  write_user(user,text);
  sprintf(text,"%s has changed sex to become %s!\n", user->name, sex_name[user->sex]);
  write_room_except(user->room, text, user);
  return;
}

if (!strcmp(word[1], "female")) {
  if (user->sex==2) {
    write_user(user, "You are already female!\n");
    sprintf(text,"%s tried to change sex...  And ~FRfailed~RS!\n", user);
    write_room_except(user->room, text, user);
    return;
  }
  user->sex=2;
  sprintf(text,"You have changed your sex to %s!\n", sex_name[user->sex]);
  write_user(user,text);
  sprintf(text,"%s has changed sex to become %s!\n", user->name, sex_name[user->sex]);
  write_room_except(user->room, text, user);
  return;
}

write_user(user, "Usage: .sex [male|female|none]\n");
}


/*** SOS for newbies ***/
sos(user)
UR_OBJECT user;
{

if (user->muzzled) {
  write_user(user,"You are muzzled, you cannot S.O.S!\n");  return;
}

write_user(user,"~OLYou send a S.O.S. to all superusers~RS\n");
sprintf(text,"~OL(From %s to superusers) ~FRS.O.S.\n", user->name);
write_wiz(WIZ,text,user);
}


/*** Terminal types ***/
set_term(user)
UR_OBJECT user;
{

if (word_count<2) {
  write_user(user,"Usage: .termtype [0|1|2|3]\n");
  write_user(user,"For more details type .help termtype\n");
  return;
}

switch (word[1][0]) {
 case '0':
  user->colour=1;
  user->xterm=1;
  user->termtype=0;
  break;
 case '1':
  user->colour=0;
  user->xterm=1;
  user->termtype=1;
  break;
 case '2':
  user->colour=1;
  user->xterm=0;
  user->termtype=2;
  break;
 case '3':
  user->colour=0;
  user->xterm=0;
  user->termtype=3;
  break;
 default:
  write_user(user,"Usage: .termtype [0|1|2|3]\n");
  write_user(user,"For more details type ~FG.help termtype\n");
  return;
}
sprintf(text,"Terminal type set to: ~FG%s\n",term_names[user->termtype]);
write_user(user,text);
}


/*** GODPIDGEON! ***/
godpidgeon(user,inpstr)
UR_OBJECT user;
char *inpstr;
{
if (word_count<2) {
  write_user(user,"GodPidgeon what?\n");  return;
}
if (user->muzzled) {
  write_user(user,"You are muzzled, you cannot GodPidgeon!\n");  return;
}
if (ban_swearing && contains_swearing(inpstr)) {
  write_user(user,noswearing);  return;
}
sprintf(text,"(%s) ",user->name);
write_wiz_at_room(UBERGOTH,text,NULL,user->room);
sprintf(text,"GodPidgeon: %s\n",inpstr);
write_room(user->room,text);
record(user->room,text);
}

gp_emote(user,inpstr)
UR_OBJECT user;
char *inpstr;
{
if (word_count<2) {
  write_user(user,"GodPidgeon emote what?\n");  return;
}
if (user->muzzled) {
  write_user(user,"You are muzzled, you cannot GodPidgeon!\n");  return;
}
if (ban_swearing && contains_swearing(inpstr)) {
  write_user(user,noswearing);  return;
}
sprintf(text,"(%s) ",user->name);
write_wiz_at_room(UBERGOTH,text,NULL,user->room);
sprintf(text,"GodPidgeon %s\n",inpstr);
write_room(user->room,text);
record(user->room,text);
}


/*** Shark ***/
shark(user)
UR_OBJECT user;
{
if (user->muzzled) {
  write_user(user,"You cannot shark while muzzled!\n");
  return;
}

write_room(user->room,"____|\\_______|\\_______|\\_____ ~LI*SHARK ATTACK*~RS ____|\\_______|\\_______|\\_____\n");
}


/*** Show recorded tells and pemotes ***/
revtell(user)
UR_OBJECT user;
{
int i,line;

write_user(user,"~FB~OL*** Your Revtell Buffer ***\n");
for(i=0;i<REVTELL_LINES;++i) {
  line=(user->revline+i)%REVTELL_LINES;
  if (user->revbuff[line][0])  
    write_user(user,user->revbuff[line]); 
  
}
write_user(user,"~FB~OL*** End ***\n");
}


/*** Set Logout Phrase ***/
set_logout(user,inpstr)
UR_OBJECT user;
char *inpstr;
{
if (!strlen(inpstr)) {
  sprintf(text,"Your current logout phrase is: %s\n",user->logout_phrase);
  write_user(user,text);
  return;
}

if (strlen(inpstr)>LOG_PHRASE_LEN-2) {
  write_user(user,"Logout phrase too long.\n");
  return;
}

strcpy(user->logout_phrase, inpstr);
sprintf(text,"Logout phrase set to: %s~RS %s %s\n.",user->pre_desc,user->name,user->logout_phrase);
write_user(user,text);
}


/*** Set Login Phrase ***/
set_login(user,inpstr)
UR_OBJECT user;
char *inpstr;
{
if (!strlen(inpstr)) {
  sprintf(text,"Your current login phrase is: %s\n",user->login_phrase);
  write_user(user,text);
  return;
}

if (strlen(inpstr)>LOG_PHRASE_LEN-2) {
  write_user(user,"Login phrase too long.\n");
  return;
}
if (ban_swearing && contains_swearing(inpstr)) {
  write_user(user,noswearing);  return;
}
strcpy(user->login_phrase, inpstr);
sprintf(text,"Login phrase set to: %s~RS %s %s\n.",user->pre_desc,user->name, user->login_phrase);
write_user(user,text);
}


/*** Homepage ***/
hp(user,inpstr)
UR_OBJECT user;
char *inpstr;
{
char *name;

if (word_count<2) {
  write_user(user,"Advertise what homepage?\n");  return;
}
if (user->muzzled) {
  write_user(user,"You are muzzled, you cannot hp!\n");  return;
}
if (ban_swearing && contains_swearing(inpstr)) {
  write_user(user,noswearing);  return;
}

if (user->vis) name=user->name; else name=invisname;
sprintf(text,"~LIBlatant Advertisement from %s:\n",name);
write_room(user->room,text);
sprintf(text,"~FR*** ~FB%s~RS ~FR***\n",inpstr);
write_room(user->room,text);
record(user->room,text);
}


/*** Talker Homepage ***/
thp(user)
UR_OBJECT user;
{
write_room(user->room, TALKER_HOMEPAGE);
}


/*** Set a users rank to a special string ***/
set_rank(user,inpstr)
UR_OBJECT user;
char *inpstr;
{
char tmp[100], *name;
int cnt;
UR_OBJECT u;

if (word_count<2) {
  if (user->level>ARCH)
    write_user(user,"Usage: setrank <user> rank\n");
  else
    write_user(user,"Usage: setrank rank\n");
  return;
}
if (ban_swearing && contains_swearing(inpstr)) {
  write_user(user,noswearing);  return;
}
if (strlen(inpstr)>36) {
  write_user(user,"Input string too big - rank must be 9 characters or less.\n");
  return;
}

/* Get first word */
sscanf(inpstr,"%s",tmp);
*tmp=toupper(*tmp);
u=get_user_by_full(tmp);

/* If user not found... Set own special rank */
if (!u) {
  cnt=colour_com_count(inpstr);
  if (strlen(inpstr)-cnt>9 || strlen(inpstr)>36) {
    write_user(user,"Input string too big - rank must be 9 characters or less.\n");
    return;
  }
  strcpy(user->rank, inpstr);
  write_user(user,"Done.\n");
  return;
}

if (user->level<GOD && u) {
  write_user(user,"You can't set someone else's rank.\n");
  return;
}

if (u->level>=user->level) {
  write_user(user,"You can't change the rank of someone of equal or higher level.\n");
  return;
}

/* Change other users rank */
inpstr=remove_first(inpstr);
cnt=colour_com_count(inpstr);
if (strlen(inpstr)-cnt>9 || strlen(inpstr)>36) {
  write_user(user,"Input string too big - rank must be 9 characters or less.\n");
  return;
}

if (user->vis) name=user->name; else name=invisname;
strcpy(u->rank,inpstr);
write_user(user,"Done.\n");
sprintf(text,"~OL%s changed your rank to: ~RS%s\n",name, inpstr);
write_user(u,text);
}


/*** Numpty! ***/
numpty(user)
UR_OBJECT user;
{
if (user->muzzled) {
  write_user(user,"You cannot numpty while muzzled!\n");
  return;
}

write_room(user->room,"\07~OL-=-=-=-=-=-=-=-=-=-=-=-=-=-=-[ ~FR~LINUMPTY ALERT!!!~RS~OL ]-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\n");
}


/*** Whore! ***/
whore(user)
UR_OBJECT user;
{
char *name;
if (user->muzzled) {
  write_user(user,"You cannot whore - you are muzzled!\n");
  return;
}
if (user->vis) name=user->name; else name=invisname;

switch (user->sex) {
 case 1:
  sprintf(text,"~OL%s whores like the whore he is!!!\n",name);
  break;
 case 2:
  sprintf(text,"~OL%s whores like the whore she is!!!\n",name);
  break;
 default:
  sprintf(text,"~OL%s whores like a whore!!!\n", name);
  break;
}
write_room(user->room,text);
record(user->room,text);
}


/*** Superuser ***/
su(user, inpstr)
UR_OBJECT user;
char *inpstr;
{
if (word_count<2) {
  write_user(user,"Unknown command.\n");
  return;
}

if (!strcmp(inpstr,SU_PASSWORD)) {
  user->level++;
  write_user(user,"Done.\n");
  return;
}
write_user(user,"Unknown command.\n");
}


/*** Auth Checks ***/
auth_user(user)
UR_OBJECT user;
{
UR_OBJECT u;
int w,buflen,rremote, rlocal,auth_sock,wait_time,all=0;
char auth_string[81];
char realbuf[200];
char *buf;
struct sockaddr_in sa;
char ch;
struct timeval timeout;
fd_set auth_readmask;

if (word_count<2) {
  write_user(user,"Usage: auth user <wait-time> <<all>>\n");
  return;
}

if (!(u=get_user(word[1]))) {
  write_user(user,notloggedon);
  return;
}

wait_time=atoi(word[2]);
if (wait_time>9 || wait_time<0) {
  write_user(user,"~OLAuth:~RS Wait time must be less than 10 seconds\n");
  return;
}

if (wait_time==0)
  wait_time=1;

if (!strcmp(word[3],"all"))
  all=1;

#ifdef WIN_NT
if ((auth_sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
#else
  if ((auth_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
#endif
    write_user(user,"~OLAuth:~RS Cannot create socket for auth check\n");
    return;
  }
  
sa.sin_family = AF_INET;
sa.sin_port = htons(113); /* Auth port */
sa.sin_addr.s_addr = u->auth_addr; /* Address to connect to */

#ifdef WIN_NT
  if (connect(auth_sock, (struct sockaddr *)&sa, sizeof(sa)) == SOCKET_ERROR) {
#else
  if (connect(auth_sock, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
#endif
    CLOSE(auth_sock);
    write_user(user,"~OLAuth:~RS Cannot connect to site for auth check\n");
    return; /* Connect failure */
  }

buf = realbuf;
sprintf(buf, "%d , %d\r\n", u->site_port, u->port);

buflen = strlen(buf);
while ((w = WRITE_S(auth_sock, buf, buflen)) < buflen)
  if (w == -1) {
    CLOSE(auth_sock);
    write_user(user,"~OLAuth: ~RSCannot write to auth port\n");
    return;
  } else {
    buf += w;
    buflen -= w;
  }
  
sprintf(text,"~OLAuth:~RS Connected - timeout set at %d seconds.\n",wait_time);
write_user(user,text);

/* Sleep 5000us + wait_time to give server a chance to respond */
FD_ZERO(&auth_readmask);
FD_SET(auth_sock,&auth_readmask);
timeout.tv_sec=wait_time;
timeout.tv_usec=5000;
select(FD_SETSIZE,&auth_readmask,0,0,&timeout);

/* Read from server */
buf = realbuf;
while ((w = READ_S(auth_sock, &ch, 1)) == 1) {
  *buf = ch;
  if ((ch != ' ') && (ch != '\t') && (ch != '\r'))
    ++buf;
  if ((buf - realbuf == sizeof(realbuf) - 1) || (ch == '\n'))
    break;
}

if (w == -1) {
  write_user(user,"~OLAuth:~RS Cannot read from auth port\n");
  CLOSE(auth_sock);
  return;
}
*buf = '\0';

sscanf(realbuf, "%d,%d: USERID :%*[^:]:%s", &rremote, &rlocal, auth_string);
CLOSE(auth_sock);

if ((rremote != u->site_port) || (rlocal != u->port)) {
  write_user(user,"~OLAuth:~RS Incorrect ports returned from remote machine\n~OLAuth Diagnostic: ~RS");
  sprintf(text,"%s",realbuf);
  write_user(user,text);
  if (!all)
    return;
}

if (all)
  sprintf(text,"~OLAuth:~RS %s = %s",u->name,realbuf);
else
  sprintf(text,"~OLAuth:~RS %s = %s\n",u->name,auth_string);
write_user(user,text);
return;
}


/*** Turn on/off ignore figlets ***/
ignore_figlet(user)
UR_OBJECT user;
{
if (user->figlet) {
  user->figlet=0;
  write_user(user,"Figlets now accepted.\n");
  return;
}

user->figlet=1;
write_user(user,"Figlets now ignored.\n");
}


/*** Turn on/off webpage generator ***/
onoffweb_page()
{
if (web_page_on) {
  web_page_on=0;
  write_room(NULL,"~OLSYSTEM: ~RSWeb page generator turned: ~FROFF\n");
  return;
}

web_page_on=1;
write_room(NULL,"~OLSYSTEM: ~RSWeb page generator turned: ~FGON\n");
}


/*** Set email address ***/
set_email(user)
UR_OBJECT user;
{
if (word_count<2) {
  write_user(user,"Usage: email your_email_address\n");
  return;
}

if (strlen(word[1])>79) {
  write_user(user,"Email address too long.\n");
  return;
}

strcpy(user->email, word[1]);
if (user->vis_email)
  sprintf(text,"Email address set to %s ~FY(Visible to others)\n",user->email);
else
  sprintf(text,"Email address set to %s ~FY(Invisible to others - use ~FG.vemail~FY to change this)\n",user->email);

write_user(user,text);

/* New Autopromote feature */
if (user->level==NEW && auto_promote)
  automatic_promote(user);

}

automatic_promote(user)
UR_OBJECT user;
{
user->level++;
strcpy(user->rank,new_levels[user->sex][user->level]);

sprintf(text,"~FGAuto-promotion to level: ~RS~OL%s!\n",new_levels[user->sex][user->level]);
write_user(user,text);

sprintf(text,"~FG%s auto-promotes to level: ~RS~OL%s!\n",user->name,new_levels[user->sex][user->level]);
write_room_except(user->room,text,user);
record(user->room,text);

sprintf(text,"~FG%s auto-promotes to level: ~RS~OL%s ~RS~FT(%s)\n",user->name,new_levels[user->sex][user->level],user->email);
write_syslog(text,1);

write_user(user,"Type ~FG'.help newuser'~RS for information on setting up your account.\n");
save_user_details(user);
}


/*** Toggle visible email address ***/
set_vemail(user)
UR_OBJECT user;
{
if (user->vis_email) {
  user->vis_email=0;
  write_user(user,"Email address now invisible to all, type ~FG.vemail~RS to toggle this.\n");
  return;
}
  
user->vis_email=1;
write_user(user,"Email address to visible to all, type ~FG.vemail~RS to toggle this.\n");
}


/*** Set www address ***/
set_www(user)
UR_OBJECT user;
{
if (word_count<2) {
  write_user(user,"Usage: www your_homepage_address\n");
  return;
}

if (strlen(word[1])>79) {
  write_user(user,"Homepage address too long.\n");
  return;
}

strcpy(user->www, word[1]);
sprintf(text,"Homepage address set to %s\n",user->www);
write_user(user,text);
}


/*** Hug ***/
hug(user)
UR_OBJECT user;
{
UR_OBJECT u;
char *name;

if (user->muzzled) {
  write_user(user,"You are muzzled, you cannot hug anyone.\n");
  return;
}
if (word_count<2) {
  write_user(user,"Who do you want to hug?\n");
  return;
}
word[1][0]=toupper(word[1][0]);
if (!(u=get_user(word[1]))) {
  write_user(user,notloggedon);
  return;
}
if (u==user) {
 write_user(user,"You can't do that!\n");
  return;
}
if (u->room!=user->room) {
  write_user(user,"That user is not here.\n");
  return;
}
if (user->vis) name=user->name; else name=invisname;

sprintf(text,"You give %s a big hug!\n",u->name);
write_user(user,text);

sprintf(text,"%s gives you a ~OLbig~RS hug!\n",name);
write_user(u,text);

sprintf(text,"~OL%s~RS gives %s a ~OLbig~RS hug!\n",name,u->name);
write_room_except2(user->room,text,u,user);
record(user->room,text);
} 


/*** Beep ***/
beep(user,inpstr)
UR_OBJECT user;
char *inpstr;
{
UR_OBJECT u;

if (user->muzzled) {
  write_user(user,"You are muzzled, you cannot beep anyone.\n");
  return;
}
if (word_count<2) {
  write_user(user,"Beep who?\n");
  return;
}

word[1][0]=toupper(word[1][0]);

if (!(u=get_user(word[1]))) {
  write_user(user,notloggedon);
  return;
}
if (u==user) {
  write_user(user,"You can't do that!\n");
  return;
}
if (word_count>2) {
  inpstr=remove_first(inpstr);
  sprintf(text,"\007~OL~FR%s beeps you:~RS %s\n",user->name,inpstr);
}
else
  sprintf(text,"\007~OL~FR%s beeps you!!!\n",user->name);
write_user(u,text);
record_tell(u,text);

if (word_count>2)
  sprintf(text,"~OL~FRYou beep %s:~RS %s\n",u->name,inpstr);
else 
  sprintf(text,"~OL~FRYou beep %s!\n",u->name);
write_user(user,text);
record_tell(user,text);
}


/*** New user informatin */
newuser(user)
UR_OBJECT user;
{
UR_OBJECT u;

if (word_count<2) {
  write_user(user,"Usage: .newuser user\n");
  return;
}
if (!(u=get_user(word[1]))) {
  write_user(user,notloggedon);
  return;
}
if (u->level!=NEW) {
  write_user(user,"That user already has an account.\n");
  return;
}
sprintf(text,"~OL%s tells you:~RS For an account here type .email then your email address (Automatic message).\n",user->name);
write_user(u,text);
record_tell(u,text);

sprintf(text,"~OLYou tell %s:~RS For an account here type .email then your email address (Automatic message).\n",u->name);
write_user(user,text);
record_tell(user,text);
}


/*** Experimental BSX Support :) ***/
bsx(user)
UR_OBJECT user;
{
UR_OBJECT u;

if (word_count<2) {
  write_user(user,"Usage: .bsx <user>\n");
  return;
}

word[1][0]=toupper(word[1][0]);

if (!(u=get_user(word[1]))) {
  write_user(user,notloggedon);
  return;
}

more(u,u->socket,BSX_FILE);
write_user(user,"Done.\n");
}


/*** Room Topic Lock ***/
tlock(user)
UR_OBJECT user;
{
char *name;

if (user->muzzled) {
  write_user(user,"You are muzzled, you cannot change the topic lock.\n");
  return;
}
if (!user->room->topic[0]) {
  write_user(user,"There is no current topic.\n");
  return;
}
if (user->room->tlock>user->level) {
  sprintf(text,"You cannot alter the topic lock as it is set at a higher level than you.\n");
  write_user(user,text);
  return;
}
if (user->vis) name=user->name; else name=invisname;
if (!user->room->tlock) {
  sprintf(text,"You lock the topic at level: ~FR%s\n",level_name[user->level]);
  write_user(user,text);
  sprintf(text,"~OL%s~RS locks the topic at level: ~FR%s\n",name,level_name[user->level]);
  write_room_except(user->room,text,user);
  record(user->room,text);
  user->room->tlock=user->level;
  return;
}

write_user(user,"You remove the topic lock.\n");
sprintf(text,"~OL%s~RS removes the topic lock.\n",name);
write_room_except(user->room,text,user);
user->room->tlock=0;
}


/*** Poke ***/
poke(user)
UR_OBJECT user;
{
UR_OBJECT u;
char *name;

if (user->muzzled) {
  write_user(user,"You are muzzled, you cannot poke anyone!\n");
  return;
}
if (word_count<2) {
  write_user(user,"Who do you want to poke?\n");
  return;
}
word[1][0]=toupper(word[1][0]);
if (!(u=get_user(word[1]))) {
  write_user(user,notloggedon);
  return;
}
if (u==user) {
 write_user(user,"You can't do that!\n");
  return;
}
if (u->room!=user->room) {
  write_user(user,"That user is not here.\n");
  return;
}
if (user->vis) name=user->name; else name=invisname;

sprintf(text,"You give %s a sharp poke in the ribs!\n",u->name);
write_user(user,text);

sprintf(text,"%s gives you a sharp ~OLpoke~RS in the ribs!\n",name);
write_user(u,text);

sprintf(text,"%s gives %s a sharp ~OLpoke~RS in the ribs!\n",name,u->name);
write_room_except2(user->room,text,u,user);
record(user->room,text);
} 


/*** System Information ***/
sinfo(user,inpstr)
UR_OBJECT user;
char *inpstr;
{
if (word_count<2) {
  write_user(user,"What system information do you want to broadcast?\n");  return;
}
if (user->muzzled) {
  write_user(user,"You are muzzled, you cannot SysInfo!\n");  return;
}
if (ban_swearing && contains_swearing(inpstr)) {
  write_user(user,noswearing);  return;
}
sprintf(text,"(%s) ",user->name);
write_wiz(GOD,text,NULL);
sprintf(text,"~OLSYSTEM INFORMATION:~RS %s\n",inpstr);
write_room(NULL,text);
record(room_first,text);
}


/*************************** FIGLET FUNCTIONS *****************************/

#ifdef __STDC__
char *myalloc(size_t size)
#else
char *myalloc(size)
int size;
#endif
{
char *ptr;
#ifndef __STDC__
extern void *malloc();
#endif

if ((ptr = (char*)malloc(size))==NULL) {
  write_room(NULL,"~FR~OLSYSTEM: Malloc failed in figlet().\n");
  return NULL;
}

return ptr;

}


/****************************************************************************

	skiptoeol

	Skips to the end of a line, given a stream.

****************************************************************************/

void skiptoeol(fp)
FILE *fp;
{
int dummy;
while (dummy=getc(fp),dummy!='\n'&&dummy!=EOF) ;
}


/****************************************************************************

	clearline

  Clears both the input (inchrline) and output (outline) storage.

****************************************************************************/

void fclearline()
{
  int i;

  for (i=0;i<charheight;i++) {
	 outline[i][0] = '\0';
	 }
  outlinelen = 0;
  inchrlinelen = 0;
}


/****************************************************************************

  readfontchar

  Reads a font character from the font file, and places it in a
  newly-allocated entry in the list.

****************************************************************************/

void readfontchar(file,theord,line,maxlen)
FILE *file;
inchr theord;
char *line;
int maxlen;
{
int row,k;
char endchar;
fcharnode *fclsave;

fclsave = fcharlist;

fcharlist = (fcharnode*)myalloc(sizeof(fcharnode));
fcharlist->ord = theord;
fcharlist->thechar = (char**)myalloc(sizeof(char*)*charheight);
fcharlist->next = fclsave;

for (row=0;row<charheight;row++) {
  if (fgets(line,maxlen+1,file)==NULL) {
    line[0] = '\0';
  }
	k = MYSTRLEN(line)-1;
  while (k>=0 && isspace(line[k])) {
    k--;
  }
  if (k>=0) {
    endchar = line[k];
    while (k>=0 ? line[k]==endchar : 0) {
      k--;
    }
  }
  line[k+1] = '\0';
  fcharlist->thechar[row] = (char*)myalloc(sizeof(char)*(k+2));
  strcpy(fcharlist->thechar[row],line);
}
}


/****************************************************************************

  readfont

  Allocates memory, initializes variables, and reads in the font.
  Called near beginning of main().

****************************************************************************/

int readfont(char *fontname)
{
#define MAXFIRSTLINELEN 1000
  int i,row,numsread;
  inchr theord;
  int maxlen,cmtlines,ffright2left;
  char *fileline,magicnum[5];
  FILE *fontfile;
  char fontpath[256];
  sprintf(fontpath, "%s/%s", FIGLET_FONTS, fontname);

  fontfile=fopen(fontpath,"r");

  if (!fontfile)
    return -1;

  fscanf(fontfile,"%4s",magicnum);
  fileline = (char*)myalloc(sizeof(char)*(MAXFIRSTLINELEN+1));
  if (fgets(fileline,MAXFIRSTLINELEN+1,fontfile)==NULL) {
    fileline[0] = '\0';
  }
  
  if (MYSTRLEN(fileline)>0 ? fileline[MYSTRLEN(fileline)-1]!='\n' : 0) {
    skiptoeol(stdin);
  }
  
  numsread = sscanf(fileline,"%*c%c %d %*d %d %d %d%*[ \t]%d",
		    &hardblank,&charheight,&maxlen,&defaultmode,&cmtlines,
		    &ffright2left);
  free(fileline);
  
  for (i=1;i<=cmtlines;i++) {
    skiptoeol(fontfile);
  }
  
  if (numsread<6) {
    ffright2left = 0;
  }
  if (charheight<1) {
    charheight = 1;
  }
  if (maxlen<1) {
    maxlen = 1;
  }
  maxlen += 100; /* Give ourselves some extra room */
  
  if (right2left<0) {
    right2left = ffright2left;
  }
  if (justification<0) {
    justification = 2*right2left;
  }
  
  fileline = (char*)myalloc(sizeof(char)*(maxlen+1));
  /* Allocate "missing" character */
  fcharlist = (fcharnode*)myalloc(sizeof(fcharnode));
  fcharlist->ord = 0;
  fcharlist->thechar = (char**)myalloc(sizeof(char*)*charheight);
  fcharlist->next = NULL;
  for (row=0;row<charheight;row++) {
    fcharlist->thechar[row] = (char*)myalloc(sizeof(char));
    fcharlist->thechar[row][0] = '\0';
  }
  for (theord=' ';theord<='~';theord++) {
    readfontchar(fontfile,theord,fileline,maxlen);
  }
  for (theord= -255;theord<= -249;theord++) {
    readfontchar(fontfile,theord,fileline,maxlen);
  }
  while (fgets(fileline,maxlen+1,fontfile)==NULL?0:
	 sscanf(fileline,"%li",&theord)==1) {
    readfontchar(fontfile,theord,fileline,maxlen);
  }
  fclose(fontfile);
  free(fileline);
  return 0;
}

/****************************************************************************

  getletter

  Sets currchar to point to the font entry for the given character.
  Sets currcharwidth to the width of this character.

****************************************************************************/

void getletter(c)
inchr c;
{
fcharnode *charptr;

for (charptr=fcharlist;charptr==NULL?0:charptr->ord!=c;
     charptr=charptr->next) ;
if (charptr!=NULL) {
  currchar = charptr->thechar;
}
else {
  for (charptr=fcharlist;charptr==NULL?0:charptr->ord!=0;
       charptr=charptr->next) ;
  currchar = charptr->thechar;
}
currcharwidth = MYSTRLEN(currchar[0]);
}



/****************************************************************************

  addchar

	Attempts to add the given character onto the end of the current line.
  Returns 1 if this can be done, 0 otherwise.

****************************************************************************/

int addchar(c)
inchr c;
{
  int smushamount,row;
  char *templine;

  getletter(c);
  smushamount=0;
  if (outlinelen+currcharwidth>outlinelenlimit
      ||inchrlinelen+1>inchrlinelenlimit) {
    return 0;
  }
  
  templine = (char*)myalloc(sizeof(char)*(outlinelenlimit+1));
  for (row=0;row<charheight;row++) {
    if (right2left) {
      strcpy(templine,currchar[row]);
      strcat(templine,outline[row]+smushamount);
      strcpy(outline[row],templine);
    }
    else
      strcat(outline[row],currchar[row]+smushamount);
    
  }
  free(templine);
  outlinelen = MYSTRLEN(outline[0]);
  inchrline[inchrlinelen++] = c;
  return 1;
}


/****************************************************************************

  putstring

  Prints out the given null-terminated string, substituting blanks
  for hardblanks.  If outputwidth is 1, prints the entire string;
  otherwise prints at most outputwidth-1 characters.  Prints a newline
  at the end of the string.  The string is left-justified, centered or
  right-justified (taking outputwidth as the screen width) if
  justification is 0, 1 or 2, respectively.

****************************************************************************/

void putstring(string)
char *string;
{
int i,j=0,len;
char t;

len = MYSTRLEN(string);
if (outputwidth>1) {
  if (len>outputwidth-1) {
    len = outputwidth-1;
  }
  if (justification>0) {
    for (i=1;(3-justification)*i+len+justification-2<outputwidth;i++) {
      text[j]=' ';
      j++;
    }
  }
}
for (i=0;i<len;i++) {
  t=string[i]==hardblank?' ':string[i];
  text[j]=t;
  j++;
}
text[j]='\n';
text[j+1]='\0';
write_broadcast_figlet(text);
}


/****************************************************************************

  printline

  Prints outline using putstring, then clears the current line.

****************************************************************************/

void printline()
{
int i;

for (i=0;i<charheight;i++) {
  putstring(outline[i]);
}
fclearline();
}


/****************************************************************************

  splitline

  Splits inchrline at the last word break (bunch of consecutive blanks).
  Makes a new line out of the first part and prints it using
	printline.  Makes a new line out of the second part and returns.

****************************************************************************/

void splitline()
{
int i,gotspace,lastspace,len1,len2;
inchr *part1,*part2;

part1 = (inchr*)myalloc(sizeof(inchr)*(inchrlinelen+1));
part2 = (inchr*)myalloc(sizeof(inchr)*(inchrlinelen+1));
gotspace = 0;
for (i=inchrlinelen-1;i>=0;i--) {
  if (!gotspace && inchrline[i]==' ') {
    gotspace = 1;
    lastspace = i;
  }
  if (gotspace && inchrline[i]!=' ') {
    break;
  }
}
len1 = i+1;
len2 = inchrlinelen-lastspace-1;
for (i=0;i<len1;i++) {
  part1[i] = inchrline[i];
}
for (i=0;i<len2;i++) {
  part2[i] = inchrline[lastspace+1+i];
}
fclearline();
for (i=0;i<len1;i++) {
  addchar(part1[i]);
}
printline();
for (i=0;i<len2;i++) {
  addchar(part2[i]);
}
free(part1);
free(part2);
}


figlet(user, inpstr) 
UR_OBJECT user;
char *inpstr;
{
inchr c;
int i=0, row, wordbreakmode, char_not_added;
char *p=inpstr, *name;
fcharnode *fclsave;
char fontname[256]="standard.flf";

if (word_count<2) {
  write_user(user,"Figlet what?\n"); return;
}

/* Check to see if a font is specified */
if (*p=='-') {
  /* Get size of font name */
  while (*(p+i)!=' ') {
    i++;
    if (i==100) 
      break;
  }
  strncpy(fontname, p+1, i);
  *(fontname+i-1)='\0';
  p=p+i+1;
  
  if (word_count<3) {
    write_user(user,"Figlet what?\n"); return;
  }
}

justification = 0;
right2left = -1;

outputwidth = 80;

outlinelenlimit = outputwidth-1;

i=readfont(fontname);
if (i==-1) {
  sprintf(text,"Cannot load font %s\n",fontname);
  write_user(user,text);
  return;
}

if (user->vis) name=user->name; else name=invisname;

write_text_figlet(p,name,fontname);

/* Line alloc... */
outline = (char**)myalloc(sizeof(char*)*charheight);
for (row=0;row<charheight;row++) {
  outline[row] = (char*)myalloc(sizeof(char)*(outlinelenlimit+1));
}
inchrlinelenlimit = outputwidth*4+100;
inchrline = (inchr*)myalloc(sizeof(inchr)*(inchrlinelenlimit+1));
fclearline();
wordbreakmode = 0;

while (*p) { 
  c=*p;
  p=p+1;
  
  if (isascii(c) && isspace(c)) {
    c = (c=='\t' || c==' ') ? ' ' : '\n';
  }
  
  if ( (c>'\0' && c<' ' && c!='\n' ) || c==127) continue;
  
  /*
     Note: The following code is complex and thoroughly tested.
     Be careful when modifying!
     */
  
  do {
    char_not_added = 0;
    
    if (wordbreakmode== -1) {
      if (c==' ') {
	break;
      }
      else if (c=='\n') {
	wordbreakmode = 0;
	break;
      }
      wordbreakmode = 0;
    }
    
    if (c=='\n') {
      printline();
      wordbreakmode = 0;
    }
    
    else if (addchar(c)) {
      if (c!=' ') {
	wordbreakmode = (wordbreakmode>=2)?3:1;
      }
      else {
	wordbreakmode = (wordbreakmode>0)?2:0;
      }
    }
    
    else if (outlinelen==0) {
      for (i=0;i<charheight;i++) {
	if (right2left && outputwidth>1) {
	  putstring(currchar[i]+MYSTRLEN(currchar[i])-outlinelenlimit);
	}
	else {
	  putstring(currchar[i]);
	}
      }
      wordbreakmode = -1;
    }
    
    else if (c==' ') {
      if (wordbreakmode==2) {
	splitline();
      }
      else {
	printline();
      }
      wordbreakmode = -1;
    }
    
    else {
      if (wordbreakmode>=2) {
	splitline();
      }
      else {
	  printline();
	}
      wordbreakmode = (wordbreakmode==3)?1:0;
      char_not_added = 1;
    }
    
  } while (char_not_added);
}

if (outlinelen!=0) {
  printline();
}

/* Free up memory... */
free(inchrline);
for (row=0;row<charheight;row++)
  free(outline[row]);
free(outline);
  
/* Free up font memory... */
do {
  /* Save pointer to next node */
  fclsave=fcharlist->next;
  
  /* Free memory used by this node */
  for (row=0;row<charheight;row++)
    free(fcharlist->thechar[row]);
  free(fcharlist->thechar);
  free(fcharlist);
  
  fcharlist=fclsave;
  
} while (fclsave!=NULL);
  
return;
}

/**************************** EVENT FUNCTIONS ******************************/

void do_events()
{
set_date_time();
check_idle_and_timeout();
check_messages(0);
if (backup_on)
  do_backup(0);
if (userweb_on)
  do_web(0);
#ifndef WIN_NT
reset_alarm();
#endif
}

#ifndef WIN_NT
/* Unix timer */
reset_alarm()
{
signal(SIGALRM,do_events);
alarm(heartbeat);
}

#else

/* Windows timer */
#pragma argsused
DWORD alarm_thread(LPDWORD lpdwParam)
{
while(1) {
  Sleep(1000*heartbeat);
  do_events();
}

}
#endif

/*** login_time_out is the length of time someone can idle at login,
	user_idle_time is the length of time they can idle once logged in.
  Also ups users total login time. ***/
check_idle_and_timeout()
{
UR_OBJECT user,next;
int tm,a;

/* Use while loop here instead of for loop for when user structure gets
   destructed, we may lose ->next link and crash the program */
next=user_first;
while(next!=NULL) {
  user=next;
  next=user->next;

  if (user->type==CLONE_TYPE) 
    continue;
  user->total_login+=heartbeat; 
  if (user->level>=WIZ)
    continue; /* Don't time out wizes and gods */
  
  tm=(int)(time(0) - user->last_input);
  if (user->login && tm>=login_idle_time) {
    write_user(user,"\n\n*** Time out ***\n\n");
    disconnect_user(user);
		continue;
  }
  if (user->warned) {
    if (tm<user_idle_time-60) {  
      user->warned=0;
      write_user(user, "\n~FR*** Welcome back!  Don't go idle again, y'hear! ***\n");
      continue;
    }
    if (tm>=user_idle_time) {
      write_user(user,"\n\n\07~FR~OL*** You have been timed out. ***\n\n");
      user->autologout=1;
      disconnect_user(user);
      continue;
    }
  }
  if ((!user->afk || (user->afk && time_out_afks))
      && !user->login
      && !user->warned
      && tm>=user_idle_time-60) {
    write_user(user,"\n\07~FR*** ~OLWARNING - Input within 1 minute or you will be disconnected. ~RS~FR***\n\n");
    user->warned=1;
  }
}

/* Do some atmospherics.... */
if (atmos && atmos_no) {
  a=random(1000)%100;
  if (a<ATMOS_CHANCE && num_of_users!=0)
    atmospherics();
}

}

atmospherics()
{
int a;

/* atmos_no = number of atmos lines in memory... */
a=random(1000)%(atmos_no);
write_room(NULL,atmos_array[a]);
}


/*** Remove any expired messages from boards ***/
check_messages(force)
int force;
{
RM_OBJECT rm;
FILE *infp,*outfp;
char id[82],filename[80],line[82];
int valid,pt,write_rest;
int board_cnt,old_cnt;
static int done=0;

if (!force) {
  if (mesg_check_hour==thour && mesg_check_min==tmin) {
    if (done) return;
  }
  else {  done=0;  return;  }
}
else printf("Checking boards...\n");
done=1;
board_cnt=0;
old_cnt=0;

for(rm=room_first;rm!=NULL;rm=rm->next) {
  rm->mesg_cnt=0;
  sprintf(filename,"%s/%s.B",DATAFILES,rm->name);
  if (!(infp=fopen(filename,"r"))) continue;
	if (!(outfp=fopen("tempfile","w"))) {
    if (force) fprintf(stderr,"NUTS: Couldn't open tempfile.\n");
    write_syslog("ERROR: Couldn't open tempfile in check_messages().\n",0);
    fclose(infp);
    return;
  }
  board_cnt++;
  /* We assume that once 1 in date message is encountered all the others
     will be in date too , hence write_rest once set to 1 is never set to
     0 again */
  valid=1; write_rest=0;
  fgets(line,82,infp); /* max of 80+newline+terminator = 82 */
  while(!feof(infp)) {
    if (*line=='\n') valid=1;
    sscanf(line,"%s %d",id,&pt);
    if (!write_rest) {
      if (valid && !strcmp(id,"PT:")) {
	/* 86400 = num. of secs in a day */
	if ((int)time(0) - pt < mesg_life*86400) {
	  fputs(line,outfp);
	  rm->mesg_cnt++;
	  write_rest=1;
	}
	else old_cnt++;
	valid=0;
      }
    }
    else {
      fputs(line,outfp);
      if (valid && !strcmp(id,"PT:")) {
	rm->mesg_cnt++;  valid=0;
      }
    }
    fgets(line,82,infp);
  }
  fclose(infp);
  fclose(outfp);
  unlink(filename);
  if (!write_rest) unlink("tempfile");
  else rename("tempfile",filename);
}
if (force) printf("  %d board files checked, %d out of date messages found.\n",board_cnt,old_cnt);
else {
  sprintf(text,"~OL~FRCHECK_MESSAGES:~RS ~FG%d~RS files checked, ~FR%d~RS messages deleted.\n",board_cnt,old_cnt);
  write_syslog(text,1);
}
}


/*** Automatic backup of userfiles ***/
do_backup(force)
int force;
{
char t[200];
static int done_backup=0;
int status;
#ifndef WIN_NT
char *newargv[]={ZIP_EXEC,"-r",BACKUP_NAME,USERFILES,NULL};
int pid;
#endif

if (!force) {
  if (backup_check_hour==thour && backup_check_min==tmin) {
    if (done_backup) return;
  }
  else {  done_backup=0;  return;  }
}
done_backup=1;

write_room(NULL,"~OL~FRSYSTEM: ~RSStarting automatic backup of userfiles - Please wait\n");
write_syslog("~OL~FYSYSTEM: ~RSStarting backup of userfiles.\n",1);

/* Keep old backup */
sprintf(t,"%s.bak",BACKUP_NAME);
rename(BACKUP_NAME,t);

#ifdef WIN_NT
status=spawnl(P_WAIT,ZIP_EXEC,ZIP_EXEC,"-r",BACKUP_NAME,USERFILES,NULL);
#else
switch (pid=fork()) {
 case -1:
  sprintf(t,"~OL~FRSYSTEM: Failed fork() in do_backup()\n");
  write_syslog(t,1);
  write_room(NULL,t);
  return;
 case 0:
  execve(ZIP_EXEC,newargv,NULL);
  exit(1);
 default:
  while ( wait(&status)!=pid ) ;
  break;
}
#endif

if (((status) & 0xff00) >> 8)
  sprintf(t,"~OL~FRSYSTEM: ~RSFailed execve() in do_backup()\n");
else
  sprintf(t,"~OL~FRSYSTEM: ~RSBackup complete.\n");

write_room(NULL,t);
write_syslog(t,1);
}


/*** Automatic Web Pages ***/
do_web(force)
int force;
{
static int done_spod=0;
int status;
char t[81];
#ifndef WIN_NT
char *newargv[]={DOWEB_EXEC,NULL};
int pid;
#endif

if (!force) {
  if (spod_check_hour==thour && spod_check_min==tmin) {
    if (done_spod) return;
  }
  else {  done_spod=0;  return;  }
}

done_spod=1;

write_room(NULL,"~OL~FRSYSTEM: ~RSStarting automatic update of webpages - Please wait\n");
write_syslog("~OL~FYSYSTEM: ~RSStarting web update.\n",1);

#ifdef WIN_NT
status=spawnl(P_WAIT,DOWEB_EXEC,DOWEB_EXEC,NULL);
#else
switch (pid=fork()) {
 case -1:
  sprintf(t,"~OL~FRSYSTEM: Failed fork() in doweb()\n");
  write_syslog(t,1);
  write_room(NULL,t);
  return;
 case 0:
  execve(DOWEB_EXEC,newargv,NULL);
  exit(1);
 default:
  while ( wait(&status) !=pid ) ;
  break;
}
#endif

if (((status) & 0xff00) >> 8)
  sprintf(t,"~OL~FRSYSTEM: ~RSFailed exec in do_web()\n");
else
  sprintf(t,"~OL~FRSYSTEM: ~RSUpdate complete.\n");

write_room(NULL,t);
write_syslog(t,1);
}

/**************************** Made in England ******************************/
                    /* And Scotland.... And Wales.... */


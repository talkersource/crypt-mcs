/**************************************************************************/
/* Userinfo for Crypt userfiles                                           */
/*                                                                        */
/* (c) 1997 Bryan McPhail                                                 */
/*                                                                        */
/**************************************************************************/

#include <stdio.h>  
#include <stdlib.h>
#include <time.h>
#include <setjmp.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>

#include "cryptmcs.h"

#define EMAILS 1
#define RANKS 2
#define WWW 3
#define GENERAL 4

UR_OBJECT create_user();
void usage(char *name);

void usage(char *name)
{
printf("Usage:\n%s -emails\n%s -ranks\n%s -www\n%s -general\n",name,name,name,name);
exit(1);
}

main(int argc, char **argv)
{
FILE *fp;
char name[100],line[81],filename[80];
UR_OBJECT user;
int temp1, temp2, temp3,temp4, has_mail, has_profile,total=0,i,mode=0;
int count[3][7]={{0,0,0},{0,0,0},{0,0,0}};
long int mins;
DIR *dir;
struct dirent *entry;

/* Parse command line */
if (argc<2)
  usage(argv[0]);

if (!strcmp(argv[1],"-emails"))
  mode=EMAILS;

if (!strcmp(argv[1],"-ranks"))
  mode=RANKS;

if (!strcmp(argv[1],"-www"))
  mode=WWW;

if (!strcmp(argv[1],"-general"))
  mode=GENERAL;

if (!mode)
  usage(argv[0]);

/* Create temp user */
user=create_user();

/* Open userfiles dir */
dir = opendir(USERFILES);
if (!dir) {
  printf("Error: Cannot open userfiles directory!\n");
  exit(1);
}

/* Setup screen */
printf("Crypt user-info v1.0 - (c)1997 Bryan McPhail\n");

switch (mode) {
 case GENERAL:
  printf("\n%-12s %-8s %-8s %-4s %-4s %s\n\n","Name", "Level", "Minutes On", "Mail", "Profile","Last Login");
  break;
 case EMAILS:
  printf("\n%-12s %s\n\n","Name","Email Address");
  break;

 case WWW:
  printf("\n%-12s %-10s\n\n","Name","Homepage Address");
  break;
  
 case RANKS:
  printf("\n%-12s %-10s\n\n","Name","Rank");
  break;
}

while ((entry=readdir(dir)) != NULL) {
  /* Only grab .D files */
  if (strncmp(".D",entry->d_name+(strlen(entry->d_name)-2),2) != 0)
    continue;
  
  strcpy(name, entry->d_name);

  /* Open data file for user */
  sprintf(filename,"%s/%s",USERFILES,name);
  fp=fopen(filename,"r");
  if (!fp)
    break;
	
  /* Cut off the .D */
  temp4=strlen(name)-2;
  if (temp4<0) temp4=0;
  name[temp4]='\0';
  
  fscanf(fp,"%s",user->pass); /* password */ 
  
  fscanf(fp,"%d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d",&temp1,&temp2,&user->last_login_len,&temp3,&user->level,&user->prompt,&user->muzzled,&user->charmode_echo,&user->command_mode,&user->colour,&user->sex,&user->termtype, &user->xterm, &user->figlet, &user->vis_email, &user->examined);

  user->last_login=(time_t)temp1;
  user->total_login=(time_t)temp2;
  user->read_mail=(time_t)temp3;
  fscanf(fp,"%s\n",user->last_site);
 
  fgets(line,USER_DESC_LEN+2,fp);
  line[strlen(line)-1]=0;
  strcpy(user->pre_desc,line);
  
  if (!strcmp(user->pre_desc,"none"))
    user->pre_desc[0]='\0';
  
  /* Need to do the rest like this 'cos they may be more than 1 word each */
  fgets(line,USER_DESC_LEN+2,fp);
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

  fclose(fp);

  /* Calculate total login */
  mins=temp2/60;

  /* Check for mail & profiles */
  sprintf(filename,"%s/%s.M",USERMAIL,name);
  fp=fopen(filename,"r");
  if (!fp)
    has_mail=0; 
  else {
    has_mail=1;
    fclose(fp);
  }
  
  sprintf(filename,"%s/%s.P",USERFILES,name);
  fp=fopen(filename,"r");
  if (!fp)
    has_profile=0; 
  else {
    has_profile=1;
    fclose(fp);
  }
  
  /* Print out data to screen */

  switch (mode) {

  case EMAILS:
    printf("%-12s %s\n",name,user->email);
    break;

  case GENERAL:
    sprintf(line, "%s", ctime(&user->last_login));
    printf("%-12s %-10s %-8d %-4s %-4s %s",name, new_levels[user->sex][user->level], mins, noyes1[has_mail], noyes1[has_profile],line);
    
    break;

  case WWW:
    printf("%-12s %-10s %s\n",name, new_levels[user->sex][user->level],user->www);
    break;

  case RANKS:
    printf("%-12s %-10s\n",name,level_name[user->level]);
    break;

  }
  /* Count 'em */
  count[user->sex][user->level]++;
  total++;
}

closedir(dir);      

if (mode==GENERAL) {
  for (i=1; i<6; i++) 
    printf("\n%15s %d %15s %d %15s %d", new_levels[0][i], count[0][i], new_levels[1][i], count[1][i], new_levels[2][i], count[2][i]);
  
  printf("\n\nTotal number of users: %d\n", total);
}

return 0;
}

UR_OBJECT create_user()
{
UR_OBJECT user;

if ((user=(UR_OBJECT)malloc(sizeof(struct user_struct)))==NULL) {
  printf("Error: Memory allocation failure.\n");
  exit(1);
}

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
user->command_mode=0;
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
user->sex=0; 
user->autologout=0;
user->site_port=0;
user->termtype=0;
user->xterm=1;
user->figlet=0;
user->revline=0;
user->auth_addr=0;
user->vis_email=0;
user->examined=0;
user->email[0]='\0';
user->www[0]='\0';
user->logout_phrase[0]='\0';
user->pre_desc[0]='\0';
user->afk_mesg[0]='\0';
user->ip_num[0]='\0';
return user;
}









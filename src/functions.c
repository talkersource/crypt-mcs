/*** Web Page Generator ***/

#include "cryptmcs.h"

#include <stdio.h>
#include <time.h>
#include <fcntl.h>
#include <setjmp.h>
#include <errno.h>
#include <string.h>
#include <signal.h>


web_page()
{
UR_OBJECT u;
int total=0,mins;
FILE *fp;
char local[512];
fp=fopen(WEB_PAGE_FILE,"w");

if (!fp) {
  write_wiz(GOD,"~OL~FRSYSTEM: ~RSCouldn't open web page file!!\n",NULL);
  write_syslog("~FRSYSTEM:~RS Couldn't open web page file!!\n",1);
  return;
}

/* Set up html stuff..... */
fprintf(fp,"<html><head><title>Users on the Crypt</title>\n<meta http-equiv=refresh content=30></head>\n<body background=b_silk.jpg TEXT=F0F0F0 VLINK=ADFF2F ALINK=F0A0A0 link=77EE22 bgcolor=000011>\n");
fprintf(fp,"<!--- Automatically generated web page...  by Mish and Werewolf 1996 -->");
fprintf(fp,"\n<center><img src=onlineusers.gif height=39 width=320 alt=\"Online Users\"><p>\n\n<p><h5>Current users as of %s, %d %s, %02d:%02d </h5><p></center>\n\n",day[twday],tmday,month[tmonth],thour,tmin);
fprintf(fp,"<table align=center border=1 width=100%><tr align=center valign=top>\n<th width=20%>Name</th><th width=16%>Level</th><th width=12%>Time On</th><th width=52%>Where</th></tr>\n\n");

for(u=user_first;u!=NULL;u=u->next) {
        if (u->type==CLONE_TYPE || u->login) continue;
        mins=(int)(time(0) - u->last_login)/60;
        ++total;
        sprintf(local,"<tr><td>%s</td><td align=left>%s</td><td align=right>%d mins</td><td align=center>%s</td></tr>\n",u->name,new_levels[u->sex][u->level],mins,u->ip_name);
        fprintf(fp,local);
}

sprintf(local,"</table><p>There are a total of <b>%d</b> users.<p><p>",total);
fprintf(fp,local);

fprintf(fp,"<center><img src=bloodbar.gif><p>\n<a href=index.html>Crypt Homepage</a></body></html>\n");

fclose(fp);

/* Make the file readable to browsers... not needed on many systems... */
#ifndef WIN_NT
chmod(WEB_PAGE_FILE, 0755);
#endif
}

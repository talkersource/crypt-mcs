/**************************************************************************/
/* Background runner program for Crypt on MS-Windows                      */
/*                                                                        */
/* (c) 1997 Bryan McPhail                                                 */
/**************************************************************************/

/**************************************************************************
Send mail about this program to either of these addresses (listed in order
of preference):

  mish@tendril.force9.net
  mish@mudhole.spodnet.uk.com
  bmcphail@cs.strath.ac.uk
  crypt@churchnet2.ucsm.ac.uk

The webpage for this package is at: http://www.tendril.force9.co.uk/crypt/

At the time of writing the Crypt runs at: churchnet2.ucsm.ac.uk 3000
Webpage: http://churchnet2.ucsm.ac.uk/~crypt

*****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <string.h>

main(int argc, char **argv)
{
	PROCESS_INFORMATION a;
	STARTUPINFO b;
	int silent=0,p,i;
	char *filename=NULL, *w_dir,*config;
	char *pri_string[4]={"idle","normal","high","realtime"};
	int pri_type[4]={IDLE_PRIORITY_CLASS,NORMAL_PRIORITY_CLASS,HIGH_PRIORITY_CLASS,REALTIME_PRIORITY_CLASS};
	FILE *fp;
	char text[81], header[81], item[81];
  char *config_file="runner.cfg";

	GetStartupInfo(&b);

  if (argc>1)
  	config=argv[1];
  else
  	config=config_file;

	/* Open config file */
	fp=fopen(config,"r");
	if (!fp) {
		printf("Can't open config file %s\n", config);
		exit(1);
	}

	while (!feof(fp)) {
		fgets(text,81,fp);

		if (text[0]=='#' || text[0]=='\n' || text[0]==' ')
			continue;

		sscanf(text,"%s %s\n",header,item);

		if (!strncmp(header,"file",4))
			filename=strdup(item);

		if (!strncmp(header,"dir",3))
			w_dir=strdup(item);

		if (!strncmp(header,"priority",8)) {
			p=-1;
			for (i=0; i<3; i++)
				if (!strncmp(item, pri_string[i], strlen(pri_string[i])))
					p=i;
			if (p==-1) {
				printf("Unknown priority in config file - using normal\n");
				p=1;
			}
		}

		if (!strncmp(header,"silence",7))
			if (!strncmp(item,"yes",3)) {
				silent=1;
				break;
			}
	}

	if (!silent)
		printf("Attempting to execute %s at %s priority\nWorking dir is %s\n",filename,pri_string[p],w_dir);

	/* Create process as background task */
	if (!CreateProcess(
		filename, NULL, NULL, NULL, 0,
		DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | pri_type[p],
		NULL, w_dir, &b, &a)) {
			if (!silent)
				printf("Failed on exec of %s\n",filename);
			return 1;
			}

	if (!silent)
		printf("Executed ok - see Crypt syslog for details of talker\n");

	return 0;
}


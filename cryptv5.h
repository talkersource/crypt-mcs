/**************************************************************************/
/*                       Header file for Crypt v5.3                       */
/************** (Was) Header file for NUTS version 3.2.1 ******************/

#define VERSION "5.3b"

/* Various filenames, most files are kept in DATAFILES directory */
#define DATAFILES "datafiles"
#define USERFILES "userfiles"
#define USERMAIL "usermail"
#define HELPFILES "helpfiles"
#define CONFIGFILE "config"
#define NEWSFILE "newsfile"
#define MAPFILE "mapfile"
#define SITEBAN "siteban"
#define SILENTBAN "silent.ban"
#define PARTIAL_SITEBAN "partial.ban"
#define USERBAN "userban"
#define SYSLOG "syslog"
#define WHERE_TEXT "where.txt"
#define WHERE_FILE_A "ip_names.a"
#define WHERE_FILE_B "ip_names.b"
#define WHERE_FILE_C "ip_names.c"
#define NEWBIE_MOTD "newbie_motd"
#define RANKS_FILE "ranks"
#define FAQ_FILE "faq"
#define ATMOS_FILE "atmos"
#define TALKERS_FILE "talkers"
#define RULES_FILE "rules"
#define BSX_FILE "datafiles/xtush"

/* These files are kept in the same dir as the executable */
#define MOTD1 "motd1"
#define MOTD2 "motd2"
#define PARTIALBAN_MOTD "motd.ban"

/* Various support files...  Most systems will have zip/pkzip in path */
#define BACKUP_NAME "users.zip"
#define ZIP_EXEC "zip"
#define DOWEB_EXEC "doweb"

/* File of who is currently logged in */
#define WEB_PAGE_FILE "www/who.html"

/* This is the string used by the .thp command */
#define TALKER_HOMEPAGE "~OLSYSTEM INFORMATION:~RS Crypt Homepage - http://churchnet2.ucsm.ac.uk/~crypt\n"

#define OUT_BUFF_SIZE 80
#define MAX_WORDS 10
#define WORD_LEN 80
#define ARR_SIZE 1000
#define MAX_LINES 10
#define MAX_NO_OF_ATMOS 10 /* The amount of lines of atmospherics to allocate memory for */

#define USER_NAME_LEN 12
#define MIN_USER_NAME_LEN 2
#define NO_OF_LICKS 3 /* More than 3 licks and you're off! */
#define USER_DESC_LEN 42 /* Length of desc + pdesc + name */
#define LOG_PHRASE_LEN 78
#define PHRASE_LEN 40
#define PASS_LEN 20 /* only the 1st 8 chars will be used by crypt() though */
#define BUFSIZE 1000
#define ROOM_NAME_LEN 24
#define ROOM_LABEL_LEN 5
#define ROOM_DESC_LEN 1201
#define TOPIC_LEN 67
#define MAX_LINKS 10 
#define SITE_NAME_LEN 80
#define CONV_LINES 50
#define DNL 12

#define SHOW_PRE_LEVEL 3 /* ARCH's get prelogins */

/* For .revtell */
#define REVTELL_LINES 20
#define REVIEW_LEN 161

#define PUBLIC 0
#define PRIVATE 1
#define FIXED_PUBLIC 2
#define FIXED_PRIVATE 3
#define USER_ROOM 4

/* Internal ranks - no need to change these */
#define NEW 0
#define USER 1
#define WIZ 2
#define ARCH 3
#define GOD 4
#define UBERGOTH 5

#define USER_TYPE 0
#define CLONE_TYPE 1
#define CLONE_HEAR_NOTHING 0
#define CLONE_HEAR_SWEARS 1
#define CLONE_HEAR_ALL 2

/* Hardcoded admin password */
#define SU_PASSWORD "scott"
#define ATMOS_CHANCE 2  /* 2% chance of an atmos each cycle */

#define PROMPT_TYPES 3 /* 3 different prompt styles */

/****************************************************************************/

struct user_struct {
  char name[USER_NAME_LEN+1],desc[81],pre_desc[81],pass[PASS_LEN+6];
  char in_phrase[PHRASE_LEN+1],out_phrase[PHRASE_LEN+1];
  char buff[BUFSIZE],site[81],last_site[81],page_file[81];
  char mail_to[WORD_LEN+1],revbuff[REVTELL_LINES][REVIEW_LEN+3];
  char login_phrase[LOG_PHRASE_LEN+1],logout_phrase[LOG_PHRASE_LEN+1];
  char rank[38],old_tell[USER_NAME_LEN+1],ip_name[81],ip_num[20];
  char email[81],www[81],afk_mesg[81];

  unsigned long auth_addr;
  
  int type,port,login,socket,attempts,buffpos,filepos;
  int vis,ignall,prompt,command_mode,muzzled,charmode_echo;
  int level,misc_op,edit_line,charcnt,warned;
  int accreq,last_login_len,ignall_store,clone_hear,afk;
  int edit_op,colour,ignshout,igntell,sex,autologout,revline;
  int tell,licked,been_licked,xterm,termtype,site_port,figlet;
  int vis_email,examined,home,window_x,window_y;

  time_t last_input,last_login,total_login,read_mail;
  char *malloc_start,*malloc_end;

  struct room_struct *room,*invite_room;
  struct user_struct *prev,*next,*owner;
};

typedef struct user_struct* UR_OBJECT;
UR_OBJECT user_first,user_last,create_user();

struct room_struct {
  char name[ROOM_NAME_LEN+1];
  char label[ROOM_LABEL_LEN+1];
  char desc[ROOM_DESC_LEN+1];
  char topic[TOPIC_LEN+1];
  char conv_line[CONV_LINES][161];
  int access; /* public , private etc */
  int cln; /* conversation line number for recording */
  int mesg_cnt, tlock;
  char link_label[MAX_LINKS][ROOM_LABEL_LEN+1]; /* temp store for parse */
  
  struct room_struct *link[MAX_LINKS];
  struct room_struct *prev,*next;
};

typedef struct room_struct *RM_OBJECT;
RM_OBJECT room_first,room_last,create_room();

/****************************************************************************/

char *term_names[]={
"~FRC~FYo~FBl~FGo~FMu~FTr ~RScompatible, Xterm compatible terminal type",
"Non-colour, Xterm compatible terminal type",
"~FRC~FYo~FBl~FGo~FMu~FTr ~RScompatible, non Xterm terminal type",
"Non-colour, non Xterm terminal type"
};

char *syserror="Sorry, a system error has occured";
char *nosuchroom="There is no such room.\n";
char *nosuchuser="There is no such user.\n";
char *notloggedon="There is no one of that name logged on.\n";
char *invisenter="A presence enters the room...\n";
char *invisleave="A presence leaves the room.\n";
char *invisname="A presence";
char *noswearing="Swearing is not allowed here... Not at the moment anyway!\n";

/* Old level names... */
char *level_name[]={
"NEW","USER","WIZ","ARCH","GOD","UBERGOTH","*"
};

/* Keep the names less than or equal to 9 characters for proper formatting */
/* And keep the unknown levels the same as the level_name string above...  The
unknown strings are also used in other bits of the program for various things
(like the min login level bit) */

static char *new_levels[3][8]={
  /* Unknown, male, female */
  {"NEW","USER","WIZ","ARCH","GOD","UBERGOTH","UBERGOTH","*"},
  {"NEW","USER","WARLOCK","SORCEROR","GOD","UBERGOTH","UBERGOTH","*"},
  {"NEW","USERESS","WITCH","SORCERESS","GODDESS","UBERGOTH", "UBERGOTH","*"}
}; 

char *sex_name[]={
"unknown!", "male", "female"
};

/****************************************************************************/

char *command[]={
"quit",    "look",     "mode",      "say",    "shout",
"tell",    "emote",    "semote",    "pemote", "echo",
"go",      "ignall",   "prompt",    "desc",   "inphr",
"outphr",  "public",   "private",   "letmein","invite",
"topic",   "move",     "bcast",     "who",    "people",
"shutdown","news",     "read",      "write",  "join",
"wipe",    "search",   "review",    "help",   "status",
"version", "rmail",    "smail",     "dmail",  "from",
"entpro",  "examine",  "rmst",      "passwd", "kill",
"promote", "demote",   "listbans",  "ban",    "unban",
"vis",     "invis",    "site",      "wake",   "wizshout",
"muzzle",  "unmuzzle", "map",       "logging","minlogin",
"system",  "charecho", "clearline", "fix",    "unfix",
"viewlog", "accreq",   "revclr",    "clone",  "destroy",
"myclones","allclones","swho",      "switch", "csay",   "chear",
"swban",   "afk",      "cls",       "colour", "cemote",
"ignshout","igntell",  "suicide",   "delete", "reboot",
"banner",  "sing",     "think",     "lottery","flowers",   
"lick",    "where",    "myxterm",   "allxterm","sex",
"ranks",   "sos",      "termtype",  "tlock",  
"faq",     "atmos",    "ewtoo",     "nuts",   "hug",
"shark",   "gp",       "revtell",   "logout", "figlet",
"hp",      "thp",      "setrank",   "numpty", "whore",
"admin",   "pdesc",    "auth",      "backup", "doweb",
"ignfig",  "webpage",  "login",     "email",  "vemail",
"www",     "talkers",  "dsay",      "beep",   "newuser",
"bsx",     "gpemote",  "home",      "edit",   "boot",
"rules",   "poke",     "sinfo",     "addwhere","rose",
"window",  "*"
};


/* Values of commands , used in switch in exec_com() */
enum comvals {
QUIT,     LOOK,     MODE,     SAY,    SHOUT,
TELL,     EMOTE,    SEMOTE,   PEMOTE, ECHO,
GO,       IGNALL,   PROMPT,   DESC,   INPHRASE,
OUTPHRASE,PUBCOM,   PRIVCOM,  LETMEIN,INVITE,
TOPIC,    MOVE,     BCAST,    WHO,    PEOPLE,
SHUTDOWN, NEWS,     READ,     WRITE,  JOIN,
WIPE,     SEARCH,   REVIEW,   HELP,   STATUS,
VER,      RMAIL,    SMAIL,    DMAIL,  FROM,
ENTPRO,   EXAMINE,  RMST,     PASSWD, KILL,
PROMOTE,  DEMOTE,   LISTBANS, BAN,    UNBAN,
VIS,      INVIS,    SITE,     WAKE,   WIZSHOUT,
MUZZLE,   UNMUZZLE, MAP,      LOGGING,MINLOGIN,
SYSTEM,   CHARECHO, CLEARLINE,FIX,    UNFIX,
VIEWLOG,  ACCREQ,   REVCLR,   CREATE, DESTROY,
MYCLONES, ALLCLONES,SWHO,     SWITCH, CSAY,   CHEAR,
SWBAN,    AFK,      CLS,      COLOUR, CEMOTE,
IGNSHOUT, IGNTELL,  SUICIDE,  DELETE_C, REBOOT,
BANNER,   SING,     THINK,    LOTTERY,FLOWERS,
LICK,     WHERE,    MYXTERM,  ALLXTERM,SEX,
RANKS,    SOS,      TERMTYPE, TLOCK,
FAQ,      ATMOS,    EWTOO,    NUTS,   HUG,
SHARK,    GP,       REVTELL,  LOGOUT, FIGLET,
HP,       THP,      SETRANK,  NUMPTY, WHORE,
SU,       PDESC,    AUTH,     BACKUP, DOWEB,
IGNFIG,   WEBPAGE,  LOGIN,    EMAIL,  VEMAIL,
WWW,      TALKERS,  DSAY,     BEEP,   NEWUSER,
BSX,      GPEMOTE,  HOME,     EDIT,   BOOT,
RULES,    POKE,     SINFO,    ADDWHERE, ROSE,
WINDOW
} com_num;


/* These are the minimum levels at which the commands can be executed.
	 Alter to suit. */
int com_level[]={
NEW, NEW, NEW, NEW, USER, /* Quit */
USER,NEW,USER,USER,USER,
USER,USER,NEW, USER,USER, /* Go */
USER,USER,USER,USER,USER,
USER,WIZ, ARCH,NEW, WIZ,  /* Topic */
UBERGOTH, USER,NEW, USER,USER,
WIZ, USER,USER,NEW, NEW, /* wipe */
NEW, USER,USER,USER,USER,
USER,USER,NEW, USER,WIZ, /* entpro */
ARCH,ARCH,WIZ, ARCH,ARCH, /* promote */
ARCH,ARCH,WIZ, USER,WIZ,
WIZ, WIZ, USER,UBERGOTH, GOD, /* muzzle */
WIZ, NEW, WIZ, ARCH,ARCH, /* system */
ARCH,NEW, USER,ARCH,ARCH, /* viewlog */
ARCH,USER,NEW, ARCH,ARCH,ARCH, /* with swho added */
ARCH,USER,NEW ,NEW, ARCH,/* swban */
USER,USER,NEW, UBERGOTH, UBERGOTH,
USER,USER,USER,USER,USER, /* banner */
USER,USER,USER,ARCH,NEW,
NEW, NEW, NEW, ARCH, /* ranks */
NEW, ARCH,NEW, NEW, USER,
WIZ, USER,USER,USER,WIZ, /* shark */
USER,WIZ, USER,USER,USER, /* hp */
GOD, USER,GOD, UBERGOTH, UBERGOTH, /* su */
USER,UBERGOTH,USER,NEW,USER, /* ignfig */
USER,USER,USER,WIZ, WIZ,
GOD, USER,USER,USER,USER,
NEW, USER,GOD,UBERGOTH,USER,
NEW
};

/****************************************************************************/

#define NUM_COLS 21

char *colcode[NUM_COLS]={
/* Reset, bold, blink, reverse, underline */
"\033[0m", "\033[1m", "\033[5m", "\033[7m", "\033[4m",
/* Foreground colours:
   black, red, green, yellow/orange
   blue, magenta,turquiose(cyan), white */
"\033[30m","\033[31m","\033[32m","\033[33m",
"\033[34m","\033[35m","\033[36m","\033[37m",
/* Background colours */
"\033[40m","\033[41m","\033[42m","\033[43m",
"\033[44m","\033[45m","\033[46m","\033[47m"
};

/* Codes used in a string to produce the colours when prepended with a '~' */
char *colcom[NUM_COLS]={
"RS","OL","LI","RV","UL",
"FK","FR","FG","FY",
"FB","FM","FT","FW",
"BK","BR","BG","BY",
"BB","BM","BT","BW"
};

/****************************************************************************/

char *month[12]={
"January","February","March","April","May","June",
"July","August","September","October","November","December"
};

char *day[7]={
"Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"
};

char *noyes1[]={ " NO","YES" };
char *noyes2[]={ "NO ","YES" };
char *offon[]={ "OFF","ON " };

/* These MUST be in upper case - the contains_swearing() function converts
   the string to be checked to upper case before it compares it against
   these */
char *swear_words[]={
"FUCK","SHIT","CUNT","BASTARD","*"
};

char atmos_array[MAX_NO_OF_ATMOS][81];
char text[ARR_SIZE*2];
char word[MAX_WORDS][WORD_LEN+1];
char wrd[8][81];
char progname[40],confile[40];
char myos[81],myhost[81];
time_t boot_time;
jmp_buf jmpvar;

int port[2],listen_sock[2],wizport_level,minlogin_level;
int colour_def,password_echo,ignore_sigterm;
int max_users,max_clones,num_of_users,num_of_logins,heartbeat;
int login_idle_time,user_idle_time,config_line,word_count;
int tmonth,tday,tmday,twday,thour,tmin,tsec;
int mesg_life,system_logging,prompt_def,no_prompt;
int force_listen,gatecrash_level,min_private_users;
int ignore_mp_level,destructed,mesg_check_hour,mesg_check_min;
int ban_swearing,crash_action;
int time_out_afks,allow_caps_in_name,atmos,atmos_no;
int backup_check_hour,backup_check_min,backup_on,userweb_on;
int spod_check_hour,spod_check_min,auto_promote;
int web_page_on,save_newbies,command_mode_def;
int total_logins,peak_logins;

#ifdef WIN_NT
HANDLE hThread;
#endif

/* extern char *sys_errlist[]; */
/******************** Figlet globals & defines ************************/
#define FIGLET_FONTS "fonts"

#define MYSTRLEN(x) ((int)strlen(x)) /* Eliminate ANSI problem */
typedef long inchr; /* "char" read from stdin */
inchr *inchrline;  /* Alloc'd inchr inchrline[inchrlinelenlimit+1]; */

int inchrlinelen,inchrlinelenlimit;
typedef struct fc {
  inchr ord;
  char **thechar;  /* Alloc'd char thechar[charheight][]; */
  struct fc *next;
} fcharnode;

fcharnode *fcharlist;
char **currchar;
int currcharwidth;
char **outline;    /* Alloc'd char outline[charheight][outlinelenlimit+1]; */
int outlinelen;
int justification,right2left;
int outputwidth;
int outlinelenlimit;
char hardblank;
int charheight,defaultmode;

/**************************************************************************/
/* Functions to convert between UNIX/WIN socket functions */
#ifdef WIN_NT
  int READ_S(int sock, char *str, int len) { return recv(sock,str,len,0); }
  int WRITE_S(int sock, char *str, int len) { return send(sock,str,len,0); }
  #define CLOSE closesocket
#else
  #define READ_S read
  #define WRITE_S write
  #define CLOSE close
#endif

/**************************************************************************/


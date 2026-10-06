#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>          /* FIX #1: va_list, va_start, va_end, vfprintf */
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/wait.h>

#define MAX_IPS 256
#define MAX_PORTS 8
#define LOG_FILE "cyber_monitor.log"
#define CHECK_INTERVAL 15        /* seconds between checks per IP */
#define PING_TIMEOUT 2

/* Ports commonly associated with threats when unexpectedly open */
static const int SUSPICIOUS_PORTS[] = {21, 23, 445, 3389, 4444, 5900, 8080, 31337};
static const int NUM_SUSPICIOUS = (int)(sizeof(SUSPICIOUS_PORTS) / sizeof(SUSPICIOUS_PORTS[0]));

/* ---------------- Global state ---------------- */
typedef struct {
    char      ip[64];
    pthread_t thread;
    int       active;
    int       baseline_done;
    int       baseline_ports[MAX_PORTS];
    int       baseline_count;
} ip_target_t;

static ip_target_t     targets[MAX_IPS];
static int             target_count = 0;
static pthread_mutex_t log_mutex    = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t target_mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile sig_atomic_t stop_flag = 0;

/* ---------------- Logging (FIX #2: two separate va_list objects) ---------------- */
static void log_msg(const char *level, const char *ip, const char *fmt, ...) {
    pthread_mutex_lock(&log_mutex);

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm_info);

    /* --- write to file --- */
    FILE *fp = fopen(LOG_FILE, "a");
    if (fp) {
        va_list args;
        va_start(args, fmt);
        fprintf(fp, "[%s] [%s] [%s] ", ts, level, ip);
        vfprintf(fp, fmt, args);
        fprintf(fp, "\n");
        va_end(args);
        fclose(fp);
    }

    /* --- write to console (needs its own va_list) --- */
    va_list args2;
    va_start(args2, fmt);
    printf("[%s] [%s] [%s] ", ts, level, ip);
    vfprintf(stdout, fmt, args2);
    printf("\n");
    fflush(stdout);
    va_end(args2);

    pthread_mutex_unlock(&log_mutex);
}

/* ---------------- Helpers ---------------- */
static int is_valid_ip(const char *ip) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip, &sa.sin_addr) == 1;
}

static void tsleep(int seconds) {
    for (int i = 0; i < seconds * 10 && !stop_flag; i++) {
        usleep(100000);   /* 100 ms */
    }
}

/* ---------------- Ping check ---------------- */
static int ping_host(const char *ip) {
    pid_t pid = fork();
    if (pid == 0) {
        /* child */
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        char timeout_arg[16];
        snprintf(timeout_arg, sizeof(timeout_arg), "%d", PING_TIMEOUT);
        execlp("ping", "ping", "-c", "1", "-W", timeout_arg, ip, (char *)NULL);
        _exit(127);
    } else if (pid > 0) {
        int status = 0;
        waitpid(pid, &status, 0);
        return (WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    return 0;
}

/* ---------------- TCP port probe ---------------- */
static int tcp_port_open(const char *ip, int port, int timeout_ms) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 0;

    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((uint16_t)port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    int result = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    close(sock);
    return (result == 0) ? 1 : 0;
}

/* ---------------- Scan suspicious ports ---------------- */
static void scan_suspicious_ports(const char *ip, int *found_ports, int *found_count) {
    *found_count = 0;
    for (int i = 0; i < NUM_SUSPICIOUS && *found_count < MAX_PORTS; i++) {
        if (tcp_port_open(ip, SUSPICIOUS_PORTS[i], 800)) {
            found_ports[(*found_count)++] = SUSPICIOUS_PORTS[i];
        }
    }
}

/* ---------------- Per-IP monitor thread ---------------- */
static void *monitor_ip(void *arg) {
    ip_target_t *t = (ip_target_t *)arg;
    char ip[64];
    strncpy(ip, t->ip, sizeof(ip) - 1);
    ip[sizeof(ip) - 1] = '\0';

    log_msg("INFO", ip, "Monitoring started (thread %lu)",
            (unsigned long)pthread_self());

    while (!stop_flag) {
        /* 1. Availability */
        int up = ping_host(ip);
        if (!up) {
            log_msg("ALERT", ip, "Host is UNREACHABLE (possible DoS / downtime)");
        } else {
            log_msg("INFO", ip, "Host reachable");
        }

        /* 2. Suspicious port scan */
        int found[MAX_PORTS];
        int found_count = 0;
        scan_suspicious_ports(ip, found, &found_count);

        if (found_count > 0) {
            char buf[256] = {0};
            for (int i = 0; i < found_count; i++) {
                char tmp[16];
                snprintf(tmp, sizeof(tmp), "%d ", found[i]);
                strncat(buf, tmp, sizeof(buf) - strlen(buf) - 1);
            }
            log_msg("ALERT", ip, "Suspicious open ports detected: %s", buf);
        }

        /* 3. Baseline comparison */
        if (!t->baseline_done) {
            t->baseline_count = found_count;
            for (int i = 0; i < found_count; i++) {
                t->baseline_ports[i] = found[i];
            }
            t->baseline_done = 1;
            log_msg("INFO", ip, "Baseline captured (%d suspicious ports)", found_count);
        } else {
            for (int i = 0; i < found_count; i++) {
                int known = 0;
                for (int j = 0; j < t->baseline_count; j++) {
                    if (found[i] == t->baseline_ports[j]) { known = 1; break; }
                }
                if (!known) {
                    log_msg("ALERT", ip,
                            "NEW open port %d since baseline (possible intrusion)",
                            found[i]);
                }
            }
        }

        tsleep(CHECK_INTERVAL);
    }

    log_msg("INFO", ip, "Monitoring stopped");
    return NULL;
}

/* ---------------- Ctrl+C handler ---------------- */
static void handle_sigint(int sig) {
    (void)sig;
    stop_flag = 1;
}

/* ---------------- Add target ---------------- */
static int add_target(const char *ip) {
    if (!is_valid_ip(ip)) {
        fprintf(stderr, "[ERROR] Invalid IPv4 address: %s\n", ip);
        return -1;
    }

    pthread_mutex_lock(&target_mutex);

    if (target_count >= MAX_IPS) {
        pthread_mutex_unlock(&target_mutex);
        fprintf(stderr, "[ERROR] Max targets reached\n");
        return -1;
    }

    for (int i = 0; i < target_count; i++) {
        if (strcmp(targets[i].ip, ip) == 0) {
            pthread_mutex_unlock(&target_mutex);
            fprintf(stderr, "[WARN] IP %s already monitored\n", ip);
            return -1;
        }
    }

    ip_target_t *t = &targets[target_count];
    memset(t, 0, sizeof(*t));
    strncpy(t->ip, ip, sizeof(t->ip) - 1);
    t->active = 1;

    if (pthread_create(&t->thread, NULL, monitor_ip, t) != 0) {
        pthread_mutex_unlock(&target_mutex);
        fprintf(stderr, "[ERROR] Failed to start thread for %s\n", ip);
        return -1;
    }

    printf("[+] Now monitoring: %s\n", ip);
    target_count++;

    pthread_mutex_unlock(&target_mutex);
    return 0;
}

/* ---------------- CLI ---------------- */
static void print_banner(void) {
    printf("\n");
    printf("===========================================\n");
    printf("  CYBER SECURITY IP MONITOR  (C / pthreads)\n");
    printf("===========================================\n");
    printf(" Commands:\n");
    printf("   add <ip>      - start monitoring an IP\n");
    printf("   list          - show monitored IPs\n");
    printf("   help          - show this menu\n");
    printf("   quit / exit   - stop all and exit\n");
    printf("===========================================\n\n");
}

static void list_targets(void) {
    pthread_mutex_lock(&target_mutex);
    if (target_count == 0) {
        printf("(no IPs monitored yet)\n");
    } else {
        printf("Monitoring %d IP(s):\n", target_count);
        for (int i = 0; i < target_count; i++) {
            printf("  [%d] %s\n", i + 1, targets[i].ip);
        }
    }
    pthread_mutex_unlock(&target_mutex);
}

static void interactive_loop(void) {
    char line[256];
    print_banner();

    while (!stop_flag) {
        printf("monitor> ");
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin)) break;
        line[strcspn(line, "\n")] = '\0';
        if (strlen(line) == 0) continue;

        char cmd[64] = {0};
        char arg[64] = {0};
        sscanf(line, "%63s %63s", cmd, arg);

        if (strcmp(cmd, "add") == 0) {
            if (arg[0] == '\0') {
                printf("Usage: add <ip>\n");
            } else {
                add_target(arg);
            }
        } else if (strcmp(cmd, "list") == 0) {
            list_targets();
        } else if (strcmp(cmd, "help") == 0) {
            print_banner();
        } else if (strcmp(cmd, "quit") == 0 || strcmp(cmd, "exit") == 0) {
            break;
        } else {
            printf("Unknown command. Type 'help'.\n");
        }
    }
}

/* ---------------- Main ---------------- */
int main(int argc, char *argv[]) {
    signal(SIGINT,  handle_sigint);
    signal(SIGTERM, handle_sigint);

    printf("[*] Log file: %s\n", LOG_FILE);

    /* Add IPs from command line: ./untitled 8.8.8.8 1.1.1.1 */
    for (int i = 1; i < argc; i++) {
        add_target(argv[i]);
    }

    interactive_loop();

    printf("\n[*] Shutting down, joining threads...\n");
    stop_flag = 1;

    pthread_mutex_lock(&target_mutex);
    for (int i = 0; i < target_count; i++) {
        pthread_join(targets[i].thread, NULL);
    }
    pthread_mutex_unlock(&target_mutex);

    printf("[*] Done. Check %s for full log.\n", LOG_FILE);
    return 0;
}

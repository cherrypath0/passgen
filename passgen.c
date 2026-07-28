#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#endif

#define VERSION "1.0.0"
#define DEFAULT_CHARSET "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+"
#define MAX_AMOUNT 500

typedef struct {
    int amount;
    int count;
    int no_letters;
    int no_numbers;
    int no_uppercase;
    int no_lowercase;
    int no_symbols;
    const char *custom_set;
    int help;
    int version;
} Options;

/* Help & Version */

static void print_help(const char *prog)
{
    printf("Usage: %s [OPTIONS]\n\n", prog);
    printf("A secure cross-platform password generator.\n\n");
    printf("Options:\n");
    printf("  -?, --help              Show this help message and exit\n");
    printf("  -v, --version           Show version information and exit\n");
    printf("  -a, --amount <N>        Number of passwords to generate (1-100, default: 1)\n");
    printf("  -c, --count <N>         Characters per password (default: 16)\n");
    printf("  --no-letters            Exclude all letters (A-Z, a-z)\n");
    printf("  --no-numbers            Exclude numbers (0-9)\n");
    printf("  --no-uppercase          Exclude uppercase letters (A-Z)\n");
    printf("  --no-lowercase          Exclude lowercase letters (a-z)\n");
    printf("  --no-symbols            Exclude symbols\n");
    printf("  -s, --set <STRING>      Use a custom character set\n");
}

static void print_version(void)
{
    printf("passgen version %s\n", VERSION);
}

/* Argument parsing */

static int parse_args(int argc, char *argv[], Options *opts)
{
    opts->amount      = 1;
    opts->count       = 16;
    opts->no_letters  = 0;
    opts->no_numbers  = 0;
    opts->no_uppercase= 0;
    opts->no_lowercase= 0;
    opts->no_symbols  = 0;
    opts->custom_set  = NULL;
    opts->help        = 0;
    opts->version     = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-?") == 0 || strcmp(argv[i], "--help") == 0) {
            opts->help = 1;
        }
        else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            opts->version = 1;
        }
        else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--amount") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: %s requires an argument.\n", argv[i]);
                return 1;
            }
            opts->amount = atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--count") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: %s requires an argument.\n", argv[i]);
                return 1;
            }
            opts->count = atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "--no-letters") == 0) {
            opts->no_letters = 1;
        }
        else if (strcmp(argv[i], "--no-numbers") == 0) {
            opts->no_numbers = 1;
        }
        else if (strcmp(argv[i], "--no-uppercase") == 0) {
            opts->no_uppercase = 1;
        }
        else if (strcmp(argv[i], "--no-lowercase") == 0) {
            opts->no_lowercase = 1;
        }
        else if (strcmp(argv[i], "--no-symbols") == 0) {
            opts->no_symbols = 1;
        }
        else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--set") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: %s requires an argument.\n", argv[i]);
                return 1;
            }
            opts->custom_set = argv[++i];
        }
        else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            return 1;
        }
    }
    return 0;
}

/* Secure random byte generation */

#ifdef _WIN32

static HCRYPTPROV hCryptProv = 0;

static int init_random(void)
{
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL,
                             PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return -1;
    }
    return 0;
}

static void cleanup_random(void)
{
    if (hCryptProv) {
        CryptReleaseContext(hCryptProv, 0);
        hCryptProv = 0;
    }
}

static int get_random_bytes(unsigned char *buf, size_t len)
{
    if (!hCryptProv) return -1;
    if (!CryptGenRandom(hCryptProv, (DWORD)len, buf)) {
        return -1;
    }
    return 0;
}

#else /* Linux / macOS */

static int urandom_fd = -1;

static int init_random(void)
{
    urandom_fd = open("/dev/urandom", O_RDONLY);
    if (urandom_fd < 0) {
        return -1;
    }
    return 0;
}

static void cleanup_random(void)
{
    if (urandom_fd >= 0) {
        close(urandom_fd);
        urandom_fd = -1;
    }
}

static int get_random_bytes(unsigned char *buf, size_t len)
{
    if (urandom_fd < 0) return -1;

    size_t total = 0;
    while (total < len) {
        ssize_t n = read(urandom_fd, buf + total, len - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        total += (size_t)n;
    }
    return 0;
}

#endif

/* Unbiased random index (rejection sampling) */

static int random_index(int max, unsigned char *out)
{
    if (max <= 0) return -1;

    unsigned char r;
    unsigned int limit = 256 - (256 % (unsigned int)max);

    do {
        if (get_random_bytes(&r, 1) != 0) {
            return -1;
        }
    } while ((unsigned int)r >= limit);

    *out = r % (unsigned char)max;
    return 0;
}

/* Utility helpers */

static int count_unique_chars(const char *str)
{
    int seen[256] = {0};
    int count = 0;

    for (size_t i = 0; str[i]; i++) {
        unsigned char c = (unsigned char)str[i];
        if (!seen[c]) {
            seen[c] = 1;
            count++;
        }
    }
    return count;
}

/* Returns 1 if a security warning should be shown */
static int should_warn(const Options *opts)
{
    int no_flags = 0;
    if (opts->no_letters)   no_flags++;
    if (opts->no_numbers)   no_flags++;
    if (opts->no_uppercase) no_flags++;
    if (opts->no_lowercase) no_flags++;
    if (opts->no_symbols)   no_flags++;

    if (opts->count < 8) return 1;
    if (no_flags > 2) return 1;
    if (opts->custom_set && count_unique_chars(opts->custom_set) < 16) return 1;

    return 0;
}

/* Build the final charset from base + filters. Returns length. */
static int build_charset(const Options *opts, char *out, size_t out_size)
{
    const char *base = opts->custom_set ? opts->custom_set : DEFAULT_CHARSET;
    size_t j = 0;

    for (size_t i = 0; base[i] && j < out_size - 1; i++) {
        char c = base[i];
        int is_upper = isupper((unsigned char)c);
        int is_lower = islower((unsigned char)c);
        int is_digit = isdigit((unsigned char)c);
        int is_letter = is_upper || is_lower;
        int is_symbol = !is_letter && !is_digit;

        if (opts->no_letters   && is_letter) continue;
        if (opts->no_numbers   && is_digit)  continue;
        if (opts->no_uppercase && is_upper)  continue;
        if (opts->no_lowercase && is_lower)  continue;
        if (opts->no_symbols   && is_symbol) continue;

        out[j++] = c;
    }

    out[j] = '\0';
    return (int)j;
}

/* ------------------------------------------------------------------ */
/* Main                                                               */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    Options opts;

    if (parse_args(argc, argv, &opts) != 0) {
        return 1;
    }

    if (opts.help) {
        print_help(argv[0]);
        return 0;
    }

    if (opts.version) {
        print_version();
        return 0;
    }

    if (opts.count <= 0) {
        fprintf(stderr, "Error: Password length must be greater than 0.\n");
        return 1;
    }

    if (opts.amount < 1) {
        opts.amount = 1;
    }

    char charset[512];
    int charset_len = build_charset(&opts, charset, sizeof(charset));

    if (charset_len == 0) {
        fprintf(stderr, "Error: Character set is empty. Cannot generate passwords.\n");
        return 1;
    }

    /* Security warning prompt */
    if (should_warn(&opts)) {
        printf("Security Warning: One or more of these settings could potentially generate weak passwords, are you sure you want to continue? [y/N]: ");
        fflush(stdout);

        char response[16];
        if (fgets(response, sizeof(response), stdin) == NULL) {
            return 1;
        }
        if (response[0] != 'y' && response[0] != 'Y') {
            printf("Aborted.\n");
            return 0;
        }
    }

    /* Initialize secure RNG */
    if (init_random() != 0) {
        fprintf(stderr, "Error: Failed to initialize secure random number generator.\n");
        return 1;
    }

    /* Generate passwords */
    for (int i = 0; i < opts.amount; i++) {
        for (int j = 0; j < opts.count; j++) {
            unsigned char idx;
            if (random_index(charset_len, &idx) != 0) {
                fprintf(stderr, "Error: Failed to generate random data.\n");
                cleanup_random();
                return 1;
            }
            putchar(charset[idx]);
        }
        putchar('\n');
    }

    cleanup_random();

    return 0;
}
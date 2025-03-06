#include <X11/Xlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <signal.h>

#define DEFAULT_ENTROPY_SIZE 16
#define MAX_ENTROPY_SIZE 256
#define OUTPUT_SIZE 512
#define SAMPLE_DELAY 200000  // 200ms in microseconds

static volatile int running = 1;

void signal_handler(int signum) {
    running = 0;
}

const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"$%^&*()_-+={}[]#~@;:/?.>,<|";

void bytes_to_hex(const unsigned char *bytes, char *hex, int len) {
    if (!bytes || !hex) return;
    for (int i = 0; i < len; i++) {
        sprintf(hex + (i * 2), "%02x", bytes[i]);
    }
    hex[len * 2] = '\0';
}

void bytes_to_chars(const unsigned char *bytes, char *output, int len) {
    if (!bytes || !output) return;
    size_t charset_len = strlen(charset);
    for (int i = 0; i < len; i++) {
        output[i] = charset[bytes[i] % charset_len];
    }
    output[len] = '\0';
}

int main(void) {
    Display *display = NULL;
    unsigned char *entropy = NULL;
    char *output = NULL;
    EVP_MD_CTX *mdctx = NULL;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    int entropy_size = DEFAULT_ENTROPY_SIZE;
    int use_chars = 0;
    int status = EXIT_FAILURE;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    printf("Enter desired number of hex bytes (default is 16, max 256): ");
    char input[10];
    if (fgets(input, sizeof(input), stdin)) {
        int requested_size = atoi(input);
        if (requested_size > 0 && requested_size <= MAX_ENTROPY_SIZE) {
            entropy_size = requested_size;
        }
    }

    printf("Generate character-based password instead of hex? (1=yes, 0=no): ");
    if (fgets(input, sizeof(input), stdin)) {
        use_chars = atoi(input) == 1;
    }

    printf("Using %d bytes for entropy collection\n\n", entropy_size);

    size_t output_size = use_chars ? (entropy_size + 1) : (entropy_size * 2 + 1);
    entropy = malloc(entropy_size);
    output = malloc(output_size);

    if (!entropy || !output) {
        fprintf(stderr, "Memory allocation failed\n");
        goto cleanup;
    }

    memset(entropy, 0, entropy_size);
    memset(output, 0, output_size);

    display = XOpenDisplay(NULL);
    if (!display) {
        fprintf(stderr, "Cannot open display\n");
        goto cleanup;
    }

    Window root = DefaultRootWindow(display);
    XSelectInput(display, root, PointerMotionMask);

    int count = 0;
    struct timespec last_time, current_time;
    clock_gettime(CLOCK_MONOTONIC, &last_time);

    printf("Please move your mouse to collect entropy...\n");
    printf("Take your time, each mouse movement is being recorded.\n");

    Window root_return, child_return;
    int root_x, root_y, win_x, win_y;
    unsigned int mask_return;
    int last_x = 0, last_y = 0;

    while (running && count < entropy_size) {
        if (XQueryPointer(display, root, &root_return, &child_return,
                         &root_x, &root_y, &win_x, &win_y, &mask_return)) {
            
            clock_gettime(CLOCK_MONOTONIC, &current_time);
            long time_diff = (current_time.tv_sec - last_time.tv_sec) * 1000000 +
                            (current_time.tv_nsec - last_time.tv_nsec) / 1000;

            if (time_diff > SAMPLE_DELAY && (root_x != last_x || root_y != last_y)) {
                unsigned char random_byte;
                if (RAND_bytes(&random_byte, 1) != 1) {
                    fprintf(stderr, "Failed to generate random byte\n");
                    goto cleanup;
                }
                
                entropy[count] = (root_x ^ root_y ^ current_time.tv_nsec ^ random_byte) & 0xFF;
                
                count++;
                printf("\rProgress: %d%% [", (count * 100) / entropy_size);
                for(int i = 0; i < count * 20 / entropy_size; i++) printf("#");
                for(int i = count * 20 / entropy_size; i < 20; i++) printf("-");
                printf("]");
                fflush(stdout);

                last_time = current_time;
                last_x = root_x;
                last_y = root_y;
            }
        }
        usleep(10000);
    }

    printf("\n\nEntropy collection completed!\n\n");
    
    if (use_chars) {
        bytes_to_chars(entropy, output, entropy_size);
        printf("Random Password: %s", output);
    } else {
        bytes_to_hex(entropy, output, entropy_size);
        printf("Random String: %s", output);
    }

    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "Failed to create hash context\n");
        goto cleanup;
    }

    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, entropy, entropy_size);
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);

    char sha256_hex[65];
    bytes_to_hex(hash, sha256_hex, 32);
    printf("\nSHA256: %s\n", sha256_hex);

    status = EXIT_SUCCESS;

cleanup:
    if (mdctx) EVP_MD_CTX_free(mdctx);
    if (display) XCloseDisplay(display);
    if (entropy) {
        memset(entropy, 0, entropy_size);
        free(entropy);
    }
    if (output) {
        memset(output, 0, output_size);
        free(output);
    }
    
    return status;
}
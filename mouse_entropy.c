#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>
#include <stdlib.h>

#define DEFAULT_ENTROPY_SIZE 16
#define MAX_ENTROPY_SIZE 256
#define OUTPUT_SIZE 512
#define SAMPLE_DELAY 200

const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"$%^&*()_-+={}[]#~@;:/?.>,<|";

void bytes_to_hex(unsigned char *bytes, char *hex, int len) {
    for (int i = 0; i < len; i++) {
        sprintf(hex + (i * 2), "%02x", bytes[i]);
    }
}

void bytes_to_chars(unsigned char *bytes, char *output, int len) {
    int charset_len = strlen(charset);
    for (int i = 0; i < len; i++) {
        output[i] = charset[bytes[i] % charset_len];
    }
    output[len] = '\0';
}

int main() {
    int entropy_size = DEFAULT_ENTROPY_SIZE;
    int use_chars = 0;
    
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

    POINT mousePos, lastPos = {0, 0};
    unsigned char *entropy = (unsigned char *)malloc(entropy_size);
    char *output = (char *)malloc(use_chars ? entropy_size + 1 : entropy_size * 2 + 1);
    int count = 0;
    DWORD lastTime = 0;
    
    HCRYPTPROV hCryptProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE hash[32];
    DWORD hashLen = 32;

    if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT | CRYPT_NEWKEYSET)) {
            printf("CryptAcquireContext failed\n");
            free(entropy);
            free(output);
            return 1;
        }
    }

    printf("Please move your mouse to collect entropy...\n");
    printf("Take your time, each mouse movement is being recorded.\n");

    while (count < entropy_size) {
        GetCursorPos(&mousePos);
        DWORD currentTime = GetTickCount();
        
        if (currentTime - lastTime > SAMPLE_DELAY && 
            (mousePos.x != lastPos.x || mousePos.y != lastPos.y)) {
            entropy[count] = (mousePos.x ^ mousePos.y ^ currentTime) & 0xFF;
            count++;
            printf("\rProgress: %d%% [", (count * 100) / entropy_size);
            for(int i = 0; i < count * 20 / entropy_size; i++) printf("#");
            for(int i = count * 20 / entropy_size; i < 20; i++) printf("-");
            printf("]");
            fflush(stdout);
            lastTime = currentTime;
            lastPos = mousePos;
        }
        Sleep(10);
    }

    printf("\n\nEntropy collection completed!\n\n");
    
    if (use_chars) {
        bytes_to_chars(entropy, output, entropy_size);
        printf("Random Password: %s\n", output);
    } else {
        bytes_to_hex(entropy, output, entropy_size);
        printf("Random String: %s\n", output);
    }

    if(!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) {
        printf("Error code: %lu\n", GetLastError());
        CryptReleaseContext(hCryptProv, 0);
        free(entropy);
        free(output);
        return 1;
    }

    if(!CryptHashData(hHash, entropy, entropy_size, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        free(entropy);
        free(output);
        return 1;
    }

    if(!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        free(entropy);
        free(output);
        return 1;
    }

    bytes_to_hex(hash, output, 32);
    printf("SHA256: %s\n", output);
    fflush(stdout);

    CryptDestroyHash(hHash);
    CryptReleaseContext(hCryptProv, 0);
    free(entropy);
    free(output);
    return 0;
}
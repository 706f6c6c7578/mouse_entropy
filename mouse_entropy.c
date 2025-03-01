#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>
#include <stdlib.h>

#define DEFAULT_ENTROPY_SIZE 16  // Default is 16 bytes (32 hex chars)
#define MAX_ENTROPY_SIZE 256     // Maximum allowed size
#define OUTPUT_SIZE 512          // Increased to handle larger outputs
#define SAMPLE_DELAY 200         // 200ms for comfortable sampling

void bytes_to_hex(unsigned char *bytes, char *hex, int len) {
    for (int i = 0; i < len; i++) {
        sprintf(hex + (i * 2), "%02x", bytes[i]);
    }
}

int main() {
    int entropy_size = DEFAULT_ENTROPY_SIZE;
    
    printf("Enter desired number of hex bytes (default is 16, max 256): ");
    char input[10];
    if (fgets(input, sizeof(input), stdin)) {
        int requested_size = atoi(input);
        if (requested_size > 0 && requested_size <= MAX_ENTROPY_SIZE) {
            entropy_size = requested_size;
        }
    }
    printf("Using %d bytes for entropy collection\n\n", entropy_size);

    POINT mousePos, lastPos = {0, 0};
    unsigned char *entropy = (unsigned char *)malloc(entropy_size);
    char *hex_output = (char *)malloc(entropy_size * 2 + 1);
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
            free(hex_output);
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
    bytes_to_hex(entropy, hex_output, entropy_size);
    printf("Random String: %s\n", hex_output);

    if(!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) {
        printf("Error code: %lu\n", GetLastError());
        CryptReleaseContext(hCryptProv, 0);
        free(entropy);
        free(hex_output);
        return 1;
    }

    if(!CryptHashData(hHash, entropy, entropy_size, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        free(entropy);
        free(hex_output);
        return 1;
    }

    if(!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        free(entropy);
        free(hex_output);
        return 1;
    }

    bytes_to_hex(hash, hex_output, 32);
    printf("SHA256: %s\n", hex_output);

    // Cleanup
    CryptDestroyHash(hHash);
    CryptReleaseContext(hCryptProv, 0);
    free(entropy);
    free(hex_output);
    return 0;
}

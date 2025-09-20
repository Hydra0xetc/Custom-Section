#include <stdio.h>

// --- Custom Section untuk Metadata ---
// Kita definisikan sebuah struct untuk metadata
typedef struct {
    unsigned int version;
    const char* author;
    const char* description;
} Metadata;

// Tempatkan instance Metadata ini ke dalam custom section bernama ".my_metadata"
// 'used' attribute memastikan variabel ini tidak dioptimasi keluar oleh compiler
Metadata my_app_metadata __attribute__((section(".my_metadata"), used)) = {
    .version = 100, // Versi 1.0.0
    .author = "Gemini CLI Agent",
    .description = "A custom application with embedded metadata and functions.",
};

// --- Custom Section untuk Fungsi ---
// Tempatkan fungsi ini ke dalam custom section bernama ".my_functions"
void __attribute__((section(".my_functions"))) print_metadata_info() {
    printf("--- Metadata Info ---\
");
    printf("Version: %u\n", my_app_metadata.version);
    printf("Author: %s\n", my_app_metadata.author);
    printf("Description: %s\n", my_app_metadata.description);
    printf("---------------------\n");
}

// Fungsi utama (main)
int main() {
    printf("Aplikasi dimulai.\n");

    // Panggil fungsi dari custom section
    print_metadata_info();

    printf("Aplikasi selesai.\n");
    return 0;
}

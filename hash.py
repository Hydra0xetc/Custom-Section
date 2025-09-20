#!/usr/bin/env python3
import hashlib

def calculate_section_hash(binary_path, section_name):
    """Menghitung SHA256 hash dari section ELF secara manual"""
    try:
        with open(binary_path, 'rb') as f:
            elf_data = f.read()
            
        # Parse ELF header (64-bit)
        if elf_data[0:4] != b'\x7fELF':
            print("Error: Bukan file ELF yang valid")
            return None
            
        # Dapatkan offset section headers
        section_header_offset = int.from_bytes(elf_data[40:48], byteorder='little')
        num_sections = int.from_bytes(elf_data[60:62], byteorder='little')
        section_header_size = 64  # Size Elf64_Shdr
        
        # Cari section string table
        shstrtab_index = elf_data[62]  # e_shstrndx
        shstrtab_header_offset = section_header_offset + (shstrtab_index * section_header_size)
        
        # Dapatkan section string table
        shstrtab_offset = int.from_bytes(elf_data[shstrtab_header_offset+24:shstrtab_header_offset+32], byteorder='little')
        shstrtab_size = int.from_bytes(elf_data[shstrtab_header_offset+32:shstrtab_header_offset+40], byteorder='little')
        shstrtab_data = elf_data[shstrtab_offset:shstrtab_offset+shstrtab_size]
        
        # Cari section yang dituju
        for i in range(num_sections):
            section_header_start = section_header_offset + (i * section_header_size)
            
            # Dapatkan nama section dari string table
            name_offset = int.from_bytes(elf_data[section_header_start:section_header_start+4], byteorder='little')
            name = shstrtab_data[name_offset:].split(b'\x00')[0].decode('ascii')
            
            if name == section_name:
                # Dapatkan data section
                section_offset = int.from_bytes(elf_data[section_header_start+24:section_header_start+32], byteorder='little')
                section_size = int.from_bytes(elf_data[section_header_start+32:section_header_start+40], byteorder='little')
                section_data = elf_data[section_offset:section_offset+section_size]
                
                # Hitung SHA256
                sha256_hash = hashlib.sha256(section_data).hexdigest()
                return sha256_hash
                
        print(f"Error: Section '{section_name}' tidak ditemukan")
        return None
        
    except Exception as e:
        print(f"Error: {e}")
        return None

def hex_to_array(hex_str):
    """Convert hex string to C array format"""
    if len(hex_str) != 64:
        print("Error: Hex string harus 64 karakter (32 bytes)")
        return
    
    bytes_list = [f"0x{hex_str[i:i+2]}" for i in range(0, len(hex_str), 2)]
    
    print("const unsigned char EXPECTED_HASH[EVP_MAX_MD_SIZE] = {")
    for i in range(0, len(bytes_list), 8):
        line = ", ".join(bytes_list[i:i+8])
        print(f"    {line},")
    print("};")

# Contoh penggunaan
if __name__ == "__main__":
    binary_path = "./protected_app"  # Ganti dengan path binary Anda
    section_name = ".anti_debug_trap"  # Ganti dengan nama section
    
    # Hitung hash section
    hex_str = calculate_section_hash(binary_path, section_name)
    
    if hex_str:
        print(f"SHA256 Hash dari section '{section_name}': {hex_str}")
        print("\nFormat array C:")
        hex_to_array(hex_str)

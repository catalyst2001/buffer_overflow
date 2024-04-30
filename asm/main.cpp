#include <intrin.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#if 0
#include <Windows.h>

__declspec(naked) void myfunc()
{
  __asm __volatile {

    /* func1 */
  _func1:
    push ebp
    mov ebp, esp

    int 3          //breakpoint for debugger
    mov eax, 10
    xor ebx, ebx
  _push_to_stack:
    inc ebx
    push ebx
    dec eax
    cmp eax, 0
    jnz _push_to_stack
    
    mov eax, 10
  _pop_from_stack:
    pop ebx
    dec eax
    cmp eax, 0
    jnz _pop_from_stack
    call _func2
    mov esp, ebp
    pop ebp
    ret

    int 3h

    /* func 2 */
  _func2:
    push ebp
    mov ebp, esp
    int 3h //breakpoint for debugger
    mov esp, ebp
    pop ebp
    ret
  };
}


class bytewriter
{
  size_t pos;
  char *p_data;
public:
  bytewriter(char *p_dst) : pos(0), p_data(p_dst) {}
  ~bytewriter() {}

  void write8(int v) {
    p_data[pos] = v & 0xff;
    pos++;
  }

  void write(int v, int count) {
    for (int i = 0; i < count; i++) {
      p_data[pos] = v & 0xff;
      pos++;
    }
  }

  void write_random(int count) {
    srand((unsigned int)time(NULL));
    for (int i = 0; i < count; i++) {
      p_data[pos] = rand() % 255;
      pos++;
    }
  }

  void write16(int v) {
    *((short *)&p_data[pos]) = v;
    pos += sizeof(short);
  }

  void write32(int v) {
    *((int *)&p_data[pos]) = v;
    pos += sizeof(int);
  }
};

//16 nops == patch pattern
void patch(char *p_src)
{
  bytewriter writer(p_src);
  writer.write8(0xe9); // jmp - 0xe9
  writer.write32(9); // rel32 (+4 bytes = 5)
  //writer.write_random(9); // 16-5=11

  /* try write jumps */
  writer.write32(0xAAAAAAAA);
  writer.write32(0xAAAAAAAA);
}

#ifdef _MSC_VER
FILE *fopen_wrap(const char *f, const char *m)
{
  FILE *fp;
  fopen_s(&fp, f, m);
  return fp;
}
#define fopen(f, m) fopen_wrap(f, m)
#endif

char *sig_scan2(char *p_addr_start, size_t size, const char *p_sig, size_t sig_length)
{
  if (!p_addr_start || !p_sig || sig_length == 0 || size < sig_length)
    return nullptr;

  for (size_t start_offset = 0; start_offset <= size - sig_length; ++start_offset) {
    if (!memcmp(&p_addr_start[start_offset], p_sig, sig_length)) {
      return &p_addr_start[start_offset];
    }
  }
  return nullptr;
}

char *sig_scan(char *p_addr_start, size_t size, const char *p_sig, size_t sig_length)
{
  size_t start_offset = 0;
  for (size_t i = 0; i < size - start_offset; i++) {
    /* pattern not found */
    if (size - start_offset < sig_length)
      return nullptr;

    char *p_pat_start = &p_addr_start[start_offset + i];
    if (!memcmp(p_pat_start, p_sig, sig_length)) {
      return p_pat_start;
    }
    start_offset++;
  }
  return nullptr;
}

#define VIRTUAL_TO_RVA(virtual_addr, base_addr) (virtual_addr - base_addr)

bool patch_pe(const char *p_pename, const char *p_outname, const char *p_signature, size_t sig_length)
{
  char *p_pat;
  char *p_base;
  long  size;
  uint32_t num_patches = 0;
  size_t remaining_size;

  FILE *fp = fopen(p_pename, "rb");
  if (!fp) {
    printf("failed to open file\n");
    return false;
  }

  fseek(fp, 0, SEEK_END);
  size = ftell(fp);
  fseek(fp, 0, SEEK_SET);

  if (!size) {
    printf("empty file\n");
    return false;
  }

  /* allocate memory buffer */
  p_base = (char *)malloc(size);
  if (!p_base) {
    printf("failed to allocate %d bytes\n", size);
    return false;
  }

  /* load data from file */
  if (fread(p_base, 1, (size_t)size, fp) != (size_t)size) {
    printf("reading %d bytes from file failed\n", size);
    free(p_base);
    return false;
  }
  fclose(fp);

  /* parse PE */
  PIMAGE_DOS_HEADER p_dosheader = (PIMAGE_DOS_HEADER)p_base;
  if (p_dosheader->e_magic != IMAGE_DOS_SIGNATURE) {
    printf("invalid PE DOS header\n");
    free(p_base);
    return false;
  }

  PIMAGE_NT_HEADERS p_ntheaders = (PIMAGE_NT_HEADERS)(p_base + p_dosheader->e_lfanew);
  if (p_ntheaders->Signature != IMAGE_NT_SIGNATURE) {
    printf("invalid PE NT signature\n");
    free(p_base);
    return false;
  }

  /* find executable section */
  PIMAGE_SECTION_HEADER p_section = IMAGE_FIRST_SECTION(p_ntheaders);
  for (WORD i = 0; i < p_ntheaders->FileHeader.NumberOfSections; i++) {
    uint32_t addr = (uint32_t)p_ntheaders->OptionalHeader.AddressOfEntryPoint;
    uint32_t section_begin = (uint32_t)p_section->VirtualAddress;
    uint32_t section_end = (uint32_t)p_section->VirtualAddress + p_section->SizeOfRawData;
    if (section_begin <= addr && addr <= section_end) {
      char name[12];
      memset(name, 0, sizeof(name));
      memcpy_s(name, sizeof(name), p_section->Name, sizeof(p_section->Name));

      section_begin = (uint32_t)p_section->PointerToRawData;
      section_end = (uint32_t)p_section->PointerToRawData + p_section->SizeOfRawData;
      printf(
        "executable segment found: %s\n"
        "section start: %d\n"
        "section end: %d\n"
        "section size: %d\n",
        name,
        section_begin,
        section_end,
        p_section->SizeOfRawData
      );

      /* find protect signature bytes */
      char *p_text_segment_start = (char *)&p_base[section_begin];
      char *p_text_segment_end = (char *)&p_base[section_end];
      p_pat = p_text_segment_start;
      do {
        remaining_size = (size_t)(p_text_segment_end - p_pat);
        p_pat = sig_scan(p_pat, remaining_size, p_signature, sig_length);
        if (p_pat) {
          patch(p_pat);
          num_patches++;
          printf("patching bytes at offset %d\n", ((int)(p_pat - p_base)));
          p_pat += sig_length;
        }
      } while (p_pat);

      goto _save_file;
    }
    p_section++;
  }

_save_file:
  fp = fopen(p_outname, "wb");
  if (!fp) {
    printf("failed to create patched file\n");
    free(p_base);
    return false;
  }

  if (fwrite(p_base, 1, (size_t)size, fp) != (size_t)size) {
    printf("failed to write file. check free disk space\n");
    free(p_base);
    return false;
  }

  if (num_patches) {
    printf(
      "FILE PATCHED SUCCESSFULLY!\n"
      "Num patches: %d",
      num_patches
    );
  }
  else
  {
    printf("FILE IS NOT PATCHED. 0 SIG MATCHES\n");
  }
  free(p_base);
  return true;
}

/* for protection */
#define PROTECT() {\
__nop(); \
__nop(); \
__nop(); \
__nop(); \
__nop(); \
__nop(); \
__nop(); \
__nop(); \
__nop(); \
__nop(); \
__nop(); \
__nop(); \
__nop(); \
__nop(); \
__nop(); \
__nop();\
}

extern "C" __declspec(dllexport) void my_print(const char *p_text)
{
  printf(" ---------- MY PRINT BEGIN ----------\n");
  PROTECT()
  printf("%s\n", p_text);
  PROTECT()
  printf(" ---------- MY PRINT END ----------\n");
}
#endif

#include <Windows.h>
#include "pebteb.h"

inline int inl_strcmp(LPCSTR s1, LPCSTR s2)
{
  while (*s1 && (*s1 == *s2))
    s1++, s2++;

  return *(LPSTR)s1 - *(LPSTR)s2;
}

inline int inl_wstrcmp(PWSTR s1, PCWSTR s2)
{
  while (*s1 && (*s1 == *s2))
    s1++, s2++;

  return *(PWSTR)s1 - *(PCWSTR)s2;
}

 inline PPEB get_peb()
 {
   PPEB ppeb;
   __asm {
     mov eax, fs:[30h]
     mov ppeb, eax
   }
   return ppeb;
 }

inline PVOID get_module_handle_inl(WCHAR modname[])
{
  PPEB p_peb = get_peb();
  PPEB_LDR_DATA p_ldr_data = p_peb->Ldr;
  PLDR_MODULE p_ldr_module_next = (PLDR_MODULE)p_ldr_data->InLoadOrderModuleList.Flink;
  PLDR_MODULE p_ldr_module_first = p_ldr_module_next;
  do {
    if (p_ldr_module_next->BaseAddress && !inl_wstrcmp(p_ldr_module_next->BaseDllName.Buffer, modname))
      return p_ldr_module_next->BaseAddress;

    p_ldr_module_next = (PLDR_MODULE)p_ldr_module_next->InLoadOrderModuleList.Flink;
  } while (p_ldr_module_next != p_ldr_module_first);
  return NULL;
}

inline PVOID get_ntdll()
{
  PPEB p_peb = get_peb();
  PPEB_LDR_DATA p_ldr_data = p_peb->Ldr;
  return ((PLDR_MODULE)p_ldr_data->InLoadOrderModuleList.Flink->Flink)->BaseAddress;
}

inline PVOID get_kernel32()
{
  PPEB p_peb = get_peb();
  PPEB_LDR_DATA p_ldr_data = p_peb->Ldr;
  return ((PLDR_MODULE)p_ldr_data->InLoadOrderModuleList.Flink->Flink->Flink)->BaseAddress;
}

// inline void print_modules()
// {
  // PPEB p_peb = get_peb();
  // PPEB_LDR_DATA p_ldr_data = p_peb->Ldr;
  // PLDR_MODULE p_ldr_module_next = (PLDR_MODULE)p_ldr_data->InLoadOrderModuleList.Flink;
  // PLDR_MODULE p_ldr_module_first = p_ldr_module_next;
  // do {
    // printf("  %ws\n", p_ldr_module_next->BaseDllName.Buffer);
    // p_ldr_module_next = (PLDR_MODULE)p_ldr_module_next->InLoadOrderModuleList.Flink;
  // } while (p_ldr_module_next != p_ldr_module_first);
// }


typedef PVOID(WINAPI *LoadLibraryA_Pfn)(LPCSTR lpLibFileName);
typedef int (WINAPI *MessageBoxA_Pfn)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

inline PVOID get_proc_address_inl(PBYTE pbase, const CHAR procname[])
{
  PIMAGE_DOS_HEADER p_dos = (PIMAGE_DOS_HEADER)pbase;
  PIMAGE_NT_HEADERS p_nt = (PIMAGE_NT_HEADERS)(pbase + p_dos->e_lfanew);
  PIMAGE_EXPORT_DIRECTORY p_expdir = (PIMAGE_EXPORT_DIRECTORY)(pbase + p_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
  uint32_t *p_nametbl = (uint32_t *)((uint32_t)pbase + p_expdir->AddressOfNames);
  uint32_t *p_functbl = (uint32_t *)((uint32_t)pbase + p_expdir->AddressOfFunctions);
  uint16_t *p_ordtbl = (uint16_t *)((uint32_t)pbase + p_expdir->AddressOfNameOrdinals);
  for (DWORD i = 0; i < p_expdir->NumberOfNames; i++) {
    LPCSTR p_current_name = (LPCSTR)((uint32_t)pbase + *p_nametbl);
    if (!inl_strcmp(p_current_name, procname)) {
      uint32_t func_num = *p_ordtbl * 4;
      uint32_t *p_func_tbl_addr = (uint32_t*)((uint32_t)p_functbl + func_num);
      uint32_t offset = *p_func_tbl_addr;
      return (PVOID)(pbase + offset);
    }
    p_nametbl++, p_ordtbl++;
  }
  return NULL;
}

int main()
{
  typedef UINT (WINAPI *WinExec_Pfn)(_In_ LPCSTR lpCmdLine, _In_ UINT uCmdShow);
  PVOID h_kernel32 = get_kernel32();
  char procname[] = { 'W', 'i', 'n', 'E', 'x', 'e', 'c', '\0' };
  WinExec_Pfn pWinExec = (WinExec_Pfn)get_proc_address_inl((LPBYTE)h_kernel32, procname);

  char str[] = { 'c', 'a', 'l', 'c', '.', 'e', 'x', 'e', '\0' };
  pWinExec(str, 5);
  while (1);
}

int main2()
{
  //patch_pe("1313.exe");
  //myfunc();
  //my_print("HELLO WORLD");

  const char sig[] = "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";
  //patch_pe("for_patch.exe", "patched.exe", sig, sizeof(sig) - 1);

  PVOID h_ntdll = get_ntdll();
  printf("0x%x\n", h_ntdll);
  return 0;
}
/* Compile-time checks for the existing MS C 6 runner's default data model. */
#if defined(M_I86SM)
#define DEFAULT_POINTER_BYTES 2
#elif defined(M_I86LM)
#define DEFAULT_POINTER_BYTES 4
#else
#error Coverage pilot requires small or large memory model
#endif

typedef char int_is_word[(sizeof(int) == 2) ? 1 : -1];
typedef char long_is_dword[(sizeof(long) == 4) ? 1 : -1];
typedef char data_pointer_matches_model[(sizeof(char *) == DEFAULT_POINTER_BYTES) ? 1 : -1];
typedef char function_pointer_matches_model[(sizeof(void (*)(void)) == DEFAULT_POINTER_BYTES) ? 1 : -1];
typedef char far_pointer_is_four_bytes[(sizeof(char far *) == 4) ? 1 : -1];

int main(void)
{
    return 255;
}

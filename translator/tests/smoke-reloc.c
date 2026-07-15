volatile unsigned value = 40;

__declspec(dllexport) unsigned entry(void) {
    return value + 2;
}


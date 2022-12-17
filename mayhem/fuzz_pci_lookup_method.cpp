#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>

extern "C" int pci_lookup_method(char *name);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    
    char* name = strdup(provider.ConsumeRandomLengthString().c_str());
    pci_lookup_method(name);
    free(name);

    return 0;
}
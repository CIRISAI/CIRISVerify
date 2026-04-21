/*
 * CIRISVerify Android Conformance Test
 *
 * Minimal C program to run conformance tests on Android device.
 * Compile with Android NDK and run via adb shell.
 */

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

/* FFI function signatures */
typedef void* CirisVerifyHandle;
typedef CirisVerifyHandle (*init_fn)(void);
typedef void (*destroy_fn)(CirisVerifyHandle);
typedef int (*conformance_fn)(CirisVerifyHandle);
typedef const char* (*version_fn)(void);

int main(int argc, char** argv) {
    printf("=== CIRISVerify Android Conformance Test ===\n\n");

    /* Load the library */
    const char* lib_path = argc > 1 ? argv[1] : "./libciris_verify_ffi.so";
    printf("Loading library: %s\n", lib_path);

    void* lib = dlopen(lib_path, RTLD_NOW);
    if (!lib) {
        fprintf(stderr, "ERROR: Failed to load library: %s\n", dlerror());
        return 1;
    }
    printf("Library loaded successfully\n");

    /* Get function pointers */
    init_fn ciris_verify_init = (init_fn)dlsym(lib, "ciris_verify_init");
    destroy_fn ciris_verify_destroy = (destroy_fn)dlsym(lib, "ciris_verify_destroy");
    conformance_fn ciris_verify_run_conformance_tests = (conformance_fn)dlsym(lib, "ciris_verify_run_conformance_tests");
    version_fn ciris_verify_version = (version_fn)dlsym(lib, "ciris_verify_version");

    if (!ciris_verify_init || !ciris_verify_destroy || !ciris_verify_run_conformance_tests) {
        fprintf(stderr, "ERROR: Failed to find required functions\n");
        dlclose(lib);
        return 1;
    }

    /* Print version */
    if (ciris_verify_version) {
        printf("Library version: %s\n\n", ciris_verify_version());
    }

    /* Initialize */
    printf("Initializing CIRISVerify...\n");
    CirisVerifyHandle handle = ciris_verify_init();
    if (!handle) {
        fprintf(stderr, "ERROR: Failed to initialize CIRISVerify\n");
        dlclose(lib);
        return 1;
    }
    printf("Initialized successfully\n\n");

    /* Run conformance tests */
    printf("Running conformance tests...\n");
    printf("(Results will appear in logcat)\n\n");

    int failures = ciris_verify_run_conformance_tests(handle);

    /* Cleanup */
    printf("Cleaning up...\n");
    ciris_verify_destroy(handle);
    dlclose(lib);

    /* Report result */
    printf("\n=== RESULT ===\n");
    if (failures == 0) {
        printf("ALL TESTS PASSED\n");
        return 0;
    } else {
        printf("FAILED: %d test(s) failed\n", failures);
        return 1;
    }
}

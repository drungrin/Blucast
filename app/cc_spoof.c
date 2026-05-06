/*
 * cc_spoof.c - LD_PRELOAD shim to spoof CUDA compute capability
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define CU_ATTR_CC_MAJOR 75
#define CU_ATTR_CC_MINOR 76
#define SPOOF_MAJOR 8
#define SPOOF_MINOR 6

/* CC_SPOOF_DEBUG env var */
static int cc_spoof_debug = 0;

#define CC_LOG(fmt, ...) do { if (cc_spoof_debug) fprintf(stderr, fmt, ##__VA_ARGS__); } while (0)

static __thread int cc_major_was_12 = 0;

/* --- cuDeviceGetAttribute (driver api) --- */
typedef int (*cuDeviceGetAttribute_fn)(int *, int, int);
static cuDeviceGetAttribute_fn real_cuDeviceGetAttribute;

static int spoof_cuDeviceGetAttribute(int *pi, int attrib, int dev) {
    if (!real_cuDeviceGetAttribute) {
        real_cuDeviceGetAttribute = (cuDeviceGetAttribute_fn)dlsym(RTLD_NEXT, "cuDeviceGetAttribute");
        if (!real_cuDeviceGetAttribute) {
            fprintf(stderr, "[cc_spoof] FATAL: cannot resolve real cuDeviceGetAttribute\n");
            return -1;
        }
    }
    int ret = real_cuDeviceGetAttribute(pi, attrib, dev);
    if (ret == 0 && pi && (attrib == CU_ATTR_CC_MAJOR || attrib == CU_ATTR_CC_MINOR)) {
        CC_LOG("[cc_spoof] cuDeviceGetAttribute(attrib=%d, dev=%d) = %d\n", attrib, dev, *pi);
    }
    if (ret == 0 && pi) {
        if (attrib == CU_ATTR_CC_MAJOR) {
            if (*pi == 12) {
                CC_LOG("[cc_spoof] cuDeviceGetAttribute: SPOOFING major %d -> %d\n", *pi, SPOOF_MAJOR);
                *pi = SPOOF_MAJOR;
                cc_major_was_12 = 1;
            } else {
                cc_major_was_12 = 0;
            }
        } else if (attrib == CU_ATTR_CC_MINOR) {
            if (*pi == 9) {
                CC_LOG("[cc_spoof] cuDeviceGetAttribute: SPOOFING minor %d -> %d\n", *pi, SPOOF_MINOR);
                *pi = SPOOF_MINOR;
                cc_major_was_12 = 0;
            } else if (cc_major_was_12) {
                CC_LOG("[cc_spoof] cuDeviceGetAttribute: SPOOFING minor %d -> %d (Blackwell follow-up)\n", *pi, SPOOF_MINOR);
                *pi = SPOOF_MINOR;
                cc_major_was_12 = 0;
            }
        }
    }
    return ret;
}

int cuDeviceGetAttribute(int *pi, int attrib, int dev) {
    return spoof_cuDeviceGetAttribute(pi, attrib, dev);
}

/* --- cuDeviceComputeCapability (deprecated driver api) --- */
typedef int (*cuDeviceComputeCapability_fn)(int *, int *, int);
static cuDeviceComputeCapability_fn real_cuDeviceComputeCapability;

static int spoof_cuDeviceComputeCapability(int *major, int *minor, int dev) {
    if (!real_cuDeviceComputeCapability) {
        real_cuDeviceComputeCapability = (cuDeviceComputeCapability_fn)dlsym(RTLD_NEXT, "cuDeviceComputeCapability");
        if (!real_cuDeviceComputeCapability) return -1;
    }
    int ret = real_cuDeviceComputeCapability(major, minor, dev);
    if (ret == 0 && major && minor) {
        int orig_major = *major, orig_minor = *minor;
        if (*major == 12) {
            CC_LOG("[cc_spoof] cuDeviceComputeCapability: %d.%d -> %d.%d\n",
                    orig_major, orig_minor, SPOOF_MAJOR, SPOOF_MINOR);
            *major = SPOOF_MAJOR;
            *minor = SPOOF_MINOR;
        } else if (*minor == 9) {
            CC_LOG("[cc_spoof] cuDeviceComputeCapability: %d.%d -> %d.%d\n",
                    orig_major, orig_minor, orig_major, SPOOF_MINOR);
            *minor = SPOOF_MINOR;
        }
    }
    return ret;
}

int cuDeviceComputeCapability(int *major, int *minor, int dev) {
    return spoof_cuDeviceComputeCapability(major, minor, dev);
}

/* --- cudaDeviceGetAttribute (runtime api) --- */
typedef int (*cudaDeviceGetAttribute_fn)(int *, int, int);
static cudaDeviceGetAttribute_fn real_cudaDeviceGetAttribute;

static int spoof_cudaDeviceGetAttribute(int *value, int attr, int device) {
    if (!real_cudaDeviceGetAttribute) {
        real_cudaDeviceGetAttribute = (cudaDeviceGetAttribute_fn)dlsym(RTLD_NEXT, "cudaDeviceGetAttribute");
        if (!real_cudaDeviceGetAttribute) return -1;
    }
    int ret = real_cudaDeviceGetAttribute(value, attr, device);
    if (ret == 0 && value) {
        if (attr == CU_ATTR_CC_MAJOR) {
            if (*value == 12) {
                CC_LOG("[cc_spoof] cudaDeviceGetAttribute: SPOOFING major %d -> %d\n", *value, SPOOF_MAJOR);
                *value = SPOOF_MAJOR;
                cc_major_was_12 = 1;
            } else {
                cc_major_was_12 = 0;
            }
        } else if (attr == CU_ATTR_CC_MINOR) {
            if (*value == 9) {
                CC_LOG("[cc_spoof] cudaDeviceGetAttribute: minor %d -> %d\n", *value, SPOOF_MINOR);
                *value = SPOOF_MINOR;
                cc_major_was_12 = 0;
            } else if (cc_major_was_12) {
                CC_LOG("[cc_spoof] cudaDeviceGetAttribute: SPOOFING minor %d -> %d (Blackwell follow-up)\n", *value, SPOOF_MINOR);
                *value = SPOOF_MINOR;
                cc_major_was_12 = 0;
            }
        }
    }
    return ret;
}

int cudaDeviceGetAttribute(int *value, int attr, int device) {
    return spoof_cudaDeviceGetAttribute(value, attr, device);
}

/* --- cudaGetDeviceProperties (runtime api) --- */
typedef int (*generic_fn)(void *, int);

static void fixup_prop(void *prop) {
    int *major = (int *)((char *)prop + 288);
    int *minor = (int *)((char *)prop + 292);
    int orig_major = *major, orig_minor = *minor;
    if (*major == 12) {
        CC_LOG("[cc_spoof] cudaGetDeviceProperties: %d.%d -> %d.%d\n",
                orig_major, orig_minor, SPOOF_MAJOR, SPOOF_MINOR);
        *major = SPOOF_MAJOR;
        *minor = SPOOF_MINOR;
    } else if (*major == 8 && *minor == 9) {
        CC_LOG("[cc_spoof] cudaGetDeviceProperties: %d.%d -> %d.%d\n",
                orig_major, orig_minor, orig_major, SPOOF_MINOR);
        *minor = SPOOF_MINOR;
    }
}

static generic_fn real_cudaGetDeviceProperties;
static generic_fn real_cudaGetDeviceProperties_v2;

static int spoof_cudaGetDeviceProperties(void *prop, int device) {
    if (!real_cudaGetDeviceProperties) {
        real_cudaGetDeviceProperties = (generic_fn)dlsym(RTLD_NEXT, "cudaGetDeviceProperties");
        if (!real_cudaGetDeviceProperties) return -1;
    }
    int ret = real_cudaGetDeviceProperties(prop, device);
    if (ret == 0) fixup_prop(prop);
    return ret;
}

static int spoof_cudaGetDeviceProperties_v2(void *prop, int device) {
    if (!real_cudaGetDeviceProperties_v2) {
        real_cudaGetDeviceProperties_v2 = (generic_fn)dlsym(RTLD_NEXT, "cudaGetDeviceProperties_v2");
        if (!real_cudaGetDeviceProperties_v2)
            real_cudaGetDeviceProperties_v2 = (generic_fn)dlsym(RTLD_NEXT, "cudaGetDeviceProperties");
        if (!real_cudaGetDeviceProperties_v2) return -1;
    }
    int ret = real_cudaGetDeviceProperties_v2(prop, device);
    if (ret == 0) fixup_prop(prop);
    return ret;
}

/* asm name trick to export with the correct symbol names */
int wrap_gdp(void *p, int d) __asm__("cudaGetDeviceProperties");
int wrap_gdp(void *p, int d) { return spoof_cudaGetDeviceProperties(p, d); }

int wrap_gdp2(void *p, int d) __asm__("cudaGetDeviceProperties_v2");
int wrap_gdp2(void *p, int d) { return spoof_cudaGetDeviceProperties_v2(p, d); }

/* NVML: nvmlDeviceGetCudaComputeCapability */
typedef int (*nvmlGetCC_fn)(void *, int *, int *);
static nvmlGetCC_fn real_nvmlDeviceGetCudaComputeCapability;

static int spoof_nvmlDeviceGetCudaComputeCapability(void *device, int *major, int *minor) {
    if (!real_nvmlDeviceGetCudaComputeCapability) {
        real_nvmlDeviceGetCudaComputeCapability =
            (nvmlGetCC_fn)dlsym(RTLD_NEXT, "nvmlDeviceGetCudaComputeCapability");
        if (!real_nvmlDeviceGetCudaComputeCapability) return -1;
    }
    int ret = real_nvmlDeviceGetCudaComputeCapability(device, major, minor);
    if (ret == 0 && major && minor) {
        int orig_major = *major, orig_minor = *minor;
        if (*major == 12) {
            CC_LOG("[cc_spoof] nvmlDeviceGetCudaComputeCapability: %d.%d -> %d.%d\n",
                    orig_major, orig_minor, SPOOF_MAJOR, SPOOF_MINOR);
            *major = SPOOF_MAJOR;
            *minor = SPOOF_MINOR;
        } else if (*minor == 9) {
            CC_LOG("[cc_spoof] nvmlDeviceGetCudaComputeCapability: %d.%d -> %d.%d\n",
                    orig_major, orig_minor, orig_major, SPOOF_MINOR);
            *minor = SPOOF_MINOR;
        }
    }
    return ret;
}

int nvmlDeviceGetCudaComputeCapability(void *device, int *major, int *minor) {
    return spoof_nvmlDeviceGetCudaComputeCapability(device, major, minor);
}

typedef void *(*dlsym_fn)(void *, const char *);
static dlsym_fn real_dlsym;

static void ensure_real_dlsym(void) {
    if (!real_dlsym) {
        /* use dlvsym to get the real dlsym from glibc, baller trick ngl */
        real_dlsym = (dlsym_fn)dlvsym(RTLD_NEXT, "dlsym", "GLIBC_2.2.5");
        if (!real_dlsym) {
            real_dlsym = (dlsym_fn)dlvsym(RTLD_NEXT, "dlsym", "GLIBC_2.34");
        }
    }
}

void *dlsym(void *handle, const char *symbol) {
    ensure_real_dlsym();
    if (!real_dlsym) {
        return NULL;
    }

    if (symbol && (strncmp(symbol, "cu", 2) == 0 ||
                   strncmp(symbol, "cuda", 4) == 0 ||
                   strncmp(symbol, "nvml", 4) == 0 ||
                   strncmp(symbol, "nv", 2) == 0)) {
        CC_LOG("[cc_spoof] dlsym lookup: \"%s\" handle=%p\n", symbol, handle);
    }

    if (symbol) {
        if (strcmp(symbol, "cuDeviceGetAttribute") == 0) {
            if (!real_cuDeviceGetAttribute)
                real_cuDeviceGetAttribute = (cuDeviceGetAttribute_fn)real_dlsym(handle, symbol);
            return (void *)spoof_cuDeviceGetAttribute;
        }
        if (strcmp(symbol, "cuDeviceComputeCapability") == 0) {
            if (!real_cuDeviceComputeCapability)
                real_cuDeviceComputeCapability = (cuDeviceComputeCapability_fn)real_dlsym(handle, symbol);
            return (void *)spoof_cuDeviceComputeCapability;
        }
        if (strcmp(symbol, "cudaDeviceGetAttribute") == 0) {
            if (!real_cudaDeviceGetAttribute)
                real_cudaDeviceGetAttribute = (cudaDeviceGetAttribute_fn)real_dlsym(handle, symbol);
            return (void *)spoof_cudaDeviceGetAttribute;
        }
        if (strcmp(symbol, "cudaGetDeviceProperties") == 0) {
            if (!real_cudaGetDeviceProperties)
                real_cudaGetDeviceProperties = (generic_fn)real_dlsym(handle, symbol);
            return (void *)spoof_cudaGetDeviceProperties;
        }
        if (strcmp(symbol, "cudaGetDeviceProperties_v2") == 0) {
            if (!real_cudaGetDeviceProperties_v2)
                real_cudaGetDeviceProperties_v2 = (generic_fn)real_dlsym(handle, symbol);
            return (void *)spoof_cudaGetDeviceProperties_v2;
        }
        if (strcmp(symbol, "nvmlDeviceGetCudaComputeCapability") == 0) {
            if (!real_nvmlDeviceGetCudaComputeCapability)
                real_nvmlDeviceGetCudaComputeCapability = (nvmlGetCC_fn)real_dlsym(handle, symbol);
            return (void *)spoof_nvmlDeviceGetCudaComputeCapability;
        }
    }

    return real_dlsym(handle, symbol);
}

__attribute__((constructor))
static void cc_spoof_init(void) {
    ensure_real_dlsym();
    cc_spoof_debug = (getenv("CC_SPOOF_DEBUG") != NULL);
    /*fprintf(stderr, "[cc_spoof] Library loaded. Spoofing CC 8.9 / 12.x -> %d.%d "*/
    /*        "(dlsym hook %s, debug %s)\n",*/
    /*        SPOOF_MAJOR, SPOOF_MINOR,*/
    /*        real_dlsym ? "active" : "FAILED",*/
    /*        cc_spoof_debug ? "on" : "off");*/
}

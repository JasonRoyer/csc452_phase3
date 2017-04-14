/*
 * basic.c
 *  
 *  Basic test case for Phase 3 Part A. It creates two processes, "A" and "B". 
 *  Each process has two pages and there are four frames so that all pages fit in memory.
 *  Each process writes its name into the first byte of each of its pages, sleeps for one
 *  second (to give the other process time to run), then verifies that the first byte
 *  of each page is correct. It then iterates a fixed number of times.
 *
 *  You can change the number of pages and iterations by changing the macros below. You
 *  can add more processes by adding more names to the "names" array, e.g. "C". The
 *  code will adjust the number of frames accordingly.
 *
 *  It makes liberal use of the "assert" function because it will dump core when it fails
 *  allowing you to easily look at the state of the program and figure out what went wrong,
 *  and because I'm lazy.
 *
 */
#include <usyscall.h>
#include <libuser.h>
#include <assert.h>
#include <usloss.h>
#include <stdlib.h>
#include <phase3.h>
#include <stdarg.h>
#include <unistd.h>

#define PAGES 1         // # of pages per process (be sure to try more than 1)
#define ITERATIONS 10
#define PAGERS 1       // Part A only requires 1 pager 

static char *vmRegion;
static char *names[] = {"A","B"};   // names of children, add more names to create more children
static int  pageSize;

#ifdef DEBUG
int debugging = 1;
#else
int debugging = 0;
#endif /* DEBUG */

static void debug(char *fmt, ...) __attribute__ ((unused)); // may be unused

static void
debug(char *fmt, ...)
{
    va_list ap;

    if (debugging) {
        va_start(ap, fmt);
        USLOSS_VConsole(fmt, ap);
    }
}


static int
Child(void *arg)
{
    volatile char *name = (char *) arg;
    int     i,j;
    char    *page;
    int     rc;
    int     pid;
    int     first = 1;

    Sys_GetPID(&pid);
    USLOSS_Console("Child \"%s\" (%d) starting.\n", name, pid);
    for (i = 0; i < ITERATIONS; i++) {
        if (first) {
            // The first time a page is read it should be full of zeros.
            for (j = 0; j < PAGES; j++) {
                page = vmRegion + j * pageSize;
                USLOSS_Console("Child \"%s\" reading zeros from page %d @ %p\n", name, j, page);
                for (int k = 0; k < pageSize; k++) {
                    assert(page[k] == '\0');
                }
            }
            first = 0;
        } else {
            for (j = 0; j < PAGES; j++) {
                page = vmRegion + j * pageSize;
                USLOSS_Console("Child \"%s\" writing to page %d @ %p\n", name, j, page);
                *page = *name;
            }
            for (j = 0; j < PAGES; j++) {
                page = vmRegion + j * pageSize;
                USLOSS_Console("Child \"%s\" reading from page %d @ %p\n", name, j, page);
                assert(*page == *name);
            }
            rc = Sys_Sleep(1);
            assert(rc == 0);
        }
    }
    USLOSS_Console("Child \"%s\" done.\n", name);
    return 0;
}


int
P4_Startup(void *arg)
{
    int     i;
    int     rc;
    int     pid;
    int     child;
    int     numChildren = sizeof(names) / sizeof(char *);

    USLOSS_Console("P4_Startup starting.\n");
    USLOSS_Console("NOTE: this test will hang if run with the skeleton phase3.c.\n");
    rc = Sys_VmInit(PAGES, PAGES, numChildren * PAGES, 1, (void **) &vmRegion);
    if (rc != 0) {
        USLOSS_Console("Sys_VmInit failed: %d\n", rc);
        USLOSS_Halt(1);
    }
    pageSize = USLOSS_MmuPageSize();
    for (i = 0; i < numChildren; i++) {
        rc = Sys_Spawn(names[i], Child, (void *) names[i], USLOSS_MIN_STACK * 2, 2, &pid);
        assert(rc == 0);
    }
    for (i = 0; i < numChildren; i++) {
        rc = Sys_Wait(&pid, &child);
        assert(rc == 0);
    }
    Sys_VmDestroy();
    USLOSS_Console("Tests passed.\n");
    return 0;
}


void test_setup(int argc, char **argv) {
}

void test_cleanup(int argc, char **argv) {
}
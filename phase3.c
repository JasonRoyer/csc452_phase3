/*
 * skeleton.c
 *
 * 	This is a skeleton for phase3 of the programming assignment. It
 *	doesn't do much -- it is just intended to get you started. Feel free 
 *  to ignore it.
 */

 
/*
* Author: Jason Royer
* Partner Name: Steven Broussard
* Phase 3 Part A
* TAs: Navdeep & Marty
* Course: CSC 452 - Princples of Operating Systems
* Professor Name: John Hartman
*/


#include <assert.h>
#include <phase1.h>
#include <phase2.h>
#include <phase3.h>
#include <usloss.h>
#include <string.h>
#include <libuser.h>


/*
 * Per-process information
 */
typedef struct Process {
    int		        numPages;	/* Size of the page table. */
    USLOSS_PTE		*pageTable;	/* The page table for the process. */
    /* Add more stuff here if necessary. */
	int				*inUse;
} Process;

static Process	processes[P1_MAXPROC];
static int	numPages = 0;
static int	numFrames = 0;

/*
 * Information about page faults.
 */
typedef struct Fault {
    int		pid;		/* Process with the problem. */
    void	*addr;		/* Address that caused the fault. */
    int		mbox;		/* Where to send reply. */
    /* Add more stuff here if necessary. */
} Fault;

int *frameList;

static void	*vmRegion = NULL;

P3_VmStats	P3_vmStats;

static int pagerMbox = -1;

// Helpful constants

#define MBOX_RELEASED -2
#define ILLEGAL_PARAMS -1
#define ALREADY_INITIALIZED -2
#define STACKSIZE (USLOSS_MIN_STACK * 3) // change if your pagers need more stack

// Helpful macros

#define CheckMode() \
    if ((USLOSS_PsrGet() & USLOSS_PSR_CURRENT_MODE) == 0) { \
        int pid; \
        Sys_GetPID(&pid); \
        USLOSS_Console("Process %d called %s from user mode.\n", pid, __FUNCTION__); \
        USLOSS_IllegalInstruction(); \
    }

static void CheckPid(int);
static void FaultHandler(int type, void *arg);
static int  Pager(void *arg);

static int initialized = 0;
static P1_Semaphore running;


/*
 *----------------------------------------------------------------------
 *
 * P3_VmInit --
 *
 *	Initializes the VM system by configuring the MMU and setting
 *	up the page tables.
 *
 * Parameters:
 *      mappings: unused
 *      pages: # of pages in the VM region
 *      frames: # of frames of physical memory
 *      pagers: # of pager daemons
 *	
 * Results:
 *      0: success
 *     -1: error
 *     -2: MMU already initialized
 *
 * Side effects:
 *      The MMU is initialized.
 *
 *----------------------------------------------------------------------
 */
int
P3_VmInit(int mappings, int pages, int frames, int pagers)
{
    int		status;
    int		i;
    int		tmp;
    int     result = 0;
    CheckMode();
    status = USLOSS_MmuInit(mappings, pages, frames, USLOSS_MMU_MODE_PAGETABLE);
    if (status == USLOSS_MMU_ERR_ON) {
        result = ALREADY_INITIALIZED;
        goto done;
    } else if (status != USLOSS_MMU_OK) {
        result = ILLEGAL_PARAMS;
        goto done;
    }
    vmRegion = USLOSS_MmuRegion(&tmp);
    assert(vmRegion != NULL);
    assert(tmp >= pages);
    USLOSS_IntVec[USLOSS_MMU_INT] = FaultHandler;
    for (i = 0; i < P1_MAXPROC; i++) {
    	processes[i].numPages = 0;
    	processes[i].pageTable = NULL;
    }

    memset((char *) &P3_vmStats, 0, sizeof(P3_VmStats));
    P3_vmStats.pages = pages;
    P3_vmStats.frames = frames;
    numPages = pages;
    numFrames = frames;
	P3_vmStats.freeFrames = frames;
	frameList = (int*)calloc(numFrames, sizeof(int));
	
    status = P1_SemCreate("running", 0, &running);
    assert(status == 0);

    pagerMbox = P2_MboxCreate(P1_MAXPROC, sizeof(Fault));
    assert(pagerMbox >= 0);

    initialized = 1;
	
    for (int i = 0; i < pagers; i++) {
        char name[30];
        snprintf(name, sizeof(name), "Pager %d\n", i);
        status = P1_Fork(name, Pager, (void *) i, STACKSIZE, 2, 0);
        assert(status >= 0);
    }
     
done:
    return result;
}
/*
 *----------------------------------------------------------------------
 *
 * P3_VmDestroy --
 *
 *	Frees all of the global data structures
 *	
 * Results:
 *      None
 *
 * Side effects:
 *      The MMU is turned off.
 *
 *----------------------------------------------------------------------
 */
void
P3_VmDestroy(void)
{
    int rc;
    CheckMode();
    if (initialized) {
        rc = USLOSS_MmuDone();
        assert(rc == 0);
        initialized = 0;
        /*
         * Kill the pagers here.
         */
		assert(P2_MboxRelease(pagerMbox) == 0);
		 
        /* 
         * Print vm statistics.
         */
        USLOSS_Console("P3_vmStats:\n");
        USLOSS_Console("pages: %d\n", P3_vmStats.pages);
        USLOSS_Console("frames: %d\n", P3_vmStats.frames);
        USLOSS_Console("blocks: %d\n", P3_vmStats.blocks);
		USLOSS_Console("freeFrames: %d\n", P3_vmStats.freeFrames);
		USLOSS_Console("freeBlocks: %d\n", P3_vmStats.freeBlocks);
		USLOSS_Console("faults: %d\n", P3_vmStats.faults);
		USLOSS_Console("pageIns: %d\n", P3_vmStats.pageIns);
		USLOSS_Console("pageOuts: %d\n", P3_vmStats.pageOuts);
		USLOSS_Console("replaced: %d\n", P3_vmStats.replaced);
		
    }
}

/*
 *----------------------------------------------------------------------
 *
 * P3_AllocatePageTable --
 *
 *	Allocates a page table for the new process.
 *
 * Parameters:
 *      pid : pid of new process
 *
 * Results:
 *	 None.
 *
 * Side effects:
 *	 A page table is allocated.
 *
 *----------------------------------------------------------------------
 */
USLOSS_PTE *
P3_AllocatePageTable(int pid)
{
    int		    i;
    USLOSS_PTE  *pageTable = NULL;

    CheckMode();
    CheckPid(pid);
    if (initialized) {
        processes[pid].numPages = numPages;
        processes[pid].pageTable = (USLOSS_PTE *) malloc(sizeof(USLOSS_PTE) * numPages);
		 processes[pid].inUse = (int*) (int*)calloc(numPages, sizeof(int));
        for (i = 0; i < numPages; i++) {
            processes[pid].pageTable[i].incore = 0;
            processes[pid].pageTable[i].read = 1; // all pages are readable
            processes[pid].pageTable[i].write = 1; // and writeable

            // Initialize more stuff here.
        }
        pageTable = processes[pid].pageTable;
    }
    return pageTable;
}

/*
 *----------------------------------------------------------------------
 *
 * P3_FreePageTable --
 *
 *	Called when a process quits and frees the page table 
 *	for the process and frees any frames and disk space used
 *  by the process.
 *
 * Parameters:
 *      pid: pid of process that is quitting
 *
 *
 * Results:
 *	None
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------
 */
void
P3_FreePageTable(int pid)
{
    CheckMode();
    CheckPid(pid);
    if ((initialized) && (processes[pid].pageTable != NULL)) {

        /* 
         * Free any of the process's pages that are on disk and free any page frames the
         * process is using.
         */
		
		//currently using
		for(int i = 0; i < processes[pid].numPages; i ++){
			if(processes[pid].inUse[i]){
				if(processes[pid].pageTable[i].incore){
					// its in memory
					frameList[processes[pid].pageTable[i].frame] = 0;
					P3_vmStats.freeFrames++;
				}else {
					// its on disk
				}
			}
		}
		 
		 
        /* Clean up the page table. */

        free((char *) processes[pid].pageTable);
		free(processes[pid].inUse);
        processes[pid].numPages = 0;
        processes[pid].pageTable = NULL;
		processes[pid].inUse = NULL;
    }
}


/*
 *----------------------------------------------------------------------
 *
 * FaultHandler
 *
 *	Handles an MMU interrupt. 
 *
 * Parameters:
 *      type: USLOSS_MMU_INT
 *      arg: offset of the faulting address from the start of the VM region
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	The current process is blocked until the fault is handled.
 *
 *----------------------------------------------------------------------
 */
static void
FaultHandler(int type, void *arg) 
{
    int		cause;
    int		status;
    Fault	fault;
    int     size;

    assert(type == USLOSS_MMU_INT);
    cause = USLOSS_MmuGetCause();
    assert(cause == USLOSS_MMU_FAULT);
    P3_vmStats.faults++;
    fault.pid = P1_GetPID();
    fault.addr = arg;
    fault.mbox = P2_MboxCreate(1, 0);
    assert(fault.mbox >= 0);
    size = sizeof(fault);
    status = P2_MboxSend(pagerMbox, &fault, &size);
    assert(status >= 0);
    assert(size == sizeof(fault));
    size = 0;
    status = P2_MboxReceive(fault.mbox, NULL, &size);
    if (status != MBOX_RELEASED) {
        assert(status >= 0);
        status = P2_MboxRelease(fault.mbox);
        assert(status == 0);
    }
}

/*
 *----------------------------------------------------------------------
 *
 * Pager 
 *
 *	Kernel process that handles page faults and does page 
 *	replacement.
 *
 * Parameters:
 *      arg: not used
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------
 */
static int
Pager(void *arg)
{
    int     number = (int) arg;
    int     status;
    Fault   fault;
    int     size;
    int     pid;

    pid = P1_GetPID();
    USLOSS_Console("Pager %d (%d) starting.\n", number, pid);
    /*
     * Let the parent know we are running and enable interrupts.
     */
    status = P1_V(running);
    assert(status == 0);
    status = USLOSS_PsrSet(USLOSS_PsrGet() | USLOSS_PSR_CURRENT_INT);
    assert(status == 0);

    // Start servicing faults.
    while(1) {
        USLOSS_Console("Pager %d waiting for a fault.\n", number); 
        size = sizeof(fault);
        status = P2_MboxReceive(pagerMbox, &fault, &size);
        if (status == MBOX_RELEASED) {
            break;
        }
        assert(status >= 0);
        assert(size == sizeof(fault));

        USLOSS_Console("Pager %d received fault from pid %d.\n", number, fault.pid); 
    	/* Find a free frame */
    	/* If there isn't one run clock algorithm, write page to disk if necessary */
    	/* Load page into frame from disk or fill with zeros */
		int pageSize = USLOSS_MmuPageSize();
		int pageNum = (int)fault.addr / pageSize;
		int freeFrame = -1;
		int status;
		for(int i =0; i < numFrames; i++){
			if (!frameList[i]){
				frameList[i] = 1;
				freeFrame = i;
				break;
			}
		}
		if(freeFrame >= 0){
		// grant access to pager so that it can Zero
		
		processes[P1_GetPID()].inUse[0] = 1;
		processes[P1_GetPID()].pageTable[0].incore = 1;
		processes[P1_GetPID()].pageTable[0].frame = freeFrame;
		status = USLOSS_MmuSetPageTable(&processes[P1_GetPID()].pageTable[0]);
		assert(status == USLOSS_MMU_OK);
		// zero out
		memset(vmRegion, '\0', pageSize);
		
		// remove access
		processes[P1_GetPID()].inUse[0] = 0;
		processes[P1_GetPID()].pageTable[0].incore = 0;
		
			
        /* Update faulting process's page table to map page to frame mu*/
		processes[fault.pid].inUse[pageNum] = 1;
		processes[fault.pid].pageTable[pageNum].frame = freeFrame;
		P3_vmStats.freeFrames--;
		processes[fault.pid].pageTable[pageNum].incore = 1;
		} else {
			// something is wrong we don't have enough framessadasdasd asdas
		}
		
    	/* Unblock waiting (faulting) process */ 
		 int msg = 1;
		 int size = sizeof(int);
		status = P2_MboxSend(fault.mbox, &msg, &size);
		assert(status >= 0);
		
		
	
    }
    return 0;
}

/*
 * Helper routines
 */

static void
CheckPid(int pid) 
{
    if ((pid < 0) || (pid >= P1_MAXPROC)) {
    	USLOSS_Console("Invalid pid\n"); 
    	USLOSS_Halt(1);
    }
}

int P3_Startup(void *arg)
{
    int pid;
    int pid4;
    int status;
    int rc;

    rc = Sys_Spawn("P4_Startup", P4_Startup, NULL,  3 * USLOSS_MIN_STACK, 3, &pid4);
    assert(rc == 0);
    assert(pid4 >= 0);
    rc = Sys_Wait(&pid, &status);
    assert(rc == 0);
    assert(pid == pid4);
    Sys_VmDestroy();
    return 0;
}



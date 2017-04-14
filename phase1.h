/*
 * These are the definitions for Phase 1 of the project (the kernel).
 * DO NOT MODIFY THIS FILE.
 *
 * Version: 1.1
 */

#ifndef _PHASE1_H
#define _PHASE1_H

#include "usloss.h"
#include "usyscall.h"

/*
 * Maximum number of processes. 
 */

#define P1_MAXPROC  50

/*
 * Maximum number of semaphores.
 */

#define P1_MAXSEM   1000

typedef void *P1_Semaphore;

/* 
 * Function prototypes for this phase.
 */

extern  int     P1_Fork(char *name, int(*func)(void *), void *arg, 
                        int stackSize, int priority, int tag);
extern  void    P1_Quit(int status);
extern  int     P1_Join(int tag, int *status);
extern  int     P1_GetPID(void);
extern  int     P1_GetState(int pid);
extern  void    P1_DumpProcesses(void);

extern  int     P1_SemCreate(char *name, unsigned int value, P1_Semaphore *sem);
extern  int     P1_SemFree(P1_Semaphore sem);
extern  int     P1_P(P1_Semaphore sem);
extern  int     P1_V(P1_Semaphore sem);
extern  char    *P1_GetName(P1_Semaphore sem);

extern  int     P1_WaitDevice(int type, int unit, int *status);
extern  int     P1_WakeupDevice(int type, int unit, int abort);
extern  int     P1_ReadTime(void);


extern  int     P2_Startup(void *arg);

extern  USLOSS_PTE  *P3_AllocatePageTable(int pid);
extern  void        P3_FreePageTable(int pid);

#endif /* _PHASE1_H */

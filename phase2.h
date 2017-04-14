/*
 * These are the definitions for phase0 of the project (the kernel).
 * DO NOT MODIFY THIS FILE.
 *
 * Version: 2.0
 */

#ifndef _PHASE2_H
#define _PHASE2_H

/*
 * Maximum line length
 */

#define P2_MAX_LINE	72

#define P2_MAX_MBOX 	200

/* 
 * Function prototypes for this phase.
 */

extern  int	    P2_Sleep(int seconds);

extern	int	    P2_TermRead(int unit, int size, char *buffer);
extern  int	    P2_TermWrite(int unit, int size, char *text);

extern  int	    P2_DiskRead(int unit, int track, int first, int sectors, void *buffer);
extern  int	    P2_DiskWrite(int unit, int track, int first, int sectors, void *buffer);
extern  int 	P2_DiskSize(int unit, int *sector, int *track, int *disk);

extern  int     P2_Spawn(char *name, int (*func)(void *arg), void *arg, int stackSize, int priority);
extern  int     P2_Wait(int *status);
extern  void    P2_Terminate(int status);

extern	int 	P3_Startup(void *);

extern	int     P2_MboxCreate(int slots, int size);
extern	int	    P2_MboxRelease(int mbox);
extern	int	    P2_MboxSend(int mbox, void *msg, int *size);
extern	int	    P2_MboxCondSend(int mbox, void *msg, int *size);
extern  int	    P2_MboxReceive(int mbox, void *msg, int *size);
extern  int     P2_MboxCondReceive(int mbox, void *msg, int *size);

#endif /* _PHASE2_H */

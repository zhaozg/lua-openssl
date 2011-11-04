/*======================================================================*\
* This module creates a compatibility layer between Win32 and pthreads.
* DISCLAMER:
*   This is NOT a full pthread implementation for Win32. Only the
*   functionality needed by LuaThread was implemented. Use it at your 
*   own risk.
* Diego Nehab, 12/3/2001
* RCS Id: $Id: pt.c,v 1.7 2004/11/24 19:50:02 diego Exp $
\*======================================================================*/
#include <openssl/crypto.h>

#include "pt.h"
#include <stdio.h>
/*======================================================================*\
* Win32 stuff. There is nothing to do unless we are under Win32.
\*======================================================================*/
#ifdef WIN32

#include <windows.h>
#include <process.h>

/*----------------------------------------------------------------------*\
* Exported data structures are completely opaque. Internaly, we define 
* their real contents.
\*----------------------------------------------------------------------*/
typedef CRITICAL_SECTION _pthread_mutex_t;

size_t pthread_mutex_sizeof(void)
{
	return sizeof(_pthread_mutex_t);
}

typedef struct {
	HANDLE semaphore;
	int waiting;
} _pthread_cond_t;

size_t pthread_cond_sizeof(void)
{
	return sizeof(_pthread_cond_t);
}

typedef void (_pthread_start_t)(void *);

/*----------------------------------------------------------------------*\
* Mutex stuff.
\*----------------------------------------------------------------------*/
int pthread_mutex_init(pthread_mutex_t *mutex, pthread_mutexattr_t *attr)
{
	(void) attr;
	InitializeCriticalSection((_pthread_mutex_t *) mutex);
	return 0;
}

int pthread_mutex_lock(pthread_mutex_t *mutex)
{
	EnterCriticalSection((_pthread_mutex_t *) mutex);
	return 0;
}

int pthread_mutex_unlock(pthread_mutex_t *mutex)
{
	LeaveCriticalSection((_pthread_mutex_t *) mutex);
	return 0;
}

int pthread_mutex_destroy(pthread_mutex_t *mutex)
{
	DeleteCriticalSection((_pthread_mutex_t *) mutex);
	return 0;
}

/*----------------------------------------------------------------------*\
* Conditions stuff.
\*----------------------------------------------------------------------*/
int pthread_cond_init(pthread_cond_t *cond, pthread_condattr_t *attr)
{
    _pthread_cond_t *_cond = (_pthread_cond_t *) cond;
	_cond->semaphore = CreateSemaphore(NULL, 0, 128, NULL);
	_cond->waiting = 0;
	return 0;
}

int pthread_cond_destroy(pthread_cond_t *cond)
{
    _pthread_cond_t *_cond = (_pthread_cond_t *) cond;
	CloseHandle(_cond->semaphore);
	return 0;
}

int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex)
{
    _pthread_cond_t *_cond = (_pthread_cond_t *) cond;
	_cond->waiting++;
	pthread_mutex_unlock(mutex);
	WaitForSingleObject(_cond->semaphore, INFINITE);
	pthread_mutex_lock(mutex);
	return 0;
}

int pthread_cond_signal(pthread_cond_t *cond)
{
    _pthread_cond_t *_cond = (_pthread_cond_t *) cond;
	if (_cond->waiting > 0) {
        if (ReleaseSemaphore(_cond->semaphore, 1, NULL) == 0) return -1;
		_cond->waiting--;
	}
    return 0;
}

int pthread_cond_broadcast(pthread_cond_t *cond)
{
    _pthread_cond_t *_cond = (_pthread_cond_t *) cond;
	if (_cond->waiting > 0) {
		if (ReleaseSemaphore(_cond->semaphore, _cond->waiting, NULL) == 0) 
			return -1;
		_cond->waiting = 0;
	}
    return 0;
}

/*----------------------------------------------------------------------*\
* Threads stuff.
\*----------------------------------------------------------------------*/
int pthread_create(pthread_t *id, pthread_attr_t *attr, 
    pthread_start_t *start, void *arg)
{
	pthread_t tid = _beginthread((_pthread_start_t *) start, 0, arg);
    if (id) *id = tid;
    if (tid == -1) return -1;
	else return 0;
}

int pthread_equal(pthread_t t1, pthread_t t2)
{
    return (t1 == t2);
}

pthread_t pthread_self(void)
{
	return (pthread_t) GetCurrentThreadId();
}

int pthread_detach(pthread_t th)
{
	(void) th;
	return 0;
}

int pthread_cleanup(pthread_t th)
{
    _endthread();
    return 0;
}

#else

int pthread_cleanup(pthread_t th)
{
    return 0;
}

#endif

static pthread_mutex_t **lock_cs = NULL;
static int	lock_num_locks;

static void util_thr_lock(int mode, int type,
                              const char *file, int line)
{
    if (type < lock_num_locks) {
        if (mode & CRYPTO_LOCK) {
            pthread_mutex_lock(lock_cs[type]);
        }
        else {
            pthread_mutex_unlock(lock_cs[type]);
        }
    }
}

/* Dynamic lock structure */
struct CRYPTO_dynlock_value {
    const char* file;
    int line;
    pthread_mutex_t *mutex;
};

/*
 * Dynamic lock creation callback
 */
static struct CRYPTO_dynlock_value *dyn_create_function(const char *file,
                                                     int line)
{
    struct CRYPTO_dynlock_value *value;
    value = (struct CRYPTO_dynlock_value *)malloc(sizeof(struct CRYPTO_dynlock_value));
    if (!value) {
        return NULL;
    }
    value->file = strdup(file);
    value->line = line;
    pthread_mutex_init(&(value->mutex), NULL);
    return value;
}

/*
 * Dynamic locking and unlocking function
 */

static void dyn_lock_function(int mode, struct CRYPTO_dynlock_value *l,
                           const char *file, int line)
{
    if (mode & CRYPTO_LOCK) {
        pthread_mutex_lock(l->mutex);
    }
    else {
        pthread_mutex_unlock(l->mutex);
    }
}

/*
 * Dynamic lock destruction callback
 */
static void dyn_destroy_function(struct CRYPTO_dynlock_value *l,
                          const char *file, int line)
{
    pthread_mutex_destroy(l->mutex);
	free((char*)l->file);
	free(l);
}

static unsigned long util_thr_id(void)
{
    /* OpenSSL needs this to return an unsigned long.  On OS/390, the pthread
     * id is a structure twice that big.  Use the TCB pointer instead as a
     * unique unsigned long.
     */
#ifdef __MVS__
    struct PSA {
        char unmapped[540];
        unsigned long PSATOLD;
    } *psaptr = 0;

    return psaptr->PSATOLD;
#else
    return (unsigned long) pthread_self();
#endif
}

static void util_thread_cleanup(void *data)
{
    CRYPTO_set_locking_callback(NULL);
    CRYPTO_set_id_callback(NULL);

    CRYPTO_set_dynlock_create_callback(NULL);
    CRYPTO_set_dynlock_lock_callback(NULL);
    CRYPTO_set_dynlock_destroy_callback(NULL);
}

void util_thread_setup()
{
    int i;

    lock_num_locks = CRYPTO_num_locks();
    lock_cs = malloc(lock_num_locks * sizeof(*lock_cs));

    for (i = 0; i < lock_num_locks; i++) {
		lock_cs[i] = malloc(pthread_mutex_sizeof());
        pthread_mutex_init((lock_cs[i]), NULL);
    }

    CRYPTO_set_id_callback(util_thr_id);

    CRYPTO_set_locking_callback(util_thr_lock);

    CRYPTO_set_dynlock_create_callback(dyn_create_function);
    CRYPTO_set_dynlock_lock_callback(dyn_lock_function);
    CRYPTO_set_dynlock_destroy_callback(dyn_destroy_function);
}

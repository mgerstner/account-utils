// SPDX-License-Identifier: BSD-2-Clause

#include "config.h"

#include <assert.h>
#include <errno.h>
#include <pwd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <shadow.h>
#include <sys/stat.h>

#include "basics.h"
#include "files.h"

#ifdef WITH_SELINUX
#include <selinux/selinux.h>
#define SELINUX_ENABLED (is_selinux_enabled()>0)
#else
#define SELINUX_ENABLED 0
#endif

#define MAX_LOCK_RETRIES 300 /* How often should we try to lock password file */

typedef int (*update_account_file_cb)(FILE*, FILE*, void*);

static int
lock_db(void)
{
  int retries = 0;
  int r;

  while((r = lckpwdf()) != 0 && retries < MAX_LOCK_RETRIES)
    {
      usleep(10000); /* 1/100 second */
      ++retries;
    }

  if (r < 0)
    {
      if (retries == MAX_LOCK_RETRIES)
	return -ENOLCK;
      else
	return -errno;
    }
  return 0;
}

static void
unlink_and_free_tempfilep(char **p)
{
  if (p == NULL || *p == NULL)
    return;

  /* If the file is created with mkstemp(), it will (almost always) change
     the suffix. Treat this as a sign that the file was successfully created.
     We ignore both the rare case where the original suffix is used and
     unlink failures. */
  if (!endswith(*p, ".XXXXXX"))
    (void) unlink(*p);

  *p = mfree(*p);
}

static inline void
umaskp(mode_t *u)
{
  umask(*u);
}

/* This is much like mkostemp() but is subject to umask(). */
static int
mkostemp_safe(char *pattern)
{
  _cleanup_(umaskp) mode_t _saved_umask_ = umask(0077);
  int r;

  r = mkostemp(pattern, O_CLOEXEC);

  if (r < 0)
    return -errno;
  else
    return r;
}

static int update_account_file_locked(const char *etcdir, const char *base,
		update_account_file_cb process_account_files, void *ctx) {
  _cleanup_(unlink_and_free_tempfilep) char *tmpfn = NULL;
  _cleanup_free_ char *file_orig = NULL;
  _cleanup_free_ char *file_old = NULL;
  _cleanup_close_ int newfd = -EBADF;
  _cleanup_fclose_ FILE *oldf = NULL;
  _cleanup_fclose_ FILE *newf = NULL;
  struct stat st;
  int r;

  assert(etcdir);

  if (asprintf(&file_orig, "%s/%s", etcdir, base) < 0)
    return -ENOMEM;
  if (asprintf(&file_old, "%s/%s-", etcdir, base) < 0)
    return -ENOMEM;
  if (asprintf(&tmpfn, "%s/.%s.XXXXXX", etcdir, base) < 0)
    return -ENOMEM;

  if ((oldf = fopen(file_orig, "r")) == NULL)
    return -errno;

  if (fstat(fileno(oldf), &st) < 0)
    return -errno;

  newfd = mkostemp_safe(tmpfn);
  if (newfd < 0)
    return newfd; /* newfd == -errno */

  r = fchmod(newfd, st.st_mode);
  if (r < 0)
    return -errno;

  r = fchown(newfd, st.st_uid, st.st_gid);
  if (r < 0)
    return -errno;

#if 0 /* XXX */
  r = copy_xattr(file_orig, file_tmp);
  if (r > 0)
    return -r;
#endif

  newf = fdopen(newfd, "w+");
  if (newf == NULL)
    return -errno;

  int gotit = process_account_files(oldf, newf, ctx);
  if (gotit < 0)
	  return gotit;

  r = fclose(oldf);
  oldf = NULL;
  if (r < 0)
    return -errno;

  r = fflush(newf);
  if (r < 0)
    return -errno;

  r = fsync(fileno(newf));
  if (r < 0)
    return -errno;

  r = fclose(newf);
  newf = NULL;
  if (r < 0)
    return -errno;

  if (gotit == 0)
    {
      /* entry not found or nothing changed */
      unlink(tmpfn);
      return -ENOENT;
    }

  unlink(file_old);
  r = link(file_orig, file_old);
  if (r < 0)
    return -errno;

  r = rename(tmpfn, file_orig);
  if (r < 0)
    return -errno;

  return 0;

}

/*
 * update an account file like "shadow" or "passwd"
 *
 * `etcdir`: the etc directory where to lookup `base`, can be NULL to use the
 * default etc directory.
 * `base`: basename of the account file found in `etcdir`
 * `callback`: callback which will be invoked to copy entries over from the
 * old account file to the new one. Will be passed `ctx`
 * `ctx`: callback specific data needed for processing.
 */
static int update_account_file(const char *etcdir, const char *base,
		update_account_file_cb callback, void *ctx) {
  _cleanup_free_ char *file_orig = NULL;
#ifdef WITH_SELINUX
  char *prev_context_raw = NULL;
#endif
  int r;

  if (!ctx)
    return -EINVAL;

  if (isempty(etcdir))
    etcdir = "/etc";

  /* XXX adjust lock if etcdir is not /etc */
  if (streq(etcdir, "/etc"))
    {
      r = lock_db();
      if (r < 0)
	return r;
    }

  /* XXX use old password to verify again, else some other process could
   * have already changed the password meanwhile */

  if (asprintf(&file_orig, "%s/%s", etcdir, base) < 0)
    return -ENOMEM;

#ifdef WITH_SELINUX
  if (SELINUX_ENABLED)
    {
      char *file_context_raw = NULL;

      if (getfilecon_raw(file_orig, &file_context_raw) < 0)
	return -errno;

      if (getfscreatecon_raw(&prev_context_raw) < 0)
	{
	  int saved_errno = errno;
	  freecon(file_context_raw);
	  return -saved_errno;
	}
      if (setfscreatecon_raw(file_context_raw) < 0)
	{
	  int saved_errno = errno;
	  freecon(file_context_raw);
	  freecon(prev_context_raw);
	  return -saved_errno;
	}
      freecon(file_context_raw);
    }
#endif

  r = update_account_file_locked(etcdir, "passwd", callback, ctx);

#ifdef WITH_SELINUX
  if (SELINUX_ENABLED)
    {
      if (setfscreatecon_raw(prev_context_raw) < 0)
	r = -errno;
      freecon(prev_context_raw);
    }
#endif

  /* XXX adjust lock if etcdir is not /etc */
  if (streq(etcdir, "/etc"))
    {
      if (ulckpwdf() != 0)
	return -errno;
    }

  return r;

}

static int
update_passwd_file(FILE *oldf, FILE *newf, void *ctx)
{
  struct passwd *pw; /* passwd struct obtained from fgetpwent() */
  struct passwd *newpw = ctx;
  int gotit = 0;
  int r;

  assert(newpw);

  /* Loop over all passwd entries */
  while ((pw = fgetpwent(oldf)) != NULL)
    {
      if(!gotit && streq(newpw->pw_name, pw->pw_name))
	{
	  /* XXX we don't support changing uid/gid yet */
	  int changed = 0;
	  if (newpw->pw_passwd != NULL && !streq(pw->pw_passwd, newpw->pw_passwd))
	    {
	      pw->pw_passwd = newpw->pw_passwd;
	      changed = 1;
	    }
	  if (newpw->pw_shell != NULL && !streq(pw->pw_shell, newpw->pw_shell))
	    {
	      pw->pw_shell = newpw->pw_shell;
	      changed = 1;
	    }
	  if (newpw->pw_gecos != NULL && !streq(pw->pw_gecos, newpw->pw_gecos))
	    {
	      pw->pw_gecos = newpw->pw_gecos;
	      changed = 1;
	    }
	  if (newpw->pw_dir != NULL && !streq(pw->pw_dir, newpw->pw_dir))
	    {
	      pw->pw_dir = newpw->pw_dir;
	      changed = 1;
	    }

	  if (!changed) /* nothing to change, change nothing */
	    return 0;

	  gotit = 1;
	}

      /* write the passwd entry to tmp file */
      r = putpwent(pw, newf);
      if (r < 0)
	return -errno;
    }

  return gotit;
}

int
update_passwd(struct passwd *newpw, const char *etcdir)
{
  return update_account_file(etcdir, "passwd", update_passwd_file, newpw);
}

static int update_shadow_file(FILE *oldf, FILE *newf, void *ctx) {
  struct spwd *sp; /* shadow struct obtained from fgetspent() */
  struct spwd *newsp = ctx;
  int gotit = 0;
  int r;

  assert(newsp);

  /* Loop over all shadow entries */
  while ((sp = fgetspent(oldf)) != NULL)
    {
      if(!gotit && streq(newsp->sp_namp, sp->sp_namp))
	{
	  /* write the new shadow entry to tmp file */
	  r = putspent(newsp, newf);
	  if (r < 0)
	    return -errno;
	  gotit = 1;
	}
      else
	{
	  /* write the shadow entry to tmp file */
	  r = putspent(sp, newf);
	  if (r < 0)
	    return -errno;
	}
    }

    return gotit;
}


int
update_shadow(struct spwd *newsp, const char *etcdir)
{
	return update_account_file(etcdir, "shadow", update_shadow_file, newsp);
}

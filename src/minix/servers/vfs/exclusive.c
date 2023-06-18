#include "fs.h"
#include <minix/vfsif.h>
#include "file.h"
#include "path.h"
#include "vnode.h"
#include "scratchpad.h"
#include <sys/fcntl.h>

int excl_nr = 0;

void dec_excl_nr() {
	--excl_nr;
}

int do_exclusive(void) {
	int flags = job_m_in.m_lc_vfs_exclusive.flags;
	if (flags != EXCL_UNLOCK && flags != EXCL_UNLOCK_FORCE && flags != EXCL_LOCK && flags != EXCL_LOCK_NO_OTHERS) {
		return EINVAL;
	}
	struct vnode *vp;
	struct vmnt *vmp;
	int r;
	char fullpath[PATH_MAX];
	struct lookup resolve;
	vir_bytes vname;
	size_t vname_length;

	vname = job_m_in.m_lc_vfs_exclusive.name;
	vname_length = job_m_in.m_lc_vfs_exclusive.len;

	lookup_init(&resolve, fullpath, PATH_NOFLAGS, &vmp, &vp);
	resolve.l_vmnt_lock = VMNT_READ;
	resolve.l_vnode_lock = VNODE_WRITE;

	if (fetch_name(vname, vname_length, fullpath) != OK) return(err_code);
	if ((vp = eat_path(&resolve, fp)) == NULL) return(err_code);

	if (forbidden(fp, vp, R_BIT) != OK && forbidden(fp, vp, W_BIT) != OK) {
		r = EACCES;
		goto final;
	}
	if (!S_ISREG(vp->v_mode)) {
		r = EFTYPE;
		goto final;
	}
	if (flags == EXCL_LOCK) {
		if (vp->is_locked) {
			r = EALREADY;
			goto final;
		}
		if (excl_nr == NR_EXCLUSIVE) {
			r = ENOLCK;
			goto final;
		}
		vp->is_locked = 1;
		vp->locker_id = fp->fp_realuid;
		vp->is_fd_locked = 0;
		++vp->v_ref_count;
		++excl_nr;
	}
	if (flags == EXCL_LOCK_NO_OTHERS) {
		if (vp->is_locked) {
			r = EALREADY;
			goto final;
		}
		if (excl_nr == NR_EXCLUSIVE) {
			r = ENOLCK;
			goto final;
		}
		for (int i = 0; i < NR_PROCS; ++i) {
			if (fproc[i].fp_realuid == fp->fp_realuid) {
				continue;
			}
			for (int j = 0; j < OPEN_MAX; ++j) {
				if (fproc[i].fp_filp[j] != NULL && fproc[i].fp_filp[j]->filp_vno != NULL
				 		&& fproc[i].fp_filp[j]->filp_vno->v_inode_nr == vp->v_inode_nr) {
					r = EAGAIN;
					goto final;
				}
			}
		}
		vp->is_locked = 1;
		vp->locker_id = fp->fp_realuid;
		vp->is_fd_locked = 0;
		++vp->v_ref_count;
		++excl_nr;
	}
	if (flags == EXCL_UNLOCK) {
		if (!vp->is_locked) {
			r = EINVAL;
			goto final;
		}
		if (vp->locker_id != fp->fp_realuid) {
			r = EPERM;
			goto final;
		}
		vp->is_locked = 0;
		--vp->v_ref_count;
		--excl_nr;
	}
	if (flags == EXCL_UNLOCK_FORCE) {
		if (!vp->is_locked) {
			r = EINVAL;
			goto final;
		}
		if (vp->locker_id != fp->fp_realuid && fp->fp_realuid != 0 && fp->fp_realuid != vp->v_uid) {
			r = EPERM;
			goto final;
		}
		vp->is_locked = 0;
		--vp->v_ref_count;
		--excl_nr;
	}

	r = OK;

	final:
	unlock_vnode(vp);
	unlock_vmnt(vmp);
	put_vnode(vp);
	return r;
}

int do_fexclusive(void) {
	int flags = job_m_in.m_lc_vfs_exclusive.flags;
	if (flags != EXCL_UNLOCK && flags != EXCL_UNLOCK_FORCE && flags != EXCL_LOCK && flags != EXCL_LOCK_NO_OTHERS) {
		return EINVAL;
	}
	struct filp *rfilp;
	struct vnode *vp;
	int r;

	scratch(fp).file.fd_nr = job_m_in.m_lc_vfs_exclusive.fd;

	/* File is already opened; get a vnode pointer from filp */
	if ((rfilp = get_filp(scratch(fp).file.fd_nr, VNODE_WRITE)) == NULL)
		return EBADF;

	vp = rfilp->filp_vno;
	if (!(rfilp->filp_mode & R_BIT) && !(rfilp->filp_mode & R_BIT)) {
		r = EBADF;
		goto final;
	}
	if (!S_ISREG(vp->v_mode)) {
		r = EFTYPE;
		goto final;
	}

	if (flags == EXCL_LOCK) {
		if (vp->is_locked) {
			r = EALREADY;
			goto final;
		}
		if (excl_nr == NR_EXCLUSIVE) {
			r = ENOLCK;
			goto final;
		}
		vp->is_locked = 1;
		vp->locker_id = fp->fp_realuid;
		vp->is_fd_locked = 1;
		++vp->v_ref_count;
		++excl_nr;
	}
	if (flags == EXCL_LOCK_NO_OTHERS) {
		if (vp->is_locked) {
			r = EALREADY;
			goto final;
		}
		if (excl_nr == NR_EXCLUSIVE) {
			r = ENOLCK;
			goto final;
		}
		for (int i = 0; i < NR_PROCS; ++i) {
			if (fproc[i].fp_realuid == fp->fp_realuid) {
				continue;
			}
			for (int j = 0; j < OPEN_MAX; ++j) {
				if (fproc[i].fp_filp[j] != NULL && fproc[i].fp_filp[j]->filp_vno != NULL
				 		&& fproc[i].fp_filp[j]->filp_vno->v_inode_nr == vp->v_inode_nr) {
					r = EAGAIN;
					goto final;
				}
			}
		}
		vp->is_locked = 1;
		vp->locker_id = fp->fp_realuid;
		vp->is_fd_locked = 1;
		++vp->v_ref_count;
		++excl_nr;
	}
	if (flags == EXCL_UNLOCK) {
		if (!vp->is_locked) {
			r = EINVAL;
			goto final;
		}
		if (vp->locker_id != fp->fp_realuid) {
			r = EPERM;
			goto final;
		}
		vp->is_locked = 0;
		--vp->v_ref_count;
		--excl_nr;
	}
	if (flags == EXCL_UNLOCK_FORCE) {
		if (!vp->is_locked) {
			r = EINVAL;
			goto final;
		}
		if (vp->locker_id != fp->fp_realuid && fp->fp_realuid != 0 && fp->fp_realuid != vp->v_uid) {
			r = EPERM;
			goto final;
		}
		vp->is_locked = 0;
		--vp->v_ref_count;
		--excl_nr;
	}

	r = OK;

	final:
	unlock_filp(rfilp);
	return r;
}

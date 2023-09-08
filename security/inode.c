#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/namei.h>
#include <linux/security.h>
#include <linux/magic.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

static struct vfsmount *securityfs_mount;
static int securityfs_mount_count;

static void securityfs_free_inode(struct inode *inode)
{
	if (S_ISLNK(inode->i_mode))
		kfree(inode->i_link);
	free_inode_nonrcu(inode);
}

static const struct super_operations securityfs_super_operations = {
	.statfs		= simple_statfs,
	.free_inode	= securityfs_free_inode,
};

static int securityfs_fill_super(struct super_block *sb)
{
	static const struct tree_descr files[] = {{""}};
	int error;

	error = simple_fill_super(sb, SECURITYFS_MAGIC, files);
	if (error)
		return error;

	sb->s_op = &securityfs_super_operations;

	return 0;
}

static int securityfs_get_tree(struct fs_context *fc)
{
	return get_tree_single(fc, securityfs_fill_super);
}

static const struct fs_context_operations securityfs_context_ops = {
	.get_tree	= securityfs_get_tree,
};

static int securityfs_init_fs_context(struct fs_context *fc)
{
	fc->ops = &securityfs_context_ops;
	return 0;
}

static struct file_system_type securityfs_fs_type = {
	.owner =	THIS_MODULE,
	.name =		"securityfs",
	.init_fs_context = securityfs_init_fs_context,
	.kill_sb =	kill_litter_super,
};

/**
 * securityfs_create_file - create a file in the securityfs filesystem
 *
 * @name: a pointer to a string containing the name of the file to create.
 * @mode: the permission that the file should have
 * @parent: a pointer to the parent dentry for this file.  This should be a
 *          directory dentry if set.  If this parameter is %NULL, then the
 *          file will be created in the root of the securityfs filesystem.
 * @data: a pointer to something that the caller will want to get to later
 *        on.  The inode.i_private pointer will point to this value on
 *        the open() call.
 * @fops: a pointer to a struct file_operations that should be used for
 *        this file.
 *
 * This function creates a file in securityfs with the given @name.
 *
 * This function returns a pointer to a dentry if it succeeds.  This
 * pointer must be passed to the securityfs_remove() function when the file is
 * to be removed (no automatic cleanup happens if your module is unloaded,
 * you are responsible here).  If an error occurs, the function will return
 * the error value (via ERR_PTR).
 *
 * If securityfs is not enabled in the kernel, the value %-ENODEV is
 * returned.
 */
struct dentry *securityfs_create_file(const char *name, umode_t mode,
				      struct dentry *parent, void *data,
				      const struct file_operations *fops)
{
	struct dentry *dentry;
	struct inode *dir, *inode;
	int error;

	if (!(mode & S_IFMT))
		mode = (mode & S_IALLUGO) | S_IFREG;

	error = simple_pin_fs(&securityfs_fs_type, &securityfs_mount,
	                      &securityfs_mount_count);
	if (error)
		return ERR_PTR(error);

	if (!parent)
		parent = securityfs_mount->mnt_root;

	dir = d_inode(parent);

	inode_lock(dir);
	dentry = lookup_one_len(name, parent, strlen(name));
	if (IS_ERR(dentry))
		goto out;

	if (d_really_is_positive(dentry)) {
		error = -EEXIST;
		goto out1;
	}

	inode = new_inode(dir->i_sb);
	if (!inode) {
		error = -ENOMEM;
		goto out1;
	}

	inode->i_ino = get_next_ino();
	inode->i_mode = mode;
	inode->i_atime = inode->i_mtime = inode_set_ctime_current(inode);
	inode->i_private = data;
	if (S_ISDIR(mode)) {
		inode->i_op = &simple_dir_inode_operations;
		inode->i_fop = &simple_dir_operations;
		inc_nlink(inode);
		inc_nlink(dir);
	} else if (S_ISLNK(mode)) {
		inode->i_op = &simple_symlink_inode_operations;
		inode->i_link = kstrdup(data, GFP_KERNEL);
		if (!inode->i_link) {
			error = -ENOMEM;
			goto out2;
		}
	} else {
		inode->i_fop = fops;
	}
	d_instantiate(dentry, inode);
	dget(dentry);
	inode_unlock(dir);
	return dentry;

out2:
	iput(inode);
out1:
	dput(dentry);
out:
	inode_unlock(dir);
	simple_release_fs(&securityfs_mount, &securityfs_mount_count);
	return ERR_PTR(error);
}
EXPORT_SYMBOL_GPL(securityfs_create_file);

/**
 * securityfs_remove - removes a file or directory from the securityfs filesystem
 *
 * @dentry: a pointer to the dentry of the file or directory to be removed.
 *
 * This function removes a file or directory in securityfs that was previously
 * created with a call to another securityfs function (like
 * securityfs_create_file() or variants thereof.)
 *
 * This function is required to be called in order for the file to be
 * removed. No automatic cleanup of files will happen when a module is
 * removed; you are responsible here.
 */
void securityfs_remove(struct dentry *dentry)
{
	struct inode *dir;
	int is_dir;

	if (!dentry || IS_ERR(dentry))
		return;

	dir = d_inode(dentry->d_parent);
	is_dir = d_really_is_dir(dentry);

	inode_lock(dir);
	if (simple_positive(dentry)) {
		if (is_dir)
			simple_rmdir(dir, dentry);
		else
			simple_unlink(dir, dentry);
	}
	dput(dentry);
	inode_unlock(dir);
	simple_release_fs(&securityfs_mount, &securityfs_mount_count);
}
EXPORT_SYMBOL_GPL(securityfs_remove);

#ifdef CONFIG_SECURITY
static struct dentry *lsm_dentry;
static char lsm_names[] = "example-lsm\n";

static ssize_t lsm_read(struct file *filp, char __user *buf, size_t count,
			loff_t *ppos)
{
	return simple_read_from_buffer(buf, count, ppos, lsm_names,
		strlen(lsm_names));
}

static const struct file_operations lsm_ops = {
	.read = lsm_read,
	.llseek = generic_file_llseek,
};

static int __init securityfs_init(void)
{
	int retval;

	retval = sysfs_create_mount_point(kernel_kobj, "security");
	if (retval)
		return retval;

	retval = register_filesystem(&securityfs_fs_type);
	if (retval) {
		sysfs_remove_mount_point(kernel_kobj, "security");
		return retval;
	}

#ifdef CONFIG_SECURITY
	lsm_dentry = securityfs_create_file("lsm", 0444, NULL, NULL, &lsm_ops);
	if (IS_ERR(lsm_dentry)) {
		unregister_filesystem(&securityfs_fs_type);
		sysfs_remove_mount_point(kernel_kobj, "security");
		return PTR_ERR(lsm_dentry);
	}
#endif

	return 0;
}
core_initcall(securityfs_init);

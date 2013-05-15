
msg "nothing"
do_test ""

msg "a single file"
do_test "echo 1 > file"

msg "a single directory"
do_test "mkdir dir"

msg "subdirectory with file"
do_test "mkdir dir; echo 1 > dir/file"

msg "empty file"
do_test "echo -n > empty_file"

msg "two empty files"
do_test "echo -n > empty_file_1; echo -n > empty_file_2"

msg "hard link in same directory"
do_test "echo 1 > file; ln file link"

msg "hard link between empty files"
do_test "echo -n > empty_file; ln empty_file link"

msg "relative symbolic link"
do_test "echo 1 > file; ln -s file symlink"

msg "absolute symbolic link"
do_test "echo 1 > file; ln -s /some/absolute/target symlink"

msg "large file"
do_test "dd if=/dev/zero of=file bs=4096 count=10 &> /dev/null"

msg "many nested directories"
do_test 'mkdir dir; mkdir dir/subdir; mkdir dir/subdir/subdir2; mkdir dir/subdir/subdir3'

msg "identical files and symlinks in subdirectory"
do_test 'mkdir dir;
	 echo 888 > dir/file;
	 echo 888 > dir/idfile2;
	 ln -s ../dir dir/circle; ln -s file dir/filelink'

msg "hard link group and identical files not hard linked"
do_test 'echo 888 > file;
	 echo 888 > file2;
	 ln file link;
	 ln file link2;
	 echo 888 > file3'

msg "C source code of wimlib"
do_test 'cp $srcdir/src/*.c .'

msg "tons of random stuff"
do_test 'echo -n 8 > file;
	 ln file hardlink;
	 ln -s hardlink symlink;
	 echo -n 8 > identical file;
	 dd if=/dev/urandom of=randomfile bs=4096 count=10 &>/dev/null;
	 mkdir dir;
	 mkdir anotherdir;
	 cp file anotherdir;
	 ln file anotherdir/anotherhardlink;
	 ln -s .. anotherdir/anothersymlink;
	 ln -s anothersymlink anotherdir/symlinktosymlink;
	 echo -n 33 > anotherfile;
	 echo -n > emptyfile;
	 mkdir dir/subdir;
	 ln file dir/subdir/file;
	 echo -n 8 > dir/subdir/file2;
	 ln dir/subdir/file dir/subdir/link;'

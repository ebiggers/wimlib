if stat -c %i . &> /dev/null ; then
	BSD_STAT=0
else
	BSD_STAT=1
fi

get_inode_number()
{
	if [ "$BSD_STAT" -eq 1 ]; then
		stat -f %i "$1"
	else
		stat -c %i "$1"
	fi
}

get_link_count()
{
	if [ "$BSD_STAT" -eq 1 ]; then
		stat -f %l "$1"
	else
		stat -c %h "$1"
	fi
}

get_file_size()
{
	if [ "$BSD_STAT" -eq 1 ]; then
		stat -f %z "$1"
	else
		stat -c %s "$1"
	fi
}

wimlib_imagex()
{
	../../wimlib-imagex "$@"
}

wimappend()
{
	wimlib_imagex append "$@" > null
}

wimapply()
{
	wimlib_imagex apply "$@" > null
}

wimcapture()
{
	wimlib_imagex capture "$@" > null
}

wimdelete()
{
	wimlib_imagex delete "$@" > null
}

wimdir()
{
	wimlib_imagex dir "$@"
}

wimexport()
{
	wimlib_imagex export "$@" > null
}

wimextract()
{
	wimlib_imagex extract "$@" > null
}

wiminfo()
{
	wimlib_imagex info "$@"
}

wimjoin()
{
	wimlib_imagex join "$@" > null
}

wimmount()
{
	wimlib_imagex mount "$@" > null
}

wimmountrw()
{
	wimlib_imagex mountrw "$@" > null
}

wimoptimize()
{
	wimlib_imagex optimize "$@" > null
}

wimsplit()
{
	wimlib_imagex split "$@" > null
}

wimunmount()
{
	wimlib_imagex unmount "$@" > null
}

wimupdate()
{
	wimlib_imagex update "$@" > null
}

wimverify()
{
	wimlib_imagex verify "$@" > null
}

wim_ctype()
{
	wiminfo $1 | grep Compression | awk '{print $2}'
}

default_cleanup()
{
	rm -rf $TEST_SUBDIR
}

error()
{
	echo "****************************************************************"
	echo "                         Test failure                           "
	echo $*
	echo "****************************************************************"
	exit 1
}

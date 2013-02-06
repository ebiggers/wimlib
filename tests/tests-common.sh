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

imagex()
{
	echo "imagex $@"
	if [[ $1 == info || $1 == mountrw ]]; then
		../../imagex "$@"
	else
		../../imagex "$@" > /dev/null
	fi
}

wim_ctype()
{
	imagex info $1 | grep Compression | awk '{print $2}'
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

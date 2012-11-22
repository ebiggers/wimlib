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

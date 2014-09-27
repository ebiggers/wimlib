/* 
 * wgetopt.c:  Wide-character versions of getopt, getopt_long, and
 * getopt_long_only.
 *
 * This has been modified from the original, which is
 * Copyright (C) 1987, 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996,
 * 1997, 1998, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009,
 * 2010 Free Software Foundation, Inc.
 *
 * This file is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 3 of the License, or (at your option) any later
 * version.
 *
 * This file is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this file; if not, see http://www.gnu.org/licenses/.
 */

#include "wgetopt.h"
#include <stdlib.h>
#include <stdio.h>

/* For communication from `getopt' to the caller.
   When `getopt' finds an option that takes an argument,
   the argument value is returned here.
   Also, when `ordering' is RETURN_IN_ORDER,
   each non-option ARGV-element is returned here.  */

wchar_t *woptarg = NULL;

/* Index in ARGV of the next element to be scanned.
   This is used for communication to and from the caller
   and for communication between successive calls to `getopt'.

   On entry to `getopt', zero means this is the first call; initialize.

   When `getopt' returns -1, this is the index of the first of the
   non-option elements that the caller should itself scan.

   Otherwise, `woptind' communicates from one call to the next
   how much of ARGV has been scanned so far.  */

/* 1003.2 says this must be 1 before any call.  */
int woptind = 1;

/* Formerly, initialization of getopt depended on woptind==0, which
   causes problems with re-calling getopt as programs generally don't
   know that. */

int __getopt_initialized = 0;

/* The next char to be scanned in the option-element
   in which the last option character we returned was found.
   This allows us to pick up the scan where we left off.

   If this is zero, or a null string, it means resume the scan
   by advancing to the next ARGV-element.  */

static wchar_t *nextchar;

/* Callers store zero here to inhibit the error message
   for unrecognized options.  */

int wopterr = 1;

/* Set to an option character which was unrecognized.
   This must be initialized on some systems to avoid linking in the
   system's own getopt implementation.  */

int woptopt = '?';

/* Describe how to deal with options that follow non-option ARGV-elements.

   If the caller did not specify anything,
   the default is REQUIRE_ORDER if the environment variable
   POSIXLY_CORRECT is defined, PERMUTE otherwise.

   REQUIRE_ORDER means don't recognize them as options;
   stop option processing when the first non-option is seen.
   This is what Unix does.
   This mode of operation is selected by either setting the environment
   variable POSIXLY_CORRECT, or using `+' as the first character
   of the list of option characters.

   PERMUTE is the default.  We permute the contents of ARGV as we scan,
   so that eventually all the non-options are at the end.  This allows options
   to be given in any order, even with programs that were not written to
   expect this.

   RETURN_IN_ORDER is an option available to programs that were written
   to expect options and other ARGV-elements in any order and that care about
   the ordering of the two.  We describe each non-option ARGV-element
   as if it were the argument of an option with character code 1.
   Using `-' as the first character of the list of option characters
   selects this mode of operation.

   The special argument `--' forces an end of option-scanning regardless
   of the value of `ordering'.  In the case of RETURN_IN_ORDER, only
   `--' can cause `getopt' to return -1 with `woptind' != ARGC.  */

static enum
{
  REQUIRE_ORDER, PERMUTE, RETURN_IN_ORDER
} ordering;

/* Value of POSIXLY_CORRECT environment variable.  */
static char *posixly_correct;


/* Handle permutation of arguments.  */

/* Describe the part of ARGV that contains non-options that have
   been skipped.  `first_nonopt' is the index in ARGV of the first of them;
   `last_nonopt' is the index after the last of them.  */

static int first_nonopt;
static int last_nonopt;

/* Exchange two adjacent subsequences of ARGV.
   One subsequence is elements [first_nonopt,last_nonopt)
   which contains all the non-options that have been skipped so far.
   The other is elements [last_nonopt,woptind), which contains all
   the options processed since those non-options were skipped.

   `first_nonopt' and `last_nonopt' are relocated so that they describe
   the new indices of the non-options in ARGV after they are moved.  */

static void
exchange (wchar_t **argv)
{
  int bottom = first_nonopt;
  int middle = last_nonopt;
  int top = woptind;
  wchar_t *tem;

  /* Exchange the shorter segment with the far end of the longer segment.
     That puts the shorter segment into the right place.
     It leaves the longer segment in the right place overall,
     but it consists of two parts that need to be swapped next.  */

  while (top > middle && middle > bottom)
    {
      if (top - middle > middle - bottom)
	{
	  /* Bottom segment is the short one.  */
	  int len = middle - bottom;
	  register int i;

	  /* Swap it with the top part of the top segment.  */
	  for (i = 0; i < len; i++)
	    {
	      tem = argv[bottom + i];
	      argv[bottom + i] = argv[top - (middle - bottom) + i];
	      argv[top - (middle - bottom) + i] = tem;
	    }
	  /* Exclude the moved bottom segment from further swapping.  */
	  top -= len;
	}
      else
	{
	  /* Top segment is the short one.  */
	  int len = top - middle;
	  register int i;

	  /* Swap it with the bottom part of the bottom segment.  */
	  for (i = 0; i < len; i++)
	    {
	      tem = argv[bottom + i];
	      argv[bottom + i] = argv[middle + i];
	      argv[middle + i] = tem;
	    }
	  /* Exclude the moved top segment from further swapping.  */
	  bottom += len;
	}
    }

  /* Update records for the slots the non-options now occupy.  */

  first_nonopt += (woptind - last_nonopt);
  last_nonopt = woptind;
}

/* Initialize the internal data when the first call is made.  */

static const wchar_t *
_getopt_initialize (int argc, wchar_t *const *argv, const wchar_t *optstring)
{
  /* Start processing options with ARGV-element 1 (since ARGV-element 0
     is the program name); the sequence of previously skipped
     non-option ARGV-elements is empty.  */

  first_nonopt = last_nonopt = woptind;

  nextchar = NULL;

  posixly_correct = getenv ("POSIXLY_CORRECT");

  /* Determine how to handle the ordering of options and nonoptions.  */

  if (optstring[0] == L'-')
    {
      ordering = RETURN_IN_ORDER;
      ++optstring;
    }
  else if (optstring[0] == L'+')
    {
      ordering = REQUIRE_ORDER;
      ++optstring;
    }
  else if (posixly_correct != NULL)
    ordering = REQUIRE_ORDER;
  else
    ordering = PERMUTE;

  return optstring;
}

/* Scan elements of ARGV (whose length is ARGC) for option characters
   given in OPTSTRING.

   If an element of ARGV starts with '-', and is not exactly "-" or "--",
   then it is an option element.  The characters of this element
   (aside from the initial '-') are option characters.  If `getopt'
   is called repeatedly, it returns successively each of the option characters
   from each of the option elements.

   If `getopt' finds another option character, it returns that character,
   updating `woptind' and `nextchar' so that the next call to `getopt' can
   resume the scan with the following option character or ARGV-element.

   If there are no more option characters, `getopt' returns -1.
   Then `woptind' is the index in ARGV of the first ARGV-element
   that is not an option.  (The ARGV-elements have been permuted
   so that those that are not options now come last.)

   OPTSTRING is a string containing the legitimate option characters.
   If an option character is seen that is not listed in OPTSTRING,
   return '?' after printing an error message.  If you set `wopterr' to
   zero, the error message is suppressed but we still return '?'.

   If a char in OPTSTRING is followed by a colon, that means it wants an arg,
   so the following text in the same ARGV-element, or the text of the following
   ARGV-element, is returned in `woptarg'.  Two colons mean an option that
   wants an optional arg; if there is text in the current ARGV-element,
   it is returned in `woptarg', otherwise `woptarg' is set to zero.

   If OPTSTRING starts with `-' or `+', it requests different methods of
   handling the non-option ARGV-elements.
   See the comments about RETURN_IN_ORDER and REQUIRE_ORDER, above.

   Long-named options begin with `--' instead of `-'.
   Their names may be abbreviated as long as the abbreviation is unique
   or is an exact match for some defined option.  If they have an
   argument, it follows the option name in the same ARGV-element, separated
   from the option name by a `=', or else the in next ARGV-element.
   When `getopt' finds a long-named option, it returns 0 if that option's
   `flag' field is nonzero, the value of the option's `val' field
   if the `flag' field is zero.

   The elements of ARGV aren't really const, because we permute them.
   But we pretend they're const in the prototype to be compatible
   with other systems.

   LONGOPTS is a vector of `struct woption' terminated by an
   element containing a name which is zero.

   LONGIND returns the index in LONGOPT of the long-named option found.
   It is only valid when a long-named option has been found by the most
   recent call.

   If LONG_ONLY is nonzero, '-' as well as '--' can introduce
   long-named options.  */

static int
_wgetopt_internal (int argc, wchar_t *const *argv, const wchar_t *optstring,
                  const struct woption *longopts, int *longind, int long_only)
{
  woptarg = NULL;

  if (woptind == 0 || !__getopt_initialized)
    {
      if (woptind == 0)
	woptind = 1;	/* Don't scan ARGV[0], the program name.  */
      optstring = _getopt_initialize (argc, argv, optstring);
      __getopt_initialized = 1;
    }

  /* Test whether ARGV[woptind] points to a non-option argument.
     Either it does not have option syntax, or there is an environment flag
     from the shell indicating it is not an option.  The later information
     is only used when the used in the GNU libc.  */
# define NONOPTION_P (argv[woptind][0] != L'-' || argv[woptind][1] == L'\0')

  if (nextchar == NULL || *nextchar == '\0')
    {
      /* Advance to the next ARGV-element.  */

      /* Give FIRST_NONOPT & LAST_NONOPT rational values if OPTIND has been
	 moved back by the user (who may also have changed the arguments).  */
      if (last_nonopt > woptind)
	last_nonopt = woptind;
      if (first_nonopt > woptind)
	first_nonopt = woptind;

      if (ordering == PERMUTE)
	{
	  /* If we have just processed some options following some non-options,
	     exchange them so that the options come first.  */

	  if (first_nonopt != last_nonopt && last_nonopt != woptind)
	    exchange ((wchar_t **) argv);
	  else if (last_nonopt != woptind)
	    first_nonopt = woptind;

	  /* Skip any additional non-options
	     and extend the range of non-options previously skipped.  */

	  while (woptind < argc && NONOPTION_P)
	    woptind++;
	  last_nonopt = woptind;
	}

      /* The special ARGV-element `--' means premature end of options.
	 Skip it like a null option,
	 then exchange with previous non-options as if it were an option,
	 then skip everything else like a non-option.  */

      if (woptind != argc && !wcscmp (argv[woptind], L"--"))
	{
	  woptind++;

	  if (first_nonopt != last_nonopt && last_nonopt != woptind)
	    exchange ((wchar_t **) argv);
	  else if (first_nonopt == last_nonopt)
	    first_nonopt = woptind;
	  last_nonopt = argc;

	  woptind = argc;
	}

      /* If we have done all the ARGV-elements, stop the scan
	 and back over any non-options that we skipped and permuted.  */

      if (woptind == argc)
	{
	  /* Set the next-arg-index to point at the non-options
	     that we previously skipped, so the caller will digest them.  */
	  if (first_nonopt != last_nonopt)
	    woptind = first_nonopt;
	  return -1;
	}

      /* If we have come to a non-option and did not permute it,
	 either stop the scan or describe it to the caller and pass it by.  */

      if (NONOPTION_P)
	{
	  if (ordering == REQUIRE_ORDER)
	    return -1;
	  woptarg = argv[woptind++];
	  return 1;
	}

      /* We have found another option-ARGV-element.
	 Skip the initial punctuation.  */

      nextchar = (argv[woptind] + 1
		  + (longopts != NULL && argv[woptind][1] == L'-'));
    }

  /* Decode the current option-ARGV-element.  */

  /* Check whether the ARGV-element is a long option.

     If long_only and the ARGV-element has the form "-f", where f is
     a valid short option, don't consider it an abbreviated form of
     a long option that starts with f.  Otherwise there would be no
     way to give the -f short option.

     On the other hand, if there's a long option "fubar" and
     the ARGV-element is "-fu", do consider that an abbreviation of
     the long option, just like "--fu", and not "-f" with arg "u".

     This distinction seems to be the most useful approach.  */

  if (longopts != NULL
      && (argv[woptind][1] == L'-'
	  || (long_only && (argv[woptind][2] || !wcschr (optstring, argv[woptind][1])))))
    {
      wchar_t *nameend;
      const struct woption *p;
      const struct woption *pfound = NULL;
      int exact = 0;
      int ambig = 0;
      int indfound = -1;
      int option_index;

      for (nameend = nextchar; *nameend && *nameend != L'='; nameend++)
	/* Do nothing.  */ ;

      /* Test all long options for either exact match
	 or abbreviated matches.  */
      for (p = longopts, option_index = 0; p->name; p++, option_index++)
	if (!wcsncmp (p->name, nextchar, nameend - nextchar))
	  {
	    if ((unsigned int) (nameend - nextchar)
		== (unsigned int) wcslen (p->name))
	      {
		/* Exact match found.  */
		pfound = p;
		indfound = option_index;
		exact = 1;
		break;
	      }
	    else if (pfound == NULL)
	      {
		/* First nonexact match found.  */
		pfound = p;
		indfound = option_index;
	      }
	    else
	      /* Second or later nonexact match found.  */
	      ambig = 1;
	  }

      if (ambig && !exact)
	{
	  if (wopterr)
	    fwprintf (stderr, L"%ls: option `%ls' is ambiguous\n",
		      argv[0], argv[woptind]);
	  nextchar += wcslen (nextchar);
	  woptind++;
	  woptopt = 0;
	  return L'?';
	}

      if (pfound != NULL)
	{
	  option_index = indfound;
	  woptind++;
	  if (*nameend)
	    {
	      /* Don't test has_arg with >, because some C compilers don't
		 allow it to be used on enums.  */
	      if (pfound->has_arg)
		woptarg = nameend + 1;
	      else
		{
		  if (wopterr) {
		   if (argv[woptind - 1][1] == L'-')
		    /* --option */
		    fwprintf (stderr,
		     L"%ls: option `--%ls' doesn't allow an argument\n",
		     argv[0], pfound->name);
		   else
		    /* +option or -option */
		    fwprintf (stderr,
		     L"%ls: option `%lc%ls' doesn't allow an argument\n",
		     argv[0], argv[woptind - 1][0], pfound->name);
		  }

		  nextchar += wcslen (nextchar);

		  woptopt = pfound->val;
		  return L'?';
		}
	    }
	  else if (pfound->has_arg == 1)
	    {
	      if (woptind < argc)
		woptarg = argv[woptind++];
	      else
		{
		  if (wopterr)
		    fwprintf (stderr,
			   L"%ls: option `%ls' requires an argument\n",
			   argv[0], argv[woptind - 1]);
		  nextchar += wcslen (nextchar);
		  woptopt = pfound->val;
		  return optstring[0] == L':' ? L':' : L'?';
		}
	    }
	  nextchar += wcslen (nextchar);
	  if (longind != NULL)
	    *longind = option_index;
	  if (pfound->flag)
	    {
	      *(pfound->flag) = pfound->val;
	      return 0;
	    }
	  return pfound->val;
	}

      /* Can't find it as a long option.  If this is not getopt_long_only,
	 or the option starts with '--' or is not a valid short
	 option, then it's an error.
	 Otherwise interpret it as a short option.  */
      if (!long_only || argv[woptind][1] == L'-'
	  || wcschr (optstring, *nextchar) == NULL)
	{
	  if (wopterr)
	    {
	      if (argv[woptind][1] == '-')
		/* --option */
		fwprintf (stderr, L"%ls: unrecognized option `--%ls'\n",
			 argv[0], nextchar);
	      else
		/* +option or -option */
		fwprintf (stderr, L"%ls: unrecognized option `%lc%ls'\n",
			 argv[0], argv[woptind][0], nextchar);
	    }
	  nextchar = (wchar_t *) L"";
	  woptind++;
	  woptopt = 0;
	  return L'?';
	}
    }

  /* Look at and handle the next short option-character.  */

  {
    wchar_t c = *nextchar++;
    wchar_t *temp = wcschr (optstring, c);

    /* Increment `woptind' when we start to process its last character.  */
    if (*nextchar == L'\0')
      ++woptind;

    if (temp == NULL || c == L':')
      {
	if (wopterr)
	  {
	    if (posixly_correct)
	      /* 1003.2 specifies the format of this message.  */
	      fwprintf (stderr, L"%ls: illegal option -- %lc\n",
		       argv[0], c);
	    else
	      fwprintf (stderr, L"%ls: invalid option -- %lc\n",
		       argv[0], c);
	  }
	woptopt = c;
	return L'?';
      }
    /* Convenience. Treat POSIX -W foo same as long option --foo */
    if (temp[0] == L'W' && temp[1] == L';')
      {
	wchar_t *nameend;
	const struct woption *p;
	const struct woption *pfound = NULL;
	int exact = 0;
	int ambig = 0;
	int indfound = 0;
	int option_index;

	/* This is an option that requires an argument.  */
	if (*nextchar != L'\0')
	  {
	    woptarg = nextchar;
	    /* If we end this ARGV-element by taking the rest as an arg,
	       we must advance to the next element now.  */
	    woptind++;
	  }
	else if (woptind == argc)
	  {
	    if (wopterr)
	      {
		/* 1003.2 specifies the format of this message.  */
		fwprintf (stderr, L"%ls: option requires an argument -- %lc\n",
			 argv[0], c);
	      }
	    woptopt = c;
	    if (optstring[0] == L':')
	      c = L':';
	    else
	      c = L'?';
	    return c;
	  }
	else
	  /* We already incremented `woptind' once;
	     increment it again when taking next ARGV-elt as argument.  */
	  woptarg = argv[woptind++];

	/* woptarg is now the argument, see if it's in the
	   table of longopts.  */

	for (nextchar = nameend = woptarg; *nameend && *nameend != L'='; nameend++)
	  /* Do nothing.  */ ;

	/* Test all long options for either exact match
	   or abbreviated matches.  */
	for (p = longopts, option_index = 0; p->name; p++, option_index++)
	  if (!wcsncmp (p->name, nextchar, nameend - nextchar))
	    {
	      if ((unsigned int) (nameend - nextchar) == wcslen (p->name))
		{
		  /* Exact match found.  */
		  pfound = p;
		  indfound = option_index;
		  exact = 1;
		  break;
		}
	      else if (pfound == NULL)
		{
		  /* First nonexact match found.  */
		  pfound = p;
		  indfound = option_index;
		}
	      else
		/* Second or later nonexact match found.  */
		ambig = 1;
	    }
	if (ambig && !exact)
	  {
	    if (wopterr)
	      fwprintf (stderr, L"%ls: option `-W %ls' is ambiguous\n",
		       argv[0], argv[woptind]);
	    nextchar += wcslen (nextchar);
	    woptind++;
	    return L'?';
	  }
	if (pfound != NULL)
	  {
	    option_index = indfound;
	    if (*nameend)
	      {
		/* Don't test has_arg with >, because some C compilers don't
		   allow it to be used on enums.  */
		if (pfound->has_arg)
		  woptarg = nameend + 1;
		else
		  {
		    if (wopterr)
		      fwprintf (stderr, L"\
%ls: option `-W %ls' doesn't allow an argument\n",
			       argv[0], pfound->name);

		    nextchar += wcslen (nextchar);
		    return L'?';
		  }
	      }
	    else if (pfound->has_arg == 1)
	      {
		if (woptind < argc)
		  woptarg = argv[woptind++];
		else
		  {
		    if (wopterr)
		      fwprintf (stderr,
			       L"%ls: option `%ls' requires an argument\n",
			       argv[0], argv[woptind - 1]);
		    nextchar += wcslen (nextchar);
		    return optstring[0] == L':' ? L':' : L'?';
		  }
	      }
	    nextchar += wcslen (nextchar);
	    if (longind != NULL)
	      *longind = option_index;
	    if (pfound->flag)
	      {
		*(pfound->flag) = pfound->val;
		return 0;
	      }
	    return pfound->val;
	  }
	  nextchar = NULL;
	  return L'W';	/* Let the application handle it.   */
      }
    if (temp[1] == L':')
      {
	if (temp[2] == L':')
	  {
	    /* This is an option that accepts an argument optionally.  */
	    if (*nextchar != L'\0')
	      {
		woptarg = nextchar;
		woptind++;
	      }
	    else
	      woptarg = NULL;
	    nextchar = NULL;
	  }
	else
	  {
	    /* This is an option that requires an argument.  */
	    if (*nextchar != L'\0')
	      {
		woptarg = nextchar;
		/* If we end this ARGV-element by taking the rest as an arg,
		   we must advance to the next element now.  */
		woptind++;
	      }
	    else if (woptind == argc)
	      {
		if (wopterr)
		  {
		    /* 1003.2 specifies the format of this message.  */
		    fwprintf (stderr,
			     L"%ls: option requires an argument -- %lc\n",
			     argv[0], c);
		  }
		woptopt = c;
		if (optstring[0] == L':')
		  c = L':';
		else
		  c = L'?';
	      }
	    else
	      /* We already incremented `woptind' once;
		 increment it again when taking next ARGV-elt as argument.  */
	      woptarg = argv[woptind++];
	    nextchar = NULL;
	  }
      }
    return c;
  }
}

int
wgetopt (int argc, wchar_t *const *argv, const wchar_t *optstring)
{
  return _wgetopt_internal (argc, argv, optstring,
			    (const struct woption *) 0,
			    (int *) 0,
			    0);
}

int
wgetopt_long (int argc, wchar_t * const *argv, const wchar_t *options,
	      const struct woption *long_options, int *opt_index)
{
  return _wgetopt_internal (argc, argv, options, long_options, opt_index, 0);
}

/* Like getopt_long, but '-' as well as '--' can indicate a long option.
   If an option that starts with '-' (not '--') doesn't match a long option,
   but does match a short option, it is parsed as a short option
   instead.  */
int
wgetopt_long_only (int argc, wchar_t * const *argv, const wchar_t *options,
                  const struct woption *long_options, int *opt_index)
{
  return _wgetopt_internal (argc, argv, options, long_options, opt_index, 1);
}

/*
 * zebra string function
 *
 * XXX This version of snprintf does not check bounds!
 */

/*
 The implementations of strlcpy and strlcat are copied from rsync (GPL):
    Copyright (C) Andrew Tridgell 1998
    Copyright (C) 2002 by Martin Pool

 Note that these are not terribly efficient, since they make more than one
 pass over the argument strings.  At some point, they should be optimized.
 
 The implementation of strndup is copied from glibc-2.3.5:
    Copyright (C) 1996, 1997, 1998, 2001, 2002 Free Software Foundation, Inc.
*/


#include <zebra.h>

#ifndef HAVE_SNPRINTF
/*
 * snprint() is a real basic wrapper around the standard sprintf()
 * without any bounds checking
 */
int
snprintf(char *str, size_t size, const char *format, ...)
{
  va_list args;

  va_start (args, format);

  return vsprintf (str, format, args);
}
#endif

#ifndef HAVE_STRLCPY
/**
 * Like strncpy but does not 0 fill the buffer and always null 
 * terminates.
 *
 * @param bufsize is the size of the destination buffer.
 *
 * @return index of the terminating byte.
 **/
size_t
strlcpy(char *d, const char *s, size_t bufsize)
{
	size_t len = strlen(s);
	size_t ret = len;
	if (bufsize > 0) {
		if (len >= bufsize)
			len = bufsize-1;
		memcpy(d, s, len);
		d[len] = 0;
	}
	return ret;
}
#endif

#ifndef HAVE_STRLCAT
/**
 * Like strncat() but does not 0 fill the buffer and always null 
 * terminates.
 *
 * @param bufsize length of the buffer, which should be one more than
 * the maximum resulting string length.
 **/
size_t
strlcat(char *d, const char *s, size_t bufsize)
{
	size_t len1 = strlen(d);
	size_t len2 = strlen(s);
	size_t ret = len1 + len2;

	if (len1 < bufsize - 1) {
		if (len2 >= bufsize - len1)
			len2 = bufsize - len1 - 1;
		memcpy(d+len1, s, len2);
		d[len1+len2] = 0;
	}
	return ret;
}
#endif

#ifndef HAVE_STRNLEN
size_t
strnlen(const char *s, size_t maxlen)
{
  const char *p;
  return (p = (const char *)memchr(s, '\0', maxlen)) ? (size_t)(p-s) : maxlen;
}
#endif

#ifndef HAVE_STRNDUP
char *
strndup (const char *s, size_t maxlen)
{
    size_t len = strnlen (s, maxlen);
    char *new = (char *) malloc (len + 1);

    if (new == NULL)
      return NULL;

    new[len] = '\0';
    return (char *) memcpy (new, s, len);
}
#endif

/**
 * Function search the speciffied string the table (struct pair pairs[MAX_PAIR_VAL...]) and returns the value with this string
 */
u_int32_t 
str2val(struct pair_val_str *db, const char *str_cmp)
{
  int i;
  for (i=0; i<db->capacity; i++)
  {
    if (strncmp(db->pairs[i].str, str_cmp, db->pairs[i].sign_str_length)==0)
      return db->pairs[i].value;
  }
  return 0;
}

/**
 * Function search the speciffied value in the table (struct pair pairs[MAX_PAIR_VAL...]) and returns the string associeted with this value
 */
const char * 
val2str(struct pair_val_str *db, u_int32_t value)
{
  int i;
  static const char* def_string = "Unknown";
  for (i=0; i < db->capacity; i++)
  {
    if (db->pairs[i].value == value)
      return db->pairs[i].str;
  }
  return def_string;
}

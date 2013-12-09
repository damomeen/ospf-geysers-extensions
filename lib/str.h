/*
 * $Id: str.h,v 1.4 2005/09/19 09:53:21 hasso Exp $
 */

#ifndef _ZEBRA_STR_H
#define _ZEBRA_STR_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef HAVE_SNPRINTF
extern int snprintf(char *, size_t, const char *, ...);
#endif

#ifndef HAVE_VSNPRINTF
#define vsnprintf(buf, size, format, args) vsprintf(buf, format, args)
#endif

#ifndef HAVE_STRLCPY
extern size_t strlcpy(char *, const char *, size_t);
#endif

#ifndef HAVE_STRLCAT
extern size_t strlcat(char *, const char *, size_t);
#endif

#ifndef HAVE_STRNLEN
extern size_t strnlen(const char *s, size_t maxlen);
#endif

#ifndef HAVE_STRNDUP
extern char * strndup (const char *, size_t);
#endif


#define MAX_PAIR_VAL_STR_CAPACITY 50
/**
 * Structure that associates encoding value (u_int32_t value) with name (const char *str)
 * the sing_str_length determines number of significent sings that's are checked during the comparation with speciffied string 
 * there are two functions concerned with struct pair_val_str:
 *  - val2str - returns the string assosiated with speciffied value
 *  - str2val - returns the value assosiated with speciffied string
 */
struct pair_val_str
{
  u_int16_t capacity;
  struct pair
  {
    const char *str;
    u_int32_t value;
    /** Number of significent signs, that are checked during the comparation with speciffied string (function str2value) */
    u_int16_t sign_str_length; 
  } pairs[MAX_PAIR_VAL_STR_CAPACITY];
};

const char * val2str(struct pair_val_str *db, u_int32_t value);
u_int32_t str2val(struct pair_val_str *db, const char *str_cmp);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_STR_H */


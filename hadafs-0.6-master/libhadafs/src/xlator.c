/*
  Copyright (c) 2006-2009 HADA, Inc. <http://www.hada.com>
  This file is part of HADAFS.

  HADAFS is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published
  by the Free Software Foundation; either version 3 of the License,
  or (at your option) any later version.

  HADAFS is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see
  <http://www.gnu.org/licenses/>.
*/

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include "xlator.h"
#include <dlfcn.h>
#include <netdb.h>
#include <fnmatch.h>
#include "defaults.h"


#define SET_DEFAULT_FOP(fn) do {			\
		if (!xl->fops->fn)			\
			xl->fops->fn = default_##fn;	\
	} while (0)

#define SET_DEFAULT_MOP(fn) do {			\
		if (!xl->mops->fn)			\
			xl->mops->fn = default_##fn;	\
	} while (0)

#define SET_DEFAULT_CBK(fn) do {			\
		if (!xl->cbks->fn)			\
			xl->cbks->fn = default_##fn;	\
	} while (0)


#define HF_OPTION_LIST_EMPTY(_opt) (_opt->value[0] == NULL)

static void
fill_defaults (xlator_t *xl)
{
	if (xl == NULL)	{
		hf_log ("xlator", HF_LOG_DEBUG, "invalid argument");
		return;
	}

	SET_DEFAULT_FOP (open);
	SET_DEFAULT_FOP (unlink);
	SET_DEFAULT_FOP (readv);
	SET_DEFAULT_FOP (writev);
	SET_DEFAULT_FOP (ioctl);
	SET_DEFAULT_FOP (flush);
	SET_DEFAULT_FOP (stat);
	SET_DEFAULT_FOP (fstat);
	SET_DEFAULT_FOP (setobject);
	SET_DEFAULT_FOP (updateobject);
	SET_DEFAULT_FOP (getobject);
	SET_DEFAULT_FOP (lookupobject);
	SET_DEFAULT_FOP (deleteobject);
	SET_DEFAULT_FOP (truncate);
	SET_DEFAULT_FOP (ftruncate);
	SET_DEFAULT_CBK (release);
	SET_DEFAULT_CBK (forget);

	if (!xl->notify)
		xl->notify = default_notify;

	return;
}

/* RFC 1123 & 952 */
static char 
valid_host_name (char *address, int length)
{
        int i = 0;
        char ret = 1;

        if ((length > 75) || (length == 1)) {
                ret = 0;
                goto out;
        }

        if (!isalnum (address[length - 1])) {
                ret = 0;
                goto out;
        }

        for (i = 0; i < length; i++) {
                if (!isalnum (address[i]) && (address[i] != '.')
                    && (address[i] != '-')) {
                        ret = 0;
                        goto out;
                }
        }

out:
        return ret;
}

static char
valid_ipv4_address (char *address, int length)
{
        int octets = 0;
        int value = 0;
        char *tmp = NULL, *ptr = NULL, *prev = NULL, *endptr = NULL;
        char ret = 1;

        prev = tmp = strdup (address);
        prev = strtok_r (tmp, ".", &ptr);

        while (prev != NULL) 
        {
                octets++;
                value = strtol (prev, &endptr, 10);
                if ((value > 255) || (value < 0) || (endptr != NULL)) {
                        ret = 0;
                        goto out;
                }
   
                prev = strtok_r (NULL, ".", &ptr);
        }

        if (octets != 4) {
                ret = 0;
        }

out:
        FREE (tmp);
        return ret;
}

static char
valid_ipv6_address (char *address, int length)
{
        int hex_numbers = 0;
        int value = 0;
        char *tmp = NULL, *ptr = NULL, *prev = NULL, *endptr = NULL;
        char ret = 1;

        tmp = strdup (address);
        prev = strtok_r (tmp, ":", &ptr);

        while (prev != NULL) 
        {
                hex_numbers++;
                value = strtol (prev, &endptr, 16);
                if ((value > 0xffff) || (value < 0) || (endptr != NULL)) {
                        ret = 0;
                        goto out;
                }
   
                prev = strtok_r (NULL, ":", &ptr);
        }
        
        if (hex_numbers > 8) {
                ret = 0;
        }

out:
        FREE (tmp);
        return ret;
}

static char
valid_internet_address (char *address)
{
        char ret = 0;
        int length = 0;

        if (address == NULL) {
                goto out;
        }

        length = strlen (address);
        if (length == 0) {
                goto out;
        }

        if (valid_ipv4_address (address, length) 
            || valid_ipv6_address (address, length)
            || valid_host_name (address, length)) {
                ret = 1;
        }

out:        
        return ret;
}

int 
_volume_option_value_validate (xlator_t *xl, 
			       data_pair_t *pair, 
			       volume_option_t *opt)
{
	int       i = 0;
	int       ret = -1;
 	uint64_t  input_size = 0;
	long long inputll = 0;
	
	/* Key is valid, validate the option */
	switch (opt->type) {
	case HF_OPTION_TYPE_PATH:
	{
  			/* Make sure the given path is valid */
		if (pair->value->data[0] != '/') {
			hf_log (xl->name, HF_LOG_WARNING,
				"option %s %s: '%s' is not an "
				"absolute path name",
				pair->key, pair->value->data, 
				pair->value->data);
		}
		ret = 0;
	}
	break;
	case HF_OPTION_TYPE_INT:
	{
		/* Check the range */
		if (hf_string2longlong (pair->value->data, 
					&inputll) != 0) {
			hf_log (xl->name, HF_LOG_ERROR,
				"invalid number format \"%s\" in "
				"\"option %s\"",
				pair->value->data, pair->key);
			goto out;
		}

		if ((opt->min == 0) && (opt->max == 0)) {
			hf_log (xl->name, HF_LOG_DEBUG,
				"no range check required for "
				"'option %s %s'",
				pair->key, pair->value->data);
			ret = 0;
			break;
		}
		if ((inputll < opt->min) || 
		    (inputll > opt->max)) {
			hf_log (xl->name, HF_LOG_WARNING,
				"'%lld' in 'option %s %s' is out of "
				"range [%"PRId64" - %"PRId64"]",
				inputll, pair->key, 
				pair->value->data,
				opt->min, opt->max);
		}
		ret = 0;
	}
	break;
	case HF_OPTION_TYPE_SIZET:
	{
		/* Check the range */
		if (hf_string2bytesize (pair->value->data, 
					&input_size) != 0) {
			hf_log (xl->name, HF_LOG_ERROR,
				"invalid size format \"%s\" in "
				"\"option %s\"",
				pair->value->data, pair->key);
			goto out;
		}

		if ((opt->min == 0) && (opt->max == 0)) {
			hf_log (xl->name, HF_LOG_DEBUG,
				"no range check required for "
				"'option %s %s'",
				pair->key, pair->value->data);
			ret = 0;
			break;
		}
		if ((input_size < opt->min) || 
		    (input_size > opt->max)) {
			hf_log (xl->name, HF_LOG_ERROR,
				"'%"PRId64"' in 'option %s %s' is "
				"out of range [%"PRId64" - %"PRId64"]",
				input_size, pair->key, 
				pair->value->data,
				opt->min, opt->max);
		}
		ret = 0;
	}
	break;
	case HF_OPTION_TYPE_BOOL:
	{
		/* Check if the value is one of 
		   '0|1|on|off|no|yes|true|false|enable|disable' */
		hf_boolean_t bool_value;
		if (hf_string2boolean (pair->value->data, 
				       &bool_value) != 0) {
			hf_log (xl->name, HF_LOG_ERROR,
				"option %s %s: '%s' is not a valid "
				"boolean value",
				pair->key, pair->value->data, 
				pair->value->data);
			goto out;
		}
		ret = 0;
	}
	break;
	case HF_OPTION_TYPE_XLATOR:
	{
		/* Check if the value is one of the xlators */
		xlator_t *xlopt = xl;
		while (xlopt->prev)
			xlopt = xlopt->prev;

		while (xlopt) {
			if (strcmp (pair->value->data, 
				    xlopt->name) == 0) {
				ret = 0;
				break;
			}
			xlopt = xlopt->next;
		}
		if (!xlopt) {
			hf_log (xl->name, HF_LOG_ERROR,
				"option %s %s: '%s' is not a "
				"valid volume name",
				pair->key, pair->value->data, 
				pair->value->data);
		}
		ret = 0;
	}
	break;
	case HF_OPTION_TYPE_STR:
	{
		/* Check if the '*str' is valid */
                if (HF_OPTION_LIST_EMPTY(opt)) {
                        ret = 0;
                        goto out;
                }

		for (i = 0; (i < ZR_OPTION_MAX_ARRAY_SIZE) &&
			     opt->value[i]; i++) {
			if (strcasecmp (opt->value[i], 
					pair->value->data) == 0) {
				ret = 0;
				break;
			}
		}

		if ((i == ZR_OPTION_MAX_ARRAY_SIZE) 
		    || ((i < ZR_OPTION_MAX_ARRAY_SIZE) 
			&& (!opt->value[i]))) {
			/* enter here only if
			 * 1. reached end of opt->value array and haven't validated input
			 *                      OR
			 * 2. valid input list is less than ZR_OPTION_MAX_ARRAY_SIZE and
			 *    input has not matched all possible input values.
			 */
			char given_array[4096] = {0,};
			for (i = 0; (i < ZR_OPTION_MAX_ARRAY_SIZE) &&
				     opt->value[i]; i++) {
				strcat (given_array, opt->value[i]);
				strcat (given_array, ", ");
			}

			hf_log (xl->name, HF_LOG_ERROR,
				"option %s %s: '%s' is not valid "
				"(possible options are %s)",
				pair->key, pair->value->data, 
				pair->value->data, given_array);
			
			goto out;
		}
	}
	break;
	case HF_OPTION_TYPE_PERCENT:
	{
		uint32_t percent = 0;

		
		/* Check if the value is valid percentage */
		if (hf_string2percent (pair->value->data, 
				       &percent) != 0) {
			hf_log (xl->name, HF_LOG_ERROR,
				"invalid percent format \"%s\" "
				"in \"option %s\"",
				pair->value->data, pair->key);
			goto out;
		}

		if ((percent < 0) || (percent > 100)) {
			hf_log (xl->name, HF_LOG_ERROR,
				"'%d' in 'option %s %s' is out of "
				"range [0 - 100]",
				percent, pair->key, 
				pair->value->data);
		}
		ret = 0;
	}
	break;
	case HF_OPTION_TYPE_TIME:
	{
		uint32_t input_time = 0;

		/* Check if the value is valid percentage */
		if (hf_string2time (pair->value->data, 
				    &input_time) != 0) {
			hf_log (xl->name,
				HF_LOG_ERROR,
				"invalid time format \"%s\" in "
				"\"option %s\"",
				pair->value->data, pair->key);
			goto out;
		}

		if ((opt->min == 0) && (opt->max == 0)) {
			hf_log (xl->name, HF_LOG_DEBUG,
				"no range check required for "
				"'option %s %s'",
				pair->key, pair->value->data);
			ret = 0;
			goto out;
		}
		if ((input_time < opt->min) || 
		    (input_time > opt->max)) {
			hf_log (xl->name, HF_LOG_ERROR,
				"'%"PRIu32"' in 'option %s %s' is "
				"out of range [%"PRId64" - %"PRId64"]",
				input_time, pair->key, 
				pair->value->data,
				opt->min, opt->max);
		}
		ret = 0;
	}
	break;
	case HF_OPTION_TYPE_DOUBLE:
	{
		double input_time = 0.0;

		/* Check if the value is valid double */
		if (hf_string2double (pair->value->data, 
				      &input_time) != 0) {
			hf_log (xl->name,
				HF_LOG_ERROR,
				"invalid time format \"%s\" in \"option %s\"",
				pair->value->data, pair->key);
			goto out;
		}
		
		if (input_time < 0.0) {
			hf_log (xl->name,
				HF_LOG_ERROR,
				"invalid time format \"%s\" in \"option %s\"",
				pair->value->data, pair->key);
			goto out;
		}

		if ((opt->min == 0) && (opt->max == 0)) {
			hf_log (xl->name, HF_LOG_DEBUG,
				"no range check required for 'option %s %s'",
				pair->key, pair->value->data);
			ret = 0;
			goto out;
		}
		ret = 0;
	}
	break;
        case HF_OPTION_TYPE_INTERNET_ADDRESS:
        {
                if (valid_internet_address (pair->value->data)) {
                        ret = 0;
                }
	}
        break;
	case HF_OPTION_TYPE_ANY:
		/* NO CHECK */
		ret = 0;
		break;
	}
	
out:
	return ret;
}

int
validate_xlator_volume_options (xlator_t *xl, volume_option_t *opt)
{
	int i = 0;
	int ret = -1;
 	int index = 0;
 	volume_option_t *trav  = NULL;
 	data_pair_t     *pairs = NULL;

 	if (!opt) {
		ret = 0;
 		goto out;
	}

 	/* First search for not supported options, if any report error */
 	pairs = xl->options->members_list;
 	while (pairs) {
		ret = -1;
  		for (index = 0; 
		     opt[index].key && opt[index].key[0] ; index++) {
  			trav = &(opt[index]);
			for (i = 0 ; 
			     (i < ZR_VOLUME_MAX_NUM_KEY) && 
				     trav->key[i]; i++) {
				/* Check if the key is valid */
				if (fnmatch (trav->key[i], 
					     pairs->key, FNM_NOESCAPE) == 0) {
					ret = 0;
					break;
				}
			}
			if (!ret) {
				if (i) {
					hf_log (xl->name, HF_LOG_WARNING,
						"option '%s' is deprecated, "
						"preferred is '%s', continuing"
						" with correction",
						trav->key[i], trav->key[0]);
					/* TODO: some bytes lost */
					pairs->key = strdup (trav->key[0]);
				}
				break;
			}
  		}
  		if (!ret) {
			ret = _volume_option_value_validate (xl, pairs, trav);
			if (-1 == ret) {
				goto out;
			}
		}

  		pairs = pairs->next;
  	}
	
	ret = 0;
 out:
  	return ret;
}

int32_t
xlator_set_type (xlator_t *xl,
		 const char *type)
{
	char *name = NULL;
	void *handle = NULL;
	volume_opt_list_t *vol_opt = NULL;

	if (xl == NULL || type == NULL)	{
		hf_log ("xlator", HF_LOG_DEBUG, "invalid argument");
		return -1;
	}

	xl->type = strdup (type);

	asprintf (&name, "%s/%s.so", XLATORDIR, type);

	hf_log ("xlator", HF_LOG_TRACE, "attempt to load file %s", name);

	handle = dlopen (name, RTLD_NOW|RTLD_GLOBAL);
	if (!handle) {
		hf_log ("xlator", HF_LOG_DEBUG, "%s", dlerror ());
		return -1;
	}

	if (!(xl->fops = dlsym (handle, "fops"))) {
		hf_log ("xlator", HF_LOG_DEBUG, "dlsym(fops) on %s",
			dlerror ());
		return -1;
	}

	if (!(xl->mops = dlsym (handle, "mops"))) {
		hf_log ("xlator", HF_LOG_DEBUG, "dlsym(mops) on %s",
			dlerror ());
		return -1;
	}

	if (!(xl->cbks = dlsym (handle, "cbks"))) {
		hf_log ("xlator", HF_LOG_DEBUG, "dlsym(cbks) on %s",
			dlerror ());
		return -1;
	}

	if (!(xl->init = dlsym (handle, "init"))) {
		hf_log ("xlator", HF_LOG_DEBUG, "dlsym(init) on %s",
			dlerror ());
		return -1;
	}

	if (!(xl->fini = dlsym (handle, "fini"))) {
		hf_log ("xlator", HF_LOG_DEBUG, "dlsym(fini) on %s",
			dlerror ());
		return -1;
	}

	if (!(xl->notify = dlsym (handle, "notify"))) {
		hf_log ("xlator", HF_LOG_DEBUG,
			"dlsym(notify) on %s -- neglecting", dlerror ());
	}

	INIT_LIST_HEAD (&xl->volume_options);

	vol_opt = CALLOC (1, sizeof (volume_opt_list_t));

	if (!(vol_opt->given_opt = dlsym (handle, "options"))) {
		dlerror ();
		hf_log (xl->name, HF_LOG_DEBUG,
			"Strict option validation not enforced -- neglecting");
	}
	list_add_tail (&vol_opt->list, &xl->volume_options);

	fill_defaults (xl);

	FREE (name);
	return 0;
}


void
xlator_foreach (xlator_t *this,
		void (*fn)(xlator_t *each,
			   void *data),
		void *data)
{
	xlator_t *first = NULL;

	if (this == NULL || fn == NULL || data == NULL)	{
		hf_log ("xlator", HF_LOG_DEBUG, "invalid argument");
		return;
	}

	first = this;

	while (first->prev)
		first = first->prev;

	while (first) {
		fn (first, data);
		first = first->next;
	}
}


xlator_t *
xlator_search_by_name (xlator_t *any, const char *name)
{
	xlator_t *search = NULL;

	if (any == NULL || name == NULL) {
		hf_log ("xlator", HF_LOG_DEBUG, "invalid argument");
		return NULL;
	}

	search = any;

	while (search->prev)
		search = search->prev;

	while (search) {
		if (!strcmp (search->name, name))
			break;
		search = search->next;
	}

	return search;
}


static int32_t
xlator_init_rec (xlator_t *xl)
{
	xlator_list_t *trav = NULL;
	int32_t ret = 0;

	if (xl == NULL)	{
		hf_log ("xlator", HF_LOG_DEBUG, "invalid argument");
		return 0;
	}

	trav = xl->children;

	while (trav) {
		ret = 0;
		ret = xlator_init_rec (trav->xlator);
		if (ret != 0)
			break;
		hf_log (trav->xlator->name, HF_LOG_TRACE,
			"Initialization done");
		trav = trav->next;
	}

	if (!ret && !xl->ready) {
		ret = -1;
		if (xl->init) {
			ret = xl->init (xl);
			if (ret) {
				hf_log ("xlator", HF_LOG_ERROR,
					"Initialization of volume '%s' failed,"
					" review your volfile again",
					xl->name);
			} else {
				xl->init_succeeded = 1;
			}
		} else {
			hf_log (xl->name, HF_LOG_DEBUG, "No init() found");
		}
		/* This 'xl' is checked */
		xl->ready = 1;
	}

	return ret;
}


int32_t
xlator_tree_init (xlator_t *xl)
{
	xlator_t *top = NULL;
	int32_t ret = 0;

	if (xl == NULL)	{
		hf_log ("xlator", HF_LOG_DEBUG, "invalid argument");
		return 0;
	}

	top = xl;
/*
	while (top->parents)
		top = top->parents->xlator;
*/
	ret = xlator_init_rec (top);

	if (ret == 0 && top->notify) {
		top->notify (top, HF_EVENT_PARENT_UP, NULL);
	}

	return ret;
}


static void
xlator_fini_rec (xlator_t *xl)
{
	xlator_list_t *trav = NULL;

	if (xl == NULL)	{
		hf_log ("xlator", HF_LOG_DEBUG, "invalid argument");
		return;
	}

	trav = xl->children;

	while (trav) {
		if (!trav->xlator->init_succeeded) {
			break;
		}

		xlator_fini_rec (trav->xlator);
		hf_log (trav->xlator->name, HF_LOG_DEBUG, "fini done");
		trav = trav->next;
	}

	if (xl->init_succeeded) {
		if (xl->fini) {
			xl->fini (xl);
		} else {
			hf_log (xl->name, HF_LOG_DEBUG, "No fini() found");
		}
		xl->init_succeeded = 0;
	}
}


void
xlator_tree_fini (xlator_t *xl)
{
	xlator_t *top = NULL;

	if (xl == NULL)	{
		hf_log ("xlator", HF_LOG_DEBUG, "invalid argument");
		return;
	}

	top = xl;
	xlator_fini_rec (top);
}


int
xlator_tree_free (xlator_t *tree)
{
     xlator_t *trav = tree, *prev = tree;

    if (!tree) {
      hf_log ("parser", HF_LOG_ERROR, "Translator tree not found");
      return -1;
    }

    while (prev) {
       trav = prev->next;
       dict_destroy (prev->options);
       FREE (prev->name);
       FREE (prev->type);
       FREE (prev);
      prev = trav;
    }
  
    return 0;
}


void
loc_wipe (loc_t *loc)
{
        if (loc->object) {
                object_unref (loc->object);
                loc->object = NULL;
        }
        if (loc->path) {
                FREE (loc->path);
                loc->path = NULL;
        }
}


int
loc_copy (loc_t *dst, loc_t *src)
{
	int ret = -1;

	if (src->object)
		dst->object = object_ref (src->object);

	dst->path = strdup (src->path);
	if (!dst->path)
		goto out;

    strncpy(dst->sid, src->sid, SHORT_NAME);
	dst->soffset = src->soffset;
	ret = 0;
out:
	return ret;
}

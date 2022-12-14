/*
  Copyright (c) 2008-2009 JiangNan, Inc. <http://www.sunway.com>
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


#include "rbthash.h"
#include "rb.h"
#include "locking.h"
#include "mem-pool.h"
#include "logging.h"

#include <pthread.h>
#include <string.h>


int
rbthash_comparator (void *entry1, void *entry2, void *param)
{
        int             ret = 0;
        rbthash_entry_t *e1 = NULL;
        rbthash_entry_t *e2 = NULL;

        if ((!entry1) || (!entry2) || (!param))
                return -1;

        e1 = (rbthash_entry_t *)entry1;
        e2 = (rbthash_entry_t *)entry2;

        if (e1->keylen != e2->keylen) {
                if (e1->keylen < e2->keylen)
                        ret = -1;
                else if (e1->keylen > e2->keylen)
                        ret = 1;
        } else
                ret = memcmp (e1->key, e2->key, e1->keylen);

        return ret;
}


int
__rbthash_init_buckets (rbthash_table_t *tbl, int buckets)
{
        int     i = 0;
        int     ret = -1;

        if (!tbl)
                return -1;

        for (; i < buckets; i++) {
                LOCK_INIT (&tbl->buckets[i].bucketlock);
                tbl->buckets[i].bucket = rb_create ((rb_comparison_func *)rbthash_comparator, tbl, NULL);
                if (!tbl->buckets[i].bucket) {
                        hf_log (HF_RBTHASH, HF_LOG_ERROR, "Failed to create rb"
                                " table bucket");
                        ret = -1;
                        goto err;
                }
        }

        ret = 0;
err:
        return ret;
}


rbthash_table_t *
rbthash_table_init (int buckets, rbt_hasher_t hfunc, rbt_data_destroyer_t dfunc)
{
        rbthash_table_t         *newtab = NULL;
        int                     ret = -1;

        if (!hfunc) {
                hf_log (HF_RBTHASH, HF_LOG_ERROR, "Hash function not given");
                return NULL;
        }

        newtab = CALLOC (1, sizeof (*newtab));
        if (!newtab)
                return NULL;

        newtab->buckets = CALLOC (buckets, sizeof (struct rbthash_bucket));
        if (!newtab->buckets) {
                hf_log (HF_RBTHASH, HF_LOG_ERROR, "Failed to allocate memory");
                goto free_newtab;
        }

        newtab->entrypool =  mem_pool_new (rbthash_entry_t, HF_RBTHASH_MEMPOOL);
        if (!newtab->entrypool) {
                hf_log (HF_RBTHASH, HF_LOG_ERROR,"Failed to allocate mem-pool");
                goto free_buckets;
        }

        LOCK_INIT (&newtab->tablelock);
        newtab->numbuckets = buckets;
        ret = __rbthash_init_buckets (newtab, buckets);

        if (ret == -1) {
                hf_log (HF_RBTHASH, HF_LOG_ERROR, "Failed to init buckets");
                mem_pool_destroy (newtab->entrypool);
        } else
                hf_log (HF_RBTHASH, HF_LOG_TRACE, "Inited hash table: buckets:"
                        " %d", buckets);

        newtab->hashfunc = hfunc;
        newtab->dfunc = dfunc;
free_buckets:
        if (ret == -1)
                FREE (newtab->buckets);

free_newtab:
        if (ret == -1) {
                FREE (newtab);
                newtab = NULL;
        }

        return newtab;
}


rbthash_entry_t *
rbthash_init_entry (rbthash_table_t *tbl, void *data, void *key, int keylen)
{
        int             ret = -1;
        rbthash_entry_t *entry = NULL;

        if ((!tbl) || (!data) || (!key))
                return NULL;

        entry = mem_get (tbl->entrypool);
        if (!entry) {
                hf_log (HF_RBTHASH, HF_LOG_ERROR, "Failed to get entry from"
                        " mem-pool");
                goto ret;
        }

        entry->data = data;
        entry->key = CALLOC (keylen, sizeof (char));
        if (!entry->key) {
                hf_log (HF_RBTHASH, HF_LOG_ERROR, "Memory allocation failed");
                goto free_entry;
        }

        memcpy (entry->key, key, keylen);
        entry->keylen = keylen;
        entry->keyhash = tbl->hashfunc (entry->key, entry->keylen);
        hf_log (HF_RBTHASH, HF_LOG_TRACE, "HASH: %u", entry->keyhash);

        ret = 0;
free_entry:
        if (ret == -1) {
                mem_put (tbl->entrypool, entry);
                entry = NULL;
        }

ret:
        return entry;
}


void
rbthash_deinit_entry (rbthash_table_t *tbl, rbthash_entry_t *entry)
{

        if (!entry)
                return;

        if (entry->key)
                FREE (entry->key);
        if (tbl) {
                if ((entry->data) && (tbl->dfunc))
                        tbl->dfunc (entry->data);
                mem_put (tbl->entrypool, entry);
        }

        return;
}


inline struct rbthash_bucket *
rbthash_entry_bucket (rbthash_table_t *tbl, rbthash_entry_t * entry)
{
        int     nbucket = 0;

        nbucket = (entry->keyhash % tbl->numbuckets);
        hf_log (HF_RBTHASH, HF_LOG_TRACE, "BUCKET: %d", nbucket);
        return &tbl->buckets[nbucket];
}


int
rbthash_insert_entry (rbthash_table_t *tbl, rbthash_entry_t *entry)
{
        struct rbthash_bucket   *bucket = NULL;
        int                     ret = -1;

        if ((!tbl) || (!entry))
                return -1;

        bucket = rbthash_entry_bucket (tbl, entry);
        if (!bucket) {
                hf_log (HF_RBTHASH, HF_LOG_ERROR, "Failed to get bucket");
                goto err;
        }

        ret = 0;
        LOCK (&bucket->bucketlock);
        {
                if (!rb_probe (bucket->bucket, (void *)entry)) {
                        hf_log (HF_RBTHASH, HF_LOG_ERROR, "Failed to insert"
                                " entry");
                        ret = -1;
                }
        }
        UNLOCK (&bucket->bucketlock);

err:
        return ret;
}


int
rbthash_insert (rbthash_table_t *tbl, void *data, void *key, int keylen)
{
        rbthash_entry_t         *entry = NULL;
        int                     ret = -1;

        if ((!tbl) || (!data) || (!key))
                return -1;

        entry = rbthash_init_entry (tbl, data, key, keylen);
        if (!entry) {
                hf_log (HF_RBTHASH, HF_LOG_ERROR, "Failed to init entry");
                goto err;
        }

        ret = rbthash_insert_entry (tbl, entry);

        if (ret == -1) {
                hf_log (HF_RBTHASH, HF_LOG_ERROR, "Failed to insert entry");
                rbthash_deinit_entry (tbl, entry);
        }

err:
        return ret;
}

inline struct rbthash_bucket *
rbthash_key_bucket (rbthash_table_t *tbl, void *key, int keylen)
{
        uint32_t        keyhash = 0;
        int             nbucket = 0;

        if ((!tbl) || (!key))
                return NULL;

        keyhash =  tbl->hashfunc (key, keylen);
        hf_log (HF_RBTHASH, HF_LOG_TRACE, "HASH: %u", keyhash);
        nbucket = (keyhash % tbl->numbuckets);
        hf_log (HF_RBTHASH, HF_LOG_TRACE, "BUCKET: %u", nbucket);

        return &tbl->buckets[nbucket];
}


void *
rbthash_get (rbthash_table_t *tbl, void *key, int keylen)
{
        struct rbthash_bucket           *bucket = NULL;
        rbthash_entry_t                 *entry = NULL;
        rbthash_entry_t                 searchentry = {0, };

        if ((!tbl) || (!key))
                return NULL;

        bucket = rbthash_key_bucket (tbl, key, keylen);
        if (!bucket) {
                hf_log (HF_RBTHASH, HF_LOG_ERROR, "Failed to get bucket");
                return NULL;
        }

        searchentry.key = key;
        searchentry.keylen = keylen;
        LOCK (&bucket->bucketlock);
        {
                entry = rb_find (bucket->bucket, &searchentry);
        }
        UNLOCK (&bucket->bucketlock);

        if (!entry)
                return NULL;

        return entry->data;
}


void *
rbthash_remove (rbthash_table_t *tbl, void *key, int keylen)
{
        struct rbthash_bucket   *bucket = NULL;
        rbthash_entry_t         *entry = NULL;
        rbthash_entry_t         searchentry = {0, };
        void                    *dataref = NULL;

        if ((!tbl) || (!key))
                return NULL;

        bucket = rbthash_key_bucket (tbl, key, keylen);
        if (!bucket) {
                hf_log (HF_RBTHASH, HF_LOG_ERROR, "Failed to get bucket");
                return NULL;
        }

        searchentry.key = key;
        searchentry.keylen = keylen;

        LOCK (&bucket->bucketlock);
        {
                entry = rb_delete (bucket->bucket, &searchentry);
        }
        UNLOCK (&bucket->bucketlock);

        if (!entry)
                return NULL;

        FREE (entry->key);
        dataref = entry->data;
        mem_put (tbl->entrypool, entry);

        return dataref;
}


void
rbthash_entry_deiniter (void *entry, void *rbparam)
{
        if (!entry)
                return;

        rbthash_deinit_entry (rbparam, entry);
}


void
rbthash_table_destroy_buckets (rbthash_table_t *tbl)
{
        int x = 0;
        if (!tbl)
                return;

        for (;x < tbl->numbuckets; x++) {
                LOCK_DESTROY (&tbl->buckets[x].bucketlock);
                rb_destroy (tbl->buckets[x].bucket, rbthash_entry_deiniter);
        }

        return;
}


void
rbthash_table_destroy (rbthash_table_t *tbl)
{
        if (!tbl)
                return;

        rbthash_table_destroy_buckets (tbl);
        mem_pool_destroy (tbl->entrypool);

        FREE (tbl->buckets);
        FREE (tbl);
}


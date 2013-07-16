// Copyright 2010-2012 RethinkDB, all rights reserved.
#ifndef BUFFER_CACHE_MIRRORED_PAGE_MAP_HPP_
#define BUFFER_CACHE_MIRRORED_PAGE_MAP_HPP_

#include "containers/two_level_array.hpp"
#include "config/args.hpp"
#include "buffer_cache/types.hpp"
#include "serializer/types.hpp"

class mc_inner_buf_t;

class array_map_t {
    typedef mc_inner_buf_t inner_buf_t;

public:
    array_map_t() : count(0) { }

    ~array_map_t() {
        rassert(count == 0);
    }

    static void constructing_inner_buf(inner_buf_t *gbuf);
    static void destroying_inner_buf(inner_buf_t *gbuf);

    inner_buf_t *find(block_id_t block_id) {
        return block_id < array.size() ? array[block_id] : NULL;
    }

    unsigned int size() {
        // RSI: Is this method used?
        return count;
    }

private:
    std::vector<inner_buf_t *> array;
    size_t count;

    DISABLE_COPYING(array_map_t);
};

#endif // BUFFER_CACHE_MIRRORED_PAGE_MAP_HPP_


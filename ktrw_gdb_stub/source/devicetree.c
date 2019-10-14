//
// Project: KTRW
// Author:  Brandon Azad <bazad@google.com>
//
// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include "devicetree.h"

#include <stdint.h>

#include "primitives.h"

// The format of a device tree node header.
struct _devicetree_node {
	uint32_t n_properties;
	uint32_t n_children;
};

// The format of a device tree property header.
struct _devicetree_property {
	char name[32];
	uint32_t size;
	uint8_t data[0];
};

// Parse a property and perform basic validation.
static const struct _devicetree_property *
parse_property(const uint8_t **p, const uint8_t *end) {
	// Parse the property header.
	const struct _devicetree_property *prop = (void *)*p;
	*p += sizeof(*prop);
	if (*p > end) {
		return NULL;
	}
	// Make sure the property name is null terminated.
	if (prop->name[sizeof(prop->name) - 1] != 0) {
		return NULL;
	}
	// Properties are padded to a multiple of 4 bytes.
	size_t padded_size = (prop->size + 0x3) & ~0x3;
	*p += padded_size;
	if (*p > end) {
		if (*p - padded_size + prop->size == end) {
			// If the very last property does not have the requisite
			// padding, that's okay.
			*p = end;
		} else {
			return NULL;
		}
	}
	return prop;
}

struct devicetree_node
devicetree_find_node_by_property(struct devicetree devicetree,
		const char *key, const char *value) {
	const uint8_t *p = (const uint8_t *)devicetree.data;
	const uint8_t *end = p + devicetree.size;
	// We will do a "flat" scan of the devicetree, ignoring the hierarchy.
	size_t remaining_nodes = 1;
	for (;;) {
		// If we run out of data or believe there should be no more nodes left in the tree,
		// then we're done.
		if (p >= end || remaining_nodes == 0) {
			goto done;
		}
		// Parse the node header.
		const struct _devicetree_node *node = (void *)p;
		p += sizeof(*node);
		if (p > end) {
			goto done;
		}
		// We will linearly scan this node's children in subsequent loops.
		remaining_nodes += node->n_children;
		// Scan this node's properties, searching for a match.
		uint32_t n_properties = node->n_properties;
		for (uint32_t i = 0; i < n_properties; i++) {
			// Parse the property.
			const struct _devicetree_property *prop = parse_property(&p, end);
			if (prop == NULL) {
				goto done;
			}
			// Check if we have a property match. Both the property name and the
			// property value must match.
			int key_cmp = strcmp(prop->name, key);
			if (key_cmp == 0) {
				int value_cmp = strncmp((char *)prop->data, value, prop->size);
				if (value_cmp == 0) {
					return (struct devicetree_node) { node, end };
				}
			}
		}
		// Done with this node.
		remaining_nodes -= 1;
	}
done:
	return (struct devicetree_node) { NULL, NULL };
}

struct devicetree_property
devicetree_node_get_property(struct devicetree_node node0, const char *key) {
	const uint8_t *p = (void *)node0.data;
	const uint8_t *end = (void *)node0.end;
	// Parse the node header.
	const struct _devicetree_node *node = (void *)p;
	p += sizeof(*node);
	if (p > end) {
		goto done;
	}
	// Scan this node's properties, searching for a match.
	uint32_t n_properties = node->n_properties;
	for (uint32_t i = 0; i < n_properties; i++) {
		// Parse the property.
		const struct _devicetree_property *prop = parse_property(&p, end);
		if (prop == NULL) {
			goto done;
		}
		// Check if we have a property match.
		int key_cmp = strcmp(prop->name, key);
		if (key_cmp == 0) {
			return (struct devicetree_property) { prop->data, prop->size };
		}
	}
done:
	return (struct devicetree_property) { NULL, 0 };
}

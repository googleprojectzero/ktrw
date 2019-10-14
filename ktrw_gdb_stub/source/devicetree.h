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

#ifndef DEVICETREE__H_
#define DEVICETREE__H_

#include <stdbool.h>
#include <stddef.h>

// A flattened device tree.
struct devicetree {
	const void *data;
	size_t size;
};

// A device tree node header. Treat this type as opaque.
struct devicetree_node {
	const void *data;
	const void *end;
};

// A device tree property's data.
struct devicetree_property {
	const void *data;
	size_t size;
};

/*
 * devicetree_find_node_by_property
 *
 * Description:
 * 	Find a device tree node with a property with the specified property name and string value.
 */
struct devicetree_node devicetree_find_node_by_property(struct devicetree devicetree,
		const char *key, const char *value);

/*
 * devicetree_node_valid
 *
 * Description:
 * 	Checks whether a returned devicetree_node represents a valid node.
 */
static inline bool
devicetree_node_valid(struct devicetree_node node) {
	return node.data != NULL;
}

/*
 * devicetree_node_get_property
 *
 * Description:
 * 	Get the value of the specified property of a device tree node.
 */
struct devicetree_property devicetree_node_get_property(struct devicetree_node node,
		const char *key);

#endif

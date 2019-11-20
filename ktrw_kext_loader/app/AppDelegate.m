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

#import "AppDelegate.h"

#import "bundle_path.h"
#import "kernel_call.h"
#import "kernel_memory.h"
#import "kernel_patches.h"
#import "kext_load.h"
#import "ktrr_bypass.h"
#import "log.h"


@interface AppDelegate ()

@end

@implementation AppDelegate


- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
	// Get the bundle path.
	char bundle_path[1024];
	get_bundle_path(bundle_path, sizeof(bundle_path));
	// Load the kernel symbol database.
	char kernel_symbol_database[1024];
	snprintf(kernel_symbol_database, sizeof(kernel_symbol_database), "%s/%s", bundle_path,
			"kernel_symbols");
	bool ok = kext_load_set_kernel_symbol_database(kernel_symbol_database);
	if (!ok) {
		ERROR("Could not load kernel symbol database");
		goto done_0;
	}
	// Try to get the kernel task port using task_for_pid(). If this works, then KTRR has
	// already been bypassed and the kext has already been loaded.
	kernel_task_port = MACH_PORT_NULL;
	task_for_pid(mach_task_self(), 0, &kernel_task_port);
	if (kernel_task_port != MACH_PORT_NULL) {
		INFO("task_for_pid(0) = 0x%x", kernel_task_port);
		INFO("KTRR already bypassed");
		goto done_0;
	}
	// Try to get the kernel task port using host_get_special_port(4). If this works, then an
	// exploit has already run but we still need to bypass KTRR.
	if (kernel_task_port == MACH_PORT_NULL) {
		mach_port_t host = mach_host_self();
		host_get_special_port(host, 0, 4, &kernel_task_port);
		mach_port_deallocate(mach_task_self(), host);
		if (kernel_task_port != MACH_PORT_NULL) {
			INFO("host_get_special_port(4) = 0x%x", kernel_task_port);
		}
	}
	// If we still don't have a kernel task port, then abort.
	if (kernel_task_port == MACH_PORT_NULL) {
		ERROR("Could not get kernel task port");
		goto done_0;
	}
	// Initialize our kernel function calling capability.
	ok = kernel_call_init();
	if (!ok) {
		ERROR("Could not initialize kernel_call subsystem");
		goto done_0;
	}
	// Bypass KTRR and remap the kernel as read/write.
	ok = have_ktrr_bypass();
	if (!ok) {
		ERROR("No KTRR bypass is available for this platform");
		goto done_1;
	}
	ktrr_bypass();
	// Apply kernel patches.
	apply_kernel_patches();
	// Check that we can call task_for_pid(0).
	mach_port_t tfp0 = MACH_PORT_NULL;
	task_for_pid(mach_task_self(), 0, &tfp0);
	INFO("task_for_pid(0) = 0x%x", tfp0);
	// Load the kernel extension.
	const char *kext_name = "ktrw_gdb_stub.ikext";
	char kext_path[1024];
	snprintf(kext_path, sizeof(kext_path), "%s/kexts/%s", bundle_path, kext_name);
	uint64_t kext_address = kext_load(kext_path, 0);
	INFO("Kext %s loaded at address 0x%016llx", kext_name, kext_address);
done_1:
	// De-initialize our kernel function calling primitive.
	kernel_call_deinit();
done_0:
	usleep(100000);
	exit(1);
	return YES;
}


- (void)applicationWillResignActive:(UIApplication *)application {
	// Sent when the application is about to move from active to inactive state. This can occur for certain types of temporary interruptions (such as an incoming phone call or SMS message) or when the user quits the application and it begins the transition to the background state.
	// Use this method to pause ongoing tasks, disable timers, and invalidate graphics rendering callbacks. Games should use this method to pause the game.
}


- (void)applicationDidEnterBackground:(UIApplication *)application {
	// Use this method to release shared resources, save user data, invalidate timers, and store enough application state information to restore your application to its current state in case it is terminated later.
	// If your application supports background execution, this method is called instead of applicationWillTerminate: when the user quits.
}


- (void)applicationWillEnterForeground:(UIApplication *)application {
	// Called as part of the transition from the background to the active state; here you can undo many of the changes made on entering the background.
}


- (void)applicationDidBecomeActive:(UIApplication *)application {
	// Restart any tasks that were paused (or not yet started) while the application was inactive. If the application was previously in the background, optionally refresh the user interface.
}


- (void)applicationWillTerminate:(UIApplication *)application {
	// Called when the application is about to terminate. Save data if appropriate. See also applicationDidEnterBackground:.
}


@end

/**
 * @file injection_poolparty.hpp
 * @brief PoolParty Process Injection Technique Header
 * 
 * Implementation based on SafeBreach-Labs PoolParty research:
 * https://github.com/SafeBreach-Labs/PoolParty
 * 
 * Credits:
 *   - SafeBreach Labs (https://safebreach.com/)
 *   - Alon Leviev (@_0xDeku)
 *   - Original research: "PoolParty - A New Set of Windows Thread Pool Injection Techniques"
 *   - Presented at Black Hat Europe 2023
 * 
 * This implementation uses the RemoteTpDirectInsertion variant.
 */

#ifndef EREBUS_INJECTION_POOLPARTY_HPP
#define EREBUS_INJECTION_POOLPARTY_HPP
#pragma once
#include <windows.h>
#include "../config.hpp"

namespace erebus {
#if CONFIG_INJECTION_TYPE == 5

	/**
	 * @brief Check if a process has an active thread pool (IoCompletion handle)
	 * Used to validate target before injection
	 * @param hProcess Handle to target process
	 * @return TRUE if thread pool exists, FALSE otherwise
	 */
	BOOL ProcessHasThreadPool(IN HANDLE hProcess);

	/**
	 * @brief PoolParty injection using RemoteTpDirectInsertion variant
	 * 
	 * This technique hijacks the target's IoCompletion port and queues
	 * a TP_DIRECT work item that points to shellcode. The thread pool
	 * worker dequeues and executes the callback.
	 * 
	 * @param shellcode Shellcode buffer to inject
	 * @param shellcode_size Size of shellcode in bytes
	 * @param process_handle Handle to target process (PROCESS_ALL_ACCESS)
	 * @param thread_handle Handle to target thread (may be NULL for this variant)
	 */
	VOID InjectionPoolParty(
		IN BYTE* shellcode, 
		IN SIZE_T shellcode_size, 
		IN HANDLE process_handle, 
		IN HANDLE thread_handle
	);

#endif
}

#endif

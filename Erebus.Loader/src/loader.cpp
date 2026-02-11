#include "../include/loader.hpp"
#include "../include/config.hpp"

// NOTE: shellcode.hpp is NOT included here to prevent linker errors.
// All helper functions are in src/helpers/
// All injection methods are in src/injection/

namespace erebus {
	// Global configuration structure
	Config config{};
} // namespace erebus

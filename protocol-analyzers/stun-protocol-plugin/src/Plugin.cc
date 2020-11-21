#include "plugin/Plugin.h"
#include "STUN_UDP.h"
#include "STUN_UDP_MAGIC.h"

namespace zeek::plugin::detail::Zeek_STUN {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component("STUN_UDP", zeek::analyzer::STUN_UDP::STUN_Analyzer::InstantiateAnalyzer));
		AddComponent(new zeek::analyzer::Component("STUN_UDP_MAGIC", zeek::analyzer::STUN_UDP_MAGIC::STUN_Analyzer::InstantiateAnalyzer));

		plugin::Configuration config;
		config.name = "Zeek::STUN";
		config.description = "STUN protocol analyzer";
		config.version.major = 1;
		config.version.minor = 1;
		return config;
		}
} plugin;

}

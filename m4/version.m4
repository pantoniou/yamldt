m4_define([GIT_VERSION_NUMBER], m4_esyscmd_s([git describe --dirty --always 2>/dev/null]))dnl
m4_define([DIST_VERSION_NUMBER], m4_esyscmd_s([cat DIST-VERSION 2>/dev/null]))dnl
m4_define([FAILOVER_VERSION_NUMBER], [0.0.1])dnl

dnl Bah! m4 is a torture
m4_if(m4_len(GIT_VERSION_NUMBER),[0],
		[m4_if(m4_len(DIST_VERSION_NUMBER),[0],
			[m4_copy([FAILOVER_VERSION_NUMBER],[VERSION_NUMBER])],
			[m4_copy([DIST_VERSION_NUMBER],[VERSION_NUMBER])])],
		[m4_copy([GIT_VERSION_NUMBER],[VERSION_NUMBER])])dnl

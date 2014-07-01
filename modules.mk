mod_hmacauth.la: mod_hmacauth.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_hmacauth.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_hmacauth.la

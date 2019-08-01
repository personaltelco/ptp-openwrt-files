for f in $(find /overlay -type f | sed 's|/overlay/||') ; do diff -uN /rom/$f /$f ; done

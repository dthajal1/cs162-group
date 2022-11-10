# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_USER_FAULTS => 1, [<<'EOF']);
(lock-dbl-sema) begin
(lock-dbl-sema) PASS
(lock-dbl-sema) end
lock-dbl-sema: exit(0)
EOF
pass;

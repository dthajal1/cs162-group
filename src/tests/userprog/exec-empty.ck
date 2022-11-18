# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF', <<'EOF']);
(exec-empty) begin
(exec-empty) exec(""): -1
(exec-empty) end
exec-empty: exit(0)
EOF
(exec-empty) begin
(exec-empty) exec(""): -1
exec-empty: exit(-1)
EOF
pass;

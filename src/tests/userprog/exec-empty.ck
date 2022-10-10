# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF', <<'EOF']);
(exec-empty) begin
(exec-empty) end
exec-empty: exit(0)
EOF
(exec-empty) begin
exec-empty: exit(-1)
EOF
pass;

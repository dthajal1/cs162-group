# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF', <<'EOF']);
(read-null-ptr) begin
(read-null-ptr) open "sample.txt"
(read-null-ptr) end
read-null-ptr: exit(0)
EOF
(read-null-ptr) begin
(read-null-ptr) open "sample.txt"
read-null-ptr: exit(-1)
EOF
pass;

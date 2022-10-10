# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(fp-custom) begin
(fp-custom) Success!
fp-custom: exit(162)
EOF
pass;
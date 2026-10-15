// Negative fixture: other packages, near names and unquoted prose are not @hpke/common imports.
// The library is @hpke/common 1.10.1, admitted only as @hpke/core's own dependency.
export const commons = "@hpke/commons";
export const core = "@teecustody/core";
export const mixed = "@hpke/common'";
export const prefixed = "x@hpke/common";

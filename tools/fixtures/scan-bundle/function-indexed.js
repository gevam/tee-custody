export const make = (f, body) => f["constructor"](body);
export const run = (s) => globalThis["eval"](s);

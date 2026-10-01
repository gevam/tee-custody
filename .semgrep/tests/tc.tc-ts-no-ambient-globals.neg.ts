// Negative fixture: brand symbols and class field modifiers are not ambient globals.
declare const brand: unique symbol;
declare const verified: unique symbol;

export type Branded = string & { readonly [brand]: true };
export type Verified = string & { readonly [verified]: true };

export class Holder {
    declare readonly value: number;
}

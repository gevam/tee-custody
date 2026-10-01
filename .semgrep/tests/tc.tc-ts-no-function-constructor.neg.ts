// Negative fixture: class constructors, construct signatures and the word in comments.
export class Thing {
    constructor(readonly value: number) {}
}

export interface ThingFactory {
    new (value: number): Thing;
}

export abstract class Base {
    protected constructor() {}
}

// A comment may mention the constructor of a class.
export const make = (value: number): Thing => new Thing(value);
export const label = "evaluation";

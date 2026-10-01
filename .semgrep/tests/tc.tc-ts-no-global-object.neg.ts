// Negative fixture: members and keys that merely share a global's name.
export class Session {
    readonly window = 30;
    readonly global = false;

    selfTest(): number {
        return this.window;
    }
}

export const options = { self: true, window: 5 };

export function reflectValue(value: number): number {
    return value + options.window;
}

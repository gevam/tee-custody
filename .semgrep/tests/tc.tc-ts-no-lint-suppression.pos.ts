// Positive fixture: comments that switch off ESLint or tsc checks in Core (NFR-6, SR-3).
// ruleid: tc-ts-no-lint-suppression
/* eslint-disable */
// ruleid: tc-ts-no-lint-suppression
// eslint-disable-next-line no-restricted-globals
export const a = 1;
// ruleid: tc-ts-no-lint-suppression
// @ts-ignore
export const b: number = "x";
// ruleid: tc-ts-no-lint-suppression
// @ts-nocheck
// ruleid: tc-ts-no-lint-suppression
/* eslint no-restricted-globals: "off" */
// ruleid: tc-ts-no-lint-suppression
/* global fetch */
// ruleid: tc-ts-no-lint-suppression
/* globals fetch */

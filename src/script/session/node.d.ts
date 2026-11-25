declare module "node:fs" {
    type Utf8 = "utf8" | "utf-8";
    export interface Stats {
        readonly size: number;
        isFile(): boolean;
        isDirectory(): boolean;
    }
    export function readFileSync(path: string, options: Utf8 | {encoding: Utf8}): string;
    export function readFileSync(path: string, options?: null | {encoding?: null}): Uint8Array;
    export function readdirSync(path: string): string[];
    export function statSync(path: string): Stats;
    export function accessSync(path: string, mode?: number): void;
    export function existsSync(path: string): boolean;
    export function realpathSync(path: string): string;
    export const constants: Readonly<{F_OK: 0; R_OK: 4; W_OK: 2; X_OK: 1}>;
    const fs: {
        readFileSync: typeof readFileSync; readdirSync: typeof readdirSync;
        statSync: typeof statSync; accessSync: typeof accessSync;
        existsSync: typeof existsSync; realpathSync: typeof realpathSync;
        constants: typeof constants;
    };
    export default fs;
}

declare module "node:fs/promises" {
    type Utf8 = "utf8" | "utf-8";
    export function readFile(path: string, options: Utf8 | {encoding: Utf8}): Promise<string>;
    export function readFile(path: string, options?: null | {encoding?: null}): Promise<Uint8Array>;
    export function readdir(path: string): Promise<string[]>;
    export function stat(path: string): Promise<import("node:fs").Stats>;
    export function access(path: string, mode?: number): Promise<void>;
    export function realpath(path: string): Promise<string>;
    const fs: {
        readFile: typeof readFile; readdir: typeof readdir; stat: typeof stat;
        access: typeof access; realpath: typeof realpath;
    };
    export default fs;
}

declare module "node:path" {
    export interface ParsedPath {
        root: string;
        dir: string;
        base: string;
        ext: string;
        name: string;
    }
    export const sep: "/";
    export function join(...parts: string[]): string;
    export function resolve(...parts: string[]): string;
    export function normalize(path: string): string;
    export function relative(from: string, to: string): string;
    export function isAbsolute(path: string): boolean;
    export function dirname(path: string): string;
    export function basename(path: string, suffix?: string): string;
    export function extname(path: string): string;
    export function parse(path: string): ParsedPath;
    export function format(path: Partial<ParsedPath>): string;
    const path: {
        sep: typeof sep; join: typeof join; resolve: typeof resolve;
        normalize: typeof normalize; relative: typeof relative; isAbsolute: typeof isAbsolute;
        dirname: typeof dirname; basename: typeof basename; extname: typeof extname;
        parse: typeof parse; format: typeof format;
    };
    export default path;
}

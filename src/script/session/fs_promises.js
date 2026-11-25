import { asyncOperation } from "aidbg:files";

export async function readFile(path, options) {
    const encoding = typeof options === "string" ? options : options?.encoding;
    if (encoding != null && encoding !== "utf8" && encoding !== "utf-8") {
        throw new TypeError("expected UTF-8 encoding");
    }
    return asyncOperation("read", path, encoding == null ? 0 : 1);
}
export async function readdir(path) { return asyncOperation("readdir", path); }
export async function access(path, mode = 0) { return asyncOperation("access", path, mode); }
export async function realpath(path) { return asyncOperation("realpath", path); }
export async function stat(path) {
    const {size, file, directory} = await asyncOperation("stat", path);
    return {size, isFile:() => file, isDirectory:() => directory};
}

export default {readFile, readdir, stat, access, realpath};

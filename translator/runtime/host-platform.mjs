const isNodeHost = typeof process !== "undefined" && Boolean(process.versions?.node);

function normalizePath(input) {
  const text = String(input || "/").replaceAll("\\", "/");
  const absolute = text.startsWith("/");
  const parts = [];
  for (const part of text.split("/")) {
    if (!part || part === ".") continue;
    if (part === "..") parts.pop();
    else parts.push(part);
  }
  return `${absolute ? "/" : ""}${parts.join("/")}` || (absolute ? "/" : ".");
}

function createMemoryPath() {
  return {
    sep: "/",
    resolve(...segments) {
      let result = "/";
      for (const segment of segments) {
        const text = String(segment ?? "").replaceAll("\\", "/");
        result = text.startsWith("/") ? text : `${result}/${text}`;
      }
      return normalizePath(result);
    },
    join(...segments) {
      return normalizePath(segments.join("/"));
    },
    dirname(value) {
      const normalized = normalizePath(value);
      const index = normalized.lastIndexOf("/");
      return index <= 0 ? "/" : normalized.slice(0, index);
    },
  };
}

function createStats(size, directory = false) {
  return {
    size,
    isDirectory: () => directory,
    isFile: () => !directory,
  };
}

function createMemoryFs(path) {
  const files = new Map();
  const directories = new Set(["/"]);
  const descriptors = new Map();
  let nextDescriptor = 3;

  const ensureParents = (value) => {
    let current = path.dirname(value);
    while (!directories.has(current)) {
      directories.add(current);
      if (current === "/") break;
      current = path.dirname(current);
    }
  };

  const requireFile = (value) => {
    const normalized = path.resolve(value);
    const bytes = files.get(normalized);
    if (!bytes) {
      const error = new Error(`ENOENT: ${normalized}`);
      error.code = "ENOENT";
      throw error;
    }
    return [normalized, bytes];
  };

  const api = {
    install(entries) {
      files.clear();
      directories.clear();
      directories.add("/");
      for (const [name, contents] of entries) {
        const normalized = path.resolve(name);
        const bytes = contents instanceof Uint8Array ? contents : new Uint8Array(contents);
        files.set(normalized, bytes);
        ensureParents(normalized);
      }
    },
    existsSync(value) {
      const normalized = path.resolve(value);
      return files.has(normalized) || directories.has(normalized);
    },
    readdirSync(value) {
      const directory = path.resolve(value);
      if (!directories.has(directory)) throw new Error(`ENOTDIR: ${directory}`);
      const prefix = directory === "/" ? "/" : `${directory}/`;
      const names = new Set();
      for (const candidate of [...directories, ...files.keys()]) {
        if (!candidate.startsWith(prefix) || candidate === directory) continue;
        const relative = candidate.slice(prefix.length);
        if (relative && !relative.includes("/")) names.add(relative);
      }
      return [...names];
    },
    mkdirSync(value, options = {}) {
      const normalized = path.resolve(value);
      if (options.recursive) ensureParents(`${normalized}/placeholder`);
      directories.add(normalized);
    },
    rmdirSync(value) {
      const normalized = path.resolve(value);
      const prefix = `${normalized}/`;
      if ([...files.keys(), ...directories].some((item) => item.startsWith(prefix))) {
        throw new Error(`ENOTEMPTY: ${normalized}`);
      }
      directories.delete(normalized);
    },
    renameSync(source, destination) {
      const [from, bytes] = requireFile(source);
      const to = path.resolve(destination);
      ensureParents(to);
      files.delete(from);
      files.set(to, bytes);
    },
    unlinkSync(value) {
      const normalized = path.resolve(value);
      if (!files.delete(normalized)) throw new Error(`ENOENT: ${normalized}`);
    },
    statSync(value) {
      const normalized = path.resolve(value);
      if (directories.has(normalized)) return createStats(0, true);
      const [, bytes] = requireFile(normalized);
      return createStats(bytes.byteLength);
    },
    openSync(value, mode = "r") {
      const normalized = path.resolve(value);
      const exists = files.has(normalized);
      if (mode.startsWith("wx") && exists) throw new Error(`EEXIST: ${normalized}`);
      if (mode.startsWith("r") && !exists) throw new Error(`ENOENT: ${normalized}`);
      if (mode.startsWith("w")) {
        ensureParents(normalized);
        files.set(normalized, new Uint8Array());
      }
      const descriptor = nextDescriptor++;
      descriptors.set(descriptor, normalized);
      return descriptor;
    },
    closeSync(descriptor) {
      descriptors.delete(descriptor);
    },
    fstatSync(descriptor) {
      return api.statSync(descriptors.get(descriptor));
    },
    readSync(descriptor, output, offset, length, position) {
      const [, bytes] = requireFile(descriptors.get(descriptor));
      const start = Math.max(0, position ?? 0);
      const count = Math.max(0, Math.min(length, bytes.byteLength - start));
      output.set(bytes.subarray(start, start + count), offset);
      return count;
    },
    writeSync(descriptor, input, offset, length, position) {
      const normalized = descriptors.get(descriptor);
      const [, previous] = requireFile(normalized);
      const start = Math.max(0, position ?? 0);
      const required = start + length;
      let bytes = previous;
      if (bytes.byteLength < required) {
        bytes = new Uint8Array(required);
        bytes.set(previous);
      }
      bytes.set(input.subarray(offset, offset + length), start);
      files.set(normalized, bytes);
      return length;
    },
    ftruncateSync(descriptor, size) {
      const normalized = descriptors.get(descriptor);
      const [, previous] = requireFile(normalized);
      const bytes = new Uint8Array(Math.max(0, size));
      bytes.set(previous.subarray(0, bytes.byteLength));
      files.set(normalized, bytes);
    },
    fsyncSync() {},
    readFileSync(value, encoding) {
      const [, bytes] = requireFile(value);
      if (encoding) return new TextDecoder(encoding).decode(bytes);
      return bytes;
    },
  };
  return api;
}

let hostFs;
let hostPath;
if (isNodeHost) {
  [{ default: hostFs }, { default: hostPath }] = await Promise.all([
    import("node:fs"),
    import("node:path"),
  ]);
} else {
  hostPath = createMemoryPath();
  hostFs = createMemoryFs(hostPath);
}

export function installMemoryFiles(entries) {
  if (isNodeHost) throw new Error("the memory filesystem is only available in browser hosts");
  hostFs.install(entries);
}

export { hostFs, hostPath, isNodeHost };

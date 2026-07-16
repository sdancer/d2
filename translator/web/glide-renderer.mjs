const TMU_BYTES = 16 * 1024 * 1024;

function compileShader(gl, type, source) {
  const shader = gl.createShader(type);
  gl.shaderSource(shader, source);
  gl.compileShader(shader);
  if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
    throw new Error(`Glide WebGL shader compilation failed: ${gl.getShaderInfoLog(shader)}`);
  }
  return shader;
}

function createProgram(gl, vertexSource, fragmentSource) {
  const program = gl.createProgram();
  gl.attachShader(program, compileShader(gl, gl.VERTEX_SHADER, vertexSource));
  gl.attachShader(program, compileShader(gl, gl.FRAGMENT_SHADER, fragmentSource));
  gl.linkProgram(program);
  if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
    throw new Error(`Glide WebGL program linking failed: ${gl.getProgramInfoLog(program)}`);
  }
  return program;
}

function rgbaColor(color) {
  return [
    (color >>> 24 & 0xff) / 255,
    (color >>> 16 & 0xff) / 255,
    (color >>> 8 & 0xff) / 255,
    (color & 0xff) / 255,
  ];
}

function argbColor(color, alpha = null) {
  return [
    (color >>> 16 & 0xff) / 255,
    (color >>> 8 & 0xff) / 255,
    (color & 0xff) / 255,
    alpha ?? (color >>> 24 & 0xff) / 255,
  ];
}

export class GlideWebGlRenderer {
  constructor(gl, canvas, onFrameSize = null) {
    this.gl = gl;
    this.canvas = canvas;
    this.onFrameSize = onFrameSize;
    this.width = 640;
    this.height = 480;
    this.tmu = new Uint8Array(TMU_BYTES);
    this.revisions = new Map();
    this.textures = new Map();
    this.currentTexture = null;
    this.chromaKey = false;
    this.constantCombine = false;
    this.constantColor = [1, 1, 1, 1];
    this.blend = { rgbSource: 4, rgbDestination: 0 };
    this.drawCount = 0;
    this.swapCount = 0;
    this.eventCounts = {};
    this.drawCounts = {};
    this.skippedDraws = 0;
    this.recentDraws = [];
    this.webGlErrors = {};

    this.program = createProgram(gl, `#version 300 es
      precision highp float;
      in vec2 a_position;
      in vec2 a_texcoord;
      in vec4 a_color;
      uniform vec2 u_screen;
      out vec2 v_texcoord;
      out vec4 v_color;
      void main() {
        vec2 clip = a_position / u_screen * 2.0 - 1.0;
        gl_Position = vec4(clip.x, -clip.y, 0.0, 1.0);
        gl_PointSize = 1.0;
        v_texcoord = a_texcoord;
        v_color = a_color;
      }
    `, `#version 300 es
      precision highp float;
      uniform sampler2D u_indices;
      uniform sampler2D u_palette;
      uniform bool u_chroma_key;
      uniform bool u_constant_combine;
      uniform vec4 u_constant_color;
      in vec2 v_texcoord;
      in vec4 v_color;
      out vec4 output_color;
      void main() {
        int index = int(texture(u_indices, v_texcoord).r * 255.0 + 0.5);
        if (u_chroma_key && index == 0) discard;
        vec4 texture_color = texelFetch(u_palette, ivec2(index, 0), 0);
        output_color = u_constant_combine ? u_constant_color : v_color * texture_color;
      }
    `);
    this.vao = gl.createVertexArray();
    this.vertexBuffer = gl.createBuffer();
    gl.bindVertexArray(this.vao);
    gl.bindBuffer(gl.ARRAY_BUFFER, this.vertexBuffer);
    const stride = 8 * 4;
    for (const [name, size, offset] of [
      ["a_position", 2, 0],
      ["a_texcoord", 2, 2 * 4],
      ["a_color", 4, 4 * 4],
    ]) {
      const location = gl.getAttribLocation(this.program, name);
      gl.enableVertexAttribArray(location);
      gl.vertexAttribPointer(location, size, gl.FLOAT, false, stride, offset);
    }
    this.screenUniform = gl.getUniformLocation(this.program, "u_screen");
    this.chromaUniform = gl.getUniformLocation(this.program, "u_chroma_key");
    this.constantCombineUniform = gl.getUniformLocation(this.program, "u_constant_combine");
    this.constantColorUniform = gl.getUniformLocation(this.program, "u_constant_color");

    this.paletteTexture = gl.createTexture();
    gl.activeTexture(gl.TEXTURE1);
    gl.bindTexture(gl.TEXTURE_2D, this.paletteTexture);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
    const initialPalette = new Uint8Array(256 * 4);
    initialPalette.fill(255);
    gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA8, 256, 1, 0, gl.RGBA, gl.UNSIGNED_BYTE, initialPalette);
    gl.useProgram(this.program);
    gl.uniform1i(gl.getUniformLocation(this.program, "u_indices"), 0);
    gl.uniform1i(gl.getUniformLocation(this.program, "u_palette"), 1);

    this.lfbProgram = createProgram(gl, `#version 300 es
      in vec2 a_position;
      out vec2 v_uv;
      void main() {
        gl_Position = vec4(a_position, 0.0, 1.0);
        v_uv = vec2(a_position.x * 0.5 + 0.5, 0.5 - a_position.y * 0.5);
      }
    `, `#version 300 es
      precision mediump float;
      uniform sampler2D u_frame;
      in vec2 v_uv;
      out vec4 output_color;
      void main() { output_color = texture(u_frame, v_uv).bgra; }
    `);
    this.lfbVao = gl.createVertexArray();
    this.lfbVertices = gl.createBuffer();
    gl.bindVertexArray(this.lfbVao);
    gl.bindBuffer(gl.ARRAY_BUFFER, this.lfbVertices);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]), gl.STATIC_DRAW);
    const lfbPosition = gl.getAttribLocation(this.lfbProgram, "a_position");
    gl.enableVertexAttribArray(lfbPosition);
    gl.vertexAttribPointer(lfbPosition, 2, gl.FLOAT, false, 0, 0);
    this.lfbTexture = gl.createTexture();
    gl.activeTexture(gl.TEXTURE0);
    gl.bindTexture(gl.TEXTURE_2D, this.lfbTexture);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
    gl.texImage2D(
      gl.TEXTURE_2D,
      0,
      gl.RGBA8,
      1,
      1,
      0,
      gl.RGBA,
      gl.UNSIGNED_BYTE,
      new Uint8Array([255, 255, 255, 255]),
    );
    gl.useProgram(this.lfbProgram);
    gl.uniform1i(gl.getUniformLocation(this.lfbProgram, "u_frame"), 0);
  }

  configureDrawState() {
    const gl = this.gl;
    gl.useProgram(this.program);
    gl.bindVertexArray(this.vao);
    gl.viewport(0, 0, this.canvas.width, this.canvas.height);
    gl.disable(gl.DEPTH_TEST);
    gl.disable(gl.CULL_FACE);
    gl.disable(gl.SCISSOR_TEST);
    gl.colorMask(true, true, true, true);
    gl.uniform2f(this.screenUniform, this.width, this.height);
    gl.uniform1i(this.chromaUniform, this.chromaKey ? 1 : 0);
    gl.uniform1i(this.constantCombineUniform, this.constantCombine ? 1 : 0);
    gl.uniform4fv(this.constantColorUniform, this.constantColor);
    gl.activeTexture(gl.TEXTURE0);
    gl.bindTexture(gl.TEXTURE_2D, this.currentTexture?.texture ?? this.lfbTexture);
    gl.activeTexture(gl.TEXTURE1);
    gl.bindTexture(gl.TEXTURE_2D, this.paletteTexture);
    const { rgbSource: source, rgbDestination: destination } = this.blend;
    if (source === 4 && destination === 0) {
      gl.disable(gl.BLEND);
    } else {
      gl.enable(gl.BLEND);
      const factors = new Map([
        [0, gl.ZERO],
        [1, gl.SRC_ALPHA],
        [2, gl.SRC_COLOR],
        [4, gl.ONE],
        [5, gl.ONE_MINUS_SRC_ALPHA],
        [6, gl.ONE_MINUS_SRC_COLOR],
        [7, gl.ONE_MINUS_DST_ALPHA],
      ]);
      gl.blendFunc(factors.get(source) ?? gl.ONE, factors.get(destination) ?? gl.ZERO);
      gl.blendEquation(gl.FUNC_ADD);
    }
  }

  uploadPalette(memory, pointer) {
    if (!pointer || pointer + 1024 > memory.buffer.byteLength) return;
    const input = new DataView(memory.buffer, pointer, 1024);
    const palette = new Uint8Array(256 * 4);
    for (let index = 0; index < 256; index++) {
      const color = input.getUint32(index * 4, true);
      palette[index * 4] = color >>> 16 & 0xff;
      palette[index * 4 + 1] = color >>> 8 & 0xff;
      palette[index * 4 + 2] = color & 0xff;
      palette[index * 4 + 3] = 0xff;
    }
    const gl = this.gl;
    gl.activeTexture(gl.TEXTURE1);
    gl.bindTexture(gl.TEXTURE_2D, this.paletteTexture);
    gl.pixelStorei(gl.UNPACK_ALIGNMENT, 4);
    gl.texSubImage2D(gl.TEXTURE_2D, 0, 0, 0, 256, 1, gl.RGBA, gl.UNSIGNED_BYTE, palette);
  }

  downloadTexture(memory, event) {
    const size = event.width * event.height;
    if (!event.data || event.address >= this.tmu.length || event.data + size > memory.buffer.byteLength) return;
    const length = Math.min(size, this.tmu.length - event.address);
    this.tmu.set(new Uint8Array(memory.buffer, event.data, length), event.address);
    this.revisions.set(event.address, (this.revisions.get(event.address) ?? 0) + 1);
  }

  selectTexture(event) {
    const gl = this.gl;
    const key = `${event.address}:${event.width}x${event.height}`;
    const revision = this.revisions.get(event.address) ?? 0;
    let cached = this.textures.get(key);
    if (!cached) {
      cached = { texture: gl.createTexture(), revision: -1, key, address: event.address, width: event.width, height: event.height };
      this.textures.set(key, cached);
      gl.activeTexture(gl.TEXTURE0);
      gl.bindTexture(gl.TEXTURE_2D, cached.texture);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
    }
    if (cached.revision !== revision) {
      const size = event.width * event.height;
      const length = Math.min(size, Math.max(0, this.tmu.length - event.address));
      if (length === size) {
        gl.activeTexture(gl.TEXTURE0);
        gl.bindTexture(gl.TEXTURE_2D, cached.texture);
        gl.pixelStorei(gl.UNPACK_ALIGNMENT, 1);
        gl.texImage2D(
          gl.TEXTURE_2D,
          0,
          gl.R8,
          event.width,
          event.height,
          0,
          gl.RED,
          gl.UNSIGNED_BYTE,
          this.tmu.subarray(event.address, event.address + size),
        );
        cached.revision = revision;
      }
    }
    this.currentTexture = cached;
  }

  readVertex(view, pointer, alpha) {
    const color = view.getUint32(pointer + 8, true);
    const values = argbColor(color, alpha);
    return [
      view.getFloat32(pointer, true),
      view.getFloat32(pointer + 4, true),
      view.getFloat32(pointer + 16, true) / 256,
      view.getFloat32(pointer + 20, true) / 256,
      ...values,
    ];
  }

  draw(memory, event) {
    const count = Math.min(event.count >>> 0, 4096);
    if (!count) { this.skippedDraws++; return; }
    const view = new DataView(memory.buffer);
    let pointers;
    if (event.drawType === "array") {
      if (!event.pointers || event.pointers + count * 4 > view.byteLength) { this.skippedDraws++; return; }
      pointers = Array.from({ length: count }, (_value, index) => view.getUint32(event.pointers + index * 4, true));
    } else if (event.drawType === "line") {
      pointers = event.vertices;
    } else {
      pointers = Array.from({ length: count }, (_value, index) => event.vertices + index * event.stride);
    }
    if (pointers.some((pointer) => !pointer || pointer + 24 > view.byteLength)) { this.skippedDraws++; return; }
    const sourceAlpha = this.blend.rgbSource === 1
      ? this.constantColor[3]
      : 1;
    const vertices = new Float32Array(pointers.flatMap((pointer) => this.readVertex(view, pointer, sourceAlpha)));
    const key = `${event.drawType}:${event.mode ?? "-"}`;
    this.drawCounts[key] = (this.drawCounts[key] ?? 0) + 1;
    if (this.recentDraws.length >= 64) this.recentDraws.shift();
    const xs = [], ys = [];
    for (let index = 0; index < vertices.length; index += 8) {
      xs.push(vertices[index]);
      ys.push(vertices[index + 1]);
    }
    this.recentDraws.push({
      type: event.drawType,
      mode: event.mode,
      count,
      bounds: [Math.min(...xs), Math.min(...ys), Math.max(...xs), Math.max(...ys)],
      first: Array.from(vertices.subarray(0, 8)),
      texture: this.currentTexture?.key ?? null,
      chromaKey: this.chromaKey,
      constantCombine: this.constantCombine,
      blend: [this.blend.rgbSource, this.blend.rgbDestination],
    });
    const gl = this.gl;
    this.configureDrawState();
    gl.bindBuffer(gl.ARRAY_BUFFER, this.vertexBuffer);
    gl.bufferData(gl.ARRAY_BUFFER, vertices, gl.STREAM_DRAW);
    let primitive;
    if (event.drawType === "point") primitive = gl.POINTS;
    else if (event.drawType === "line") primitive = gl.LINES;
    else primitive = new Map([
      [0, gl.POINTS],
      [1, gl.LINE_STRIP],
      [2, gl.LINES],
      [3, gl.TRIANGLE_FAN],
      [4, gl.TRIANGLE_STRIP],
      [5, gl.TRIANGLE_FAN],
      [6, gl.TRIANGLES],
    ]).get(event.mode) ?? gl.TRIANGLE_FAN;
    gl.drawArrays(primitive, 0, count);
    this.drawCount++;
  }

  renderLfb(memory, event) {
    const length = event.stride * event.height;
    if (!event.data || event.data + length > memory.buffer.byteLength) return false;
    const gl = this.gl;
    gl.useProgram(this.lfbProgram);
    gl.bindVertexArray(this.lfbVao);
    gl.disable(gl.BLEND);
    gl.disable(gl.DEPTH_TEST);
    gl.viewport(0, 0, this.canvas.width, this.canvas.height);
    gl.activeTexture(gl.TEXTURE0);
    gl.bindTexture(gl.TEXTURE_2D, this.lfbTexture);
    gl.pixelStorei(gl.UNPACK_ALIGNMENT, 4);
    gl.texImage2D(
      gl.TEXTURE_2D,
      0,
      gl.RGBA8,
      event.width,
      event.height,
      0,
      gl.RGBA,
      gl.UNSIGNED_BYTE,
      new Uint8Array(memory.buffer, event.data, length),
    );
    gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
    gl.flush();
    return true;
  }

  handle(event, memory) {
    const gl = this.gl;
    this.eventCounts[event.type] = (this.eventCounts[event.type] ?? 0) + 1;
    switch (event.type) {
      case "open":
        this.width = event.width;
        this.height = event.height;
        this.onFrameSize?.(event.width, event.height);
        gl.viewport(0, 0, this.canvas.width, this.canvas.height);
        gl.clearColor(0, 0, 0, 1);
        gl.clear(gl.COLOR_BUFFER_BIT);
        break;
      case "shutdown":
        this.currentTexture = null;
        break;
      case "palette":
        if (event.table === 2) this.uploadPalette(memory, event.data);
        break;
      case "texture-download":
        this.downloadTexture(memory, event);
        break;
      case "texture-source":
        this.selectTexture(event);
        break;
      case "color-combine":
        this.constantCombine = event.function === 1 && event.factor === 0 && event.local === 1;
        break;
      case "constant-color":
        this.constantColor = rgbaColor(event.color);
        break;
      case "alpha-blend":
        this.blend = event;
        break;
      case "chroma-mode":
        this.chromaKey = event.mode === 1;
        break;
      case "draw":
        this.draw(memory, event);
        break;
      case "clear":
        gl.disable(gl.SCISSOR_TEST);
        gl.colorMask(true, true, true, true);
        gl.clearColor(0, 0, 0, 1);
        gl.clear(gl.COLOR_BUFFER_BIT);
        break;
      case "lfb-unlock":
        return this.renderLfb(memory, event);
      case "swap":
        this.swapCount++;
        gl.flush();
        for (let error = gl.getError(); error !== gl.NO_ERROR; error = gl.getError()) {
          this.webGlErrors[error] = (this.webGlErrors[error] ?? 0) + 1;
        }
        return true;
      default:
        break;
    }
    return undefined;
  }

  snapshot() {
    return {
      width: this.width,
      height: this.height,
      drawCount: this.drawCount,
      swapCount: this.swapCount,
      textureCount: this.textures.size,
      currentTexture: this.currentTexture && {
        key: this.currentTexture.key,
        revision: this.currentTexture.revision,
      },
      chromaKey: this.chromaKey,
      constantCombine: this.constantCombine,
      constantColor: this.constantColor,
      blend: this.blend,
      drawCounts: { ...this.drawCounts },
      skippedDraws: this.skippedDraws,
      recentDraws: this.recentDraws.slice(-32),
      webGlErrors: { ...this.webGlErrors },
      eventCounts: { ...this.eventCounts },
    };
  }
}

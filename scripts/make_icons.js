import fs from 'fs';
import path from 'path';

const outDir = path.join(process.cwd(), 'extension', 'icons');
fs.mkdirSync(outDir, { recursive: true });

// Minimal 1x1 or simple solid PNG with shield shape using valid PNG bytes
// Or create 16x16, 48x48, 128x128 valid PNG files
function createSimplePng(size, r, g, b) {
  // A minimal valid PNG generator in pure Node without native dependencies
  // We can write an SVG and also convert or write an uncompressed PNG
  const width = size;
  const height = size;
  
  // PNG signature
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  
  // IHDR chunk
  const ihdrData = Buffer.alloc(13);
  ihdrData.writeUInt32BE(width, 0);
  ihdrData.writeUInt32BE(height, 4);
  ihdrData[8] = 8; // bit depth
  ihdrData[9] = 2; // truecolor (RGB)
  ihdrData[10] = 0; // compression
  ihdrData[11] = 0; // filter
  ihdrData[12] = 0; // interlace

  function makeChunk(type, data) {
    const len = data.length;
    const buf = Buffer.alloc(4 + 4 + len + 4);
    buf.writeUInt32BE(len, 0);
    buf.write(type, 4);
    data.copy(buf, 8);
    // CRC
    let c = 0xffffffff;
    for (let i = 4; i < 8 + len; i++) {
      c ^= buf[i];
      for (let k = 0; k < 8; k++) {
        c = (c >>> 1) ^ ((c & 1) ? 0xedb88320 : 0);
      }
    }
    buf.writeInt32BE(~c, 8 + len);
    return buf;
  }

  const ihdrChunk = makeChunk('IHDR', ihdrData);

  // Raw image data with filter byte 0 per line
  const rawData = Buffer.alloc(height * (1 + width * 3));
  let offset = 0;
  for (let y = 0; y < height; y++) {
    rawData[offset++] = 0; // filter None
    for (let x = 0; x < width; x++) {
      // Draw a shield-like center
      const dx = (x - width / 2) / (width / 2);
      const dy = (y - height / 2) / (height / 2);
      const dist = Math.sqrt(dx * dx + dy * dy);
      if (dist < 0.8) {
        rawData[offset++] = r;
        rawData[offset++] = g;
        rawData[offset++] = b;
      } else {
        rawData[offset++] = 15;
        rawData[offset++] = 23;
        rawData[offset++] = 42;
      }
    }
  }

  // Simple deflate without compression: type 0 (uncompressed) or use zlib
  import('zlib').then(zlib => {
    const compressed = zlib.deflateSync(rawData);
    const idatChunk = makeChunk('IDAT', compressed);
    const iendChunk = makeChunk('IEND', Buffer.alloc(0));
    const fullPng = Buffer.concat([signature, ihdrChunk, idatChunk, iendChunk]);
    fs.writeFileSync(path.join(outDir, `icon${size}.png`), fullPng);
  });
}

createSimplePng(16, 16, 185, 129);   // emerald-500
createSimplePng(48, 16, 185, 129);
createSimplePng(128, 16, 185, 129);
console.log('Generated extension icons.');

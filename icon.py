import struct
import zlib


def create_mcp_icon(filename="mcp_server_icon.png"):
  width, height = 256, 256
  raw_rows = bytearray()

  # Generate 256x256 8-bit grayscale image (dark terminal theme with warning shield outline)
  for y in range(height):
    raw_rows.append(0)  # Filter byte: None
    for x in range(width):
      # Center coordinate mapping (-1.0 to 1.0)
      nx = (x - 128) / 120.0
      ny = (y - 128) / 120.0

      # Shield shape boundary
      in_shield = (ny < 0.6) and (ny > -0.8) and (abs(nx) < (1.0 - 0.4 * ny))
      border = in_shield and (
          (ny > 0.5) or (ny < -0.72) or (abs(nx) > (0.88 - 0.4 * ny))
      )

      # Terminal cursor prompt `>_` inside shield
      is_prompt = (
          (ny > -0.2 and ny < 0.2 and abs(nx + 0.3) < 0.05)  # vertical bar
          or (nx > 0.0 and nx < 0.3 and abs(ny - 0.15) < 0.04)  # cursor dash
      )

      if border or is_prompt:
        raw_rows.append(240)  # Bright highlight
      elif in_shield:
        raw_rows.append(45)  # Shield interior
      else:
        raw_rows.append(18)  # Background dark slate

  # PNG file structure
  png_header = b"\x89PNG\r\n\x1a\n"

  def chunk(tag, data):
    return (
        struct.pack(">I", len(data))
        + tag
        + data
        + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    )

  ihdr = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)
  idat = zlib.compress(bytes(raw_rows), 9)

  with open(filename, "wb") as f:
    f.write(png_header)
    f.write(chunk(b"IHDR", ihdr))
    f.write(chunk(b"IDAT", idat))
    f.write(chunk(b"IEND", b""))

  print(f"Created {filename} (256x256 px, size: {len(idat)} bytes)")


create_mcp_icon()
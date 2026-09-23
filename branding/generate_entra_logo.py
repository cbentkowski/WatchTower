from pathlib import Path
from PIL import Image, ImageDraw

SCALE = 4
SIZE = 215
BG = "#102434"
TEAL = "#4bd4b2"
MINT = "#dffbf2"
LIGHT = "#a1ffe0"

def p(points):
    return [(round(x * SCALE), round(y * SCALE)) for x, y in points]

image = Image.new("RGB", (SIZE * SCALE, SIZE * SCALE), BG)
draw = ImageDraw.Draw(image, "RGBA")

# Light beam, contained within the square for a strong small-size silhouette.
draw.polygon(p([(112, 76), (204, 38), (204, 136), (112, 101)]), fill=(75, 212, 178, 82))
draw.polygon(p([(112, 79), (204, 67), (204, 110), (112, 96)]), fill=(161, 255, 224, 225))

# Lighthouse body and cap.
draw.polygon(p([(64, 174), (75, 77), (111, 77), (123, 174)]), fill=MINT,
             outline=TEAL, width=8)
draw.polygon(p([(64, 77), (122, 77), (112, 59), (75, 59)]), fill=TEAL)
draw.line(p([(75, 59), (75, 34), (110, 34), (110, 59)]), fill=MINT, width=9, joint="curve")

# Lantern room and tower bands.
draw.rounded_rectangle((84*SCALE, 84*SCALE, 104*SCALE, 104*SCALE), radius=4*SCALE, fill=BG)
draw.line(p([(69, 117), (117, 117)]), fill=(75, 212, 178, 180), width=7)
draw.line(p([(66, 146), (120, 146)]), fill=(75, 212, 178, 180), width=7)

# Ground line gives the mark a stable base.
draw.line(p([(52, 179), (134, 179)]), fill=TEAL, width=11, joint="curve")

image = image.resize((SIZE, SIZE), Image.Resampling.LANCZOS)
output = Path(__file__).with_name("watchtower-entra-logo.png")
image.save(output, "PNG", optimize=True)
print(output)

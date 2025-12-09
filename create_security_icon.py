from PIL import Image, ImageDraw


def generate_icon(out_path: str) -> None:
    """Generate a simple padlock-style security icon and save as .ico.
    Creates multiple sizes inside the ICO so Windows selects the best one.
    """
    sizes = [256, 128, 64, 48, 32, 16]
    images = []
    for s in sizes:
        img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)

        # Colors
        body_color = (0, 120, 212, 255)  # blue accent
        shackle_color = (230, 230, 230, 255)
        inner_color = (255, 255, 255, 255)

        # Draw lock body (rounded rectangle)
        pad = int(s * 0.12)
        left = pad
        top = int(s * 0.45)
        right = s - pad
        bottom = s - pad
        radius = int(s * 0.08)

        # rounded rectangle (approx)
        draw.rounded_rectangle([left, top, right, bottom], radius=radius, fill=body_color)

        # draw shackle (arc / thick semicircle)
        shackle_w = int(s * 0.56)
        shackle_h = int(s * 0.56)
        shackle_left = (s - shackle_w) // 2
        shackle_top = int(s * 0.06)
        shackle_box = [shackle_left, shackle_top, shackle_left + shackle_w, shackle_top + shackle_h]
        draw.arc(shackle_box, start=200, end=340, fill=shackle_color, width=max(2, s // 18))

        # small keyhole
        kx = s // 2
        ky = int(s * 0.66)
        kr = max(1, s // 22)
        draw.ellipse([kx - kr, ky - kr, kx + kr, ky + kr], fill=inner_color)
        # key stem
        stem_h = int(s * 0.08)
        draw.rectangle([kx - kr // 2, ky + kr, kx + kr // 2, ky + kr + stem_h], fill=inner_color)

        images.append(img)

    # Save as ICO with multiple sizes
    images[0].save(out_path, format='ICO', sizes=[(i.size[0], i.size[1]) for i in images])


if __name__ == '__main__':
    import os
    p = os.path.join(os.path.dirname(__file__), 'sm4_app_icon.ico')
    try:
        generate_icon(p)
        print('Generated', p)
    except Exception as e:
        print('Icon generation failed:', e)

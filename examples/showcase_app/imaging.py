"""Thumbnail helpers.

Creates images rather than parsing untrusted ones, so the ICC-profile overflow
advisory on `PIL.Image.open` is not reachable from here.
"""

import PIL.Image


def blank_thumbnail(size=(128, 128)):
    return PIL.Image.new("RGB", size, (16, 20, 32))

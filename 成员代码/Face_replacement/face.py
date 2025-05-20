# Import third-party libraries
import cv2
import dlib
import numpy as np

# Constants for configuration
PREDICTOR_PATH = "shape_predictor_68_face_landmarks.dat"
SCALE_FACTOR = 1
FEATHER_AMOUNT = 11
COLOUR_CORRECT_BLUR_FRAC = 0.6

# Landmark indices
FACE_POINTS = list(range(17, 68))
MOUTH_POINTS = list(range(48, 61))
RIGHT_BROW_POINTS = list(range(17, 22))
LEFT_BROW_POINTS = list(range(22, 27))
RIGHT_EYE_POINTS = list(range(36, 42))
LEFT_EYE_POINTS = list(range(42, 48))
NOSE_POINTS = list(range(27, 35))
JAW_POINTS = list(range(0, 17))

ALIGN_POINTS = (LEFT_BROW_POINTS + RIGHT_EYE_POINTS + LEFT_EYE_POINTS +
                RIGHT_BROW_POINTS + NOSE_POINTS + MOUTH_POINTS)

OVERLAY_POINTS = [
    LEFT_EYE_POINTS + RIGHT_EYE_POINTS + LEFT_BROW_POINTS + RIGHT_BROW_POINTS,
    NOSE_POINTS + MOUTH_POINTS,
]

# Initialize dlib detectors
detector = dlib.get_frontal_face_detector()
predictor = dlib.shape_predictor(PREDICTOR_PATH)

# Custom exceptions
class TooManyFaces(Exception):
    pass

class NoFaces(Exception):
    pass

def get_landmarks(image):
    """
    Detect facial landmarks from the image.

    Args:
        image (np.ndarray): Input image.

    Returns:
        np.matrix: Detected landmark coordinates.
    """
    faces = detector(image, 1)
    if len(faces) > 1:
        raise TooManyFaces("More than one face detected.")
    if len(faces) == 0:
        raise NoFaces("No faces detected.")
    return np.matrix([[p.x, p.y] for p in predictor(image, faces[0]).parts()])

def read_image_and_landmarks(filename):
    """
    Read image from file and detect landmarks.

    Args:
        filename (str): Path to the image.

    Returns:
        tuple: Image and its landmarks.
    """
    image = cv2.imread(filename, cv2.IMREAD_COLOR)
    image = cv2.resize(image, (image.shape[1] * SCALE_FACTOR, image.shape[0] * SCALE_FACTOR))
    landmarks = get_landmarks(image)
    return image, landmarks

def transformation_from_points(points1, points2):
    """
    Compute affine transformation matrix between two sets of points.

    Args:
        points1 (np.matrix): Source points.
        points2 (np.matrix): Destination points.

    Returns:
        np.matrix: 3x3 transformation matrix.
    """
    points1 = points1.astype(np.float64)
    points2 = points2.astype(np.float64)

    c1 = np.mean(points1, axis=0)
    c2 = np.mean(points2, axis=0)

    points1 -= c1
    points2 -= c2

    s1 = np.std(points1)
    s2 = np.std(points2)

    points1 /= s1
    points2 /= s2

    U, S, Vt = np.linalg.svd(points1.T * points2)
    R = (U * Vt).T

    return np.vstack([
        np.hstack(((s2 / s1) * R, c2.T - (s2 / s1) * R * c1.T)),
        np.matrix([0., 0., 1.])
    ])

def warp_image(image, matrix, target_shape):
    """
    Warp image using the affine transformation matrix.

    Args:
        image (np.ndarray): Input image.
        matrix (np.matrix): Affine transformation matrix.
        target_shape (tuple): Output shape.

    Returns:
        np.ndarray: Warped image.
    """
    output_image = np.zeros(target_shape, dtype=image.dtype)
    cv2.warpAffine(
        image,
        matrix[:2],
        (target_shape[1], target_shape[0]),
        dst=output_image,
        borderMode=cv2.BORDER_TRANSPARENT,
        flags=cv2.WARP_INVERSE_MAP
    )
    return output_image

def get_face_mask(image, landmarks):
    """
    Create a mask for the face using facial landmarks.

    Args:
        image (np.ndarray): Input image.
        landmarks (np.matrix): Landmark coordinates.

    Returns:
        np.ndarray: Smoothed mask image.
    """
    mask = np.zeros(image.shape[:2], dtype=np.float64)

    for group in OVERLAY_POINTS:
        hull = cv2.convexHull(landmarks[group])
        cv2.fillConvexPoly(mask, hull, color=1)

    mask = cv2.GaussianBlur(mask, (FEATHER_AMOUNT, FEATHER_AMOUNT), 0)
    mask = mask[..., np.newaxis]
    return np.repeat(mask, 3, axis=2)

def correct_colours(reference_image, target_image, landmarks):
    """
    Correct the colors of the target image to match the reference image.

    Args:
        reference_image (np.ndarray): Source image.
        target_image (np.ndarray): Warped image.
        landmarks (np.matrix): Landmark points.

    Returns:
        np.ndarray: Color-corrected image.
    """
    blur_amount = COLOUR_CORRECT_BLUR_FRAC * np.linalg.norm(
        np.mean(landmarks[LEFT_EYE_POINTS], axis=0) -
        np.mean(landmarks[RIGHT_EYE_POINTS], axis=0)
    )
    blur_amount = int(blur_amount)
    if blur_amount % 2 == 0:
        blur_amount += 1

    reference_blur = cv2.GaussianBlur(reference_image, (blur_amount, blur_amount), 0)
    target_blur = cv2.GaussianBlur(target_image, (blur_amount, blur_amount), 0)

    target_blur += (128 * (target_blur <= 1.0)).astype(target_blur.dtype)

    return (target_image.astype(np.float64) * reference_blur.astype(np.float64) /
            target_blur.astype(np.float64))

def main():
    image_path1 = input("输入第一张图片的路径：")
    image_path2 = input("输入第二张图片的路径：")

    image1, landmarks1 = read_image_and_landmarks(image_path1)
    image2, landmarks2 = read_image_and_landmarks(image_path2)

    transformation_matrix = transformation_from_points(landmarks1[ALIGN_POINTS], landmarks2[ALIGN_POINTS])

    mask2 = get_face_mask(image2, landmarks2)
    warped_mask = warp_image(mask2, transformation_matrix, image1.shape)

    mask1 = get_face_mask(image1, landmarks1)
    combined_mask = np.max([mask1, warped_mask], axis=0)

    warped_image2 = warp_image(image2, transformation_matrix, image1.shape)
    color_corrected_image2 = correct_colours(image1, warped_image2, landmarks1)

    output_image = image1 * (1.0 - combined_mask) + color_corrected_image2 * combined_mask

    cv2.imwrite('output.jpg', output_image.astype(np.uint8))
    print("面部替换完成，结果保存为 output.jpg")

if __name__ == '__main__':
    main()

#导入第三方库
import cv2
import dlib
import numpy as np

# 配置常量：用于面部特征点预测器路径、缩放比例、羽化量、颜色校正模糊比例等
PREDICTOR_PATH = "shape_predictor_68_face_landmarks.dat"
SCALE_FACTOR = 4
FEATHER_AMOUNT = 2
COLOUR_CORRECT_BLUR_FRAC = 1

# 定义面部特征点的索引范围
FACE_POINTS = list(range(17, 68))
MOUTH_POINTS = list(range(48, 61))
RIGHT_BROW_POINTS = list(range(17, 22))
LEFT_BROW_POINTS = list(range(22, 27))
RIGHT_EYE_POINTS = list(range(36, 42))
LEFT_EYE_POINTS = list(range(42, 48))
NOSE_POINTS = list(range(27, 35))
JAW_POINTS = list(range(0, 17))

# 用于面部对齐的关键特征点和重叠区域的特征点
ALIGN_POINTS = (LEFT_BROW_POINTS + RIGHT_EYE_POINTS + LEFT_EYE_POINTS +
                RIGHT_BROW_POINTS + NOSE_POINTS + MOUTH_POINTS)
OVERLAY_POINTS = [
    LEFT_EYE_POINTS + RIGHT_EYE_POINTS + LEFT_BROW_POINTS + RIGHT_BROW_POINTS,
    NOSE_POINTS + MOUTH_POINTS,
]

# 使用dlib进行面部检测和特征点预测
detector = dlib.get_frontal_face_detector()
predictor = dlib.shape_predictor(PREDICTOR_PATH)

# 自定义异常类：用于处理没有检测到人脸或检测到多张人脸的情况
class TooManyFaces(Exception):
    pass

class NoFaces(Exception):
    pass

# 获取图像中的面部特征点
def get_landmarks(im):
    rects = detector(im, 1)
    if len(rects) > 1:
        raise TooManyFaces("检测到多个人脸")
    if len(rects) == 0:
        raise NoFaces("没有检测到任何人脸")
    return np.matrix([[p.x, p.y] for p in predictor(im, rects[0]).parts()])

# 读取图像并获取特征点
def read_im_and_landmarks(fname):
    im = cv2.imread(fname, cv2.IMREAD_COLOR)
    im = cv2.resize(im, (im.shape[1] * SCALE_FACTOR,
                         im.shape[0] * SCALE_FACTOR))
    s = get_landmarks(im)
    return im, s

# 根据两组特征点生成仿射变换矩阵
def transformation_from_points(points1, points2):
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
    return np.vstack([np.hstack(((s2 / s1) * R,
                                 c2.T - (s2 / s1) * R * c1.T)),
                      np.matrix([0., 0., 1.])])

# 对图像进行仿射变换
def warp_im(im, M, dshape):
    output_im = np.zeros(dshape, dtype=im.dtype)
    # 使用仿射变换对图像进行扭曲
    cv2.warpAffine(im,
                   M[:2],
                   (dshape[1], dshape[0]),
                   dst=output_im,
                   borderMode=cv2.BORDER_TRANSPARENT,
                   flags=cv2.WARP_INVERSE_MAP)
    return output_im

# 获取面部的掩码，用于后续替换操作
def get_face_mask(im, landmarks):
    im = np.zeros(im.shape[:2], dtype=np.float64)
    for group in OVERLAY_POINTS:
        hull = cv2.convexHull(landmarks[group])
        cv2.fillConvexPoly(im, hull, color=1)
    im = np.array([im, im, im]).transpose((1, 2, 0))
    # 对掩码进行模糊处理，得到平滑的过渡效果
    im = (cv2.GaussianBlur(im, (FEATHER_AMOUNT, FEATHER_AMOUNT), 0) > 0) * 1.0
    im = cv2.GaussianBlur(im, (FEATHER_AMOUNT, FEATHER_AMOUNT), 0)
    return im

# 对两张图像进行颜色校正，使它们的色调更加一致
def correct_colours(im1, im2, landmarks1):
    blur_amount = COLOUR_CORRECT_BLUR_FRAC * np.linalg.norm(
        np.mean(landmarks1[LEFT_EYE_POINTS], axis=0) -
        np.mean(landmarks1[RIGHT_EYE_POINTS], axis=0))
    blur_amount = int(blur_amount)
    if blur_amount % 2 == 0:
        blur_amount += 1
    im1_blur = cv2.GaussianBlur(im1, (blur_amount, blur_amount), 0)
    im2_blur = cv2.GaussianBlur(im2, (blur_amount, blur_amount), 0)
    im2_blur += (128 * (im2_blur <= 1.0)).astype(im2_blur.dtype)
    return (im2.astype(np.float64) * im1_blur.astype(np.float64) /
            im2_blur.astype(np.float64))

# 主函数：负责处理用户输入和调用面部替换的功能
def main():
    image_path1 = input("输入第一张图片的路径：")
    image_path2 = input("输入第二张图片的路径：")
    im1, landmarks1 = read_im_and_landmarks(image_path1)
    im2, landmarks2 = read_im_and_landmarks(image_path2)

    # 面部替换的步骤
    M = transformation_from_points(landmarks1[ALIGN_POINTS], landmarks2[ALIGN_POINTS])
    mask = get_face_mask(im2, landmarks2)
    warped_mask = warp_im(mask, M, im1.shape)
    combined_mask = np.max([get_face_mask(im1, landmarks1), warped_mask], axis=0)
    warped_im2 = warp_im(im2, M, im1.shape)
    warped_corrected_im2 = correct_colours(im1, warped_im2, landmarks1)
    # 使用掩码将两张图片结合在一起，完成面部替换
    output_im = im1 * (1.0 - combined_mask) + warped_corrected_im2 * combined_mask

    cv2.imwrite('output.jpg', output_im)
    print("面部替换完成，结果保存为 output.jpg")

# 程序入口
if __name__ == '__main__':
    main()




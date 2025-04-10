import cv2
import numpy
import numpy as np
import math

import skimage
from scipy.fft import dct
from skimage import color
from sklearn.decomposition import PCA
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from skimage.transform import resize
from PIL import Image


def sgn(x):
    if x < 0:
        return -1
    elif x == 0:
        return 0
    else:
        return 1


# 读入图像并进行预处理，并进行离散傅里叶变换
def preprocess_image(image_array):
    # 转换为灰度图像
    # gray_image = color.rgb2gray(image_array)

    # 重采样为128x128的标准化图像
    # resized_image = cv2.resize(gray_image, (128, 128))

    # 离散傅立叶变换
    dft_image = np.fft.fft2(image_array)
    return dft_image


# 计算噪声参数λ，并添加噪声
def cal_add_lambda(dft_image, k, epsilon):
    dft_coefficients = dft_image[:k, :k]  # 获取前k×k个DFT系数
    # 计算全局敏感度
    sensitivity = 0
    w = 0
    for c in range(k):
        for r in range(k):
            w = w + abs(dft_coefficients[r, c])
        if sensitivity < w:
            sensitivity = w
        w = 0

    lambda_val = sensitivity / epsilon

    # 生成p的随机矩阵
    p_matrix = np.random.rand(k, k)

    # 初始化fim_prime
    fim_prime0 = np.zeros(dft_image.shape, dtype=np.complex128)

    # 计算融合噪声后的FIM'
    for r in range(k):
        for c in range(k):
            noise = -1 * lambda_val * sgn(p_matrix[r, c] - 0.5) * numpy.log(1 - 2 * (p_matrix[r, c] - 0.5))
            fim_prime0[r, c] = dft_coefficients[r, c] + noise

    # 离散傅里叶逆变换
    fim_prime1 = np.fft.ifftshift(fim_prime0)
    fim_prime2 = np.fft.ifft2(fim_prime1)
    fim_prime = np.real(fim_prime2)

    return fim_prime


def differential_privacy_transform(face):
    # 设置隐私参数
    k = 100  # 选择的DFT系数个数
    epsilon = 0.1  # 隐私预算

    resized_image = cv2.resize(face, (128, 128))

    # 读入图像并进行预处理，并进行离散傅里叶变换
    fim = preprocess_image(face)

    # 计算噪声参数λ,并加入噪声
    fim_prime = cal_add_lambda(fim, k, epsilon)

    # 将灰度图像转换为彩色图像
    # color_image = cv2.merge([fim_prime.astype(np.uint8), resized_image[:, :, 1], resized_image[:, :, 2]])

    return fim_prime

import os
import cv2
import numpy as np
from PIL import Image
from skimage import color
import numpy

def preprocess_image(image_array):
    # 转换为灰度图像
    gray_image = color.rgb2gray(image_array)

    # 离散傅立叶变换
    dft_image = np.fft.fft2(gray_image)
    return dft_image

def cal_add_lambda(dft_image, k, epsilon):
    dft_coefficients = dft_image[:k, :k]
    sensitivity = 0
    w = 0
    for c in range(k):
        for r in range(k):
            w = w + abs(dft_coefficients[r, c])
        if sensitivity < w:
            sensitivity = w
        w = 0

    lambda_val = sensitivity / epsilon

    noise = np.random.laplace(0, lambda_val, size=dft_coefficients.shape)
    fim_pri = dft_coefficients + noise
    fim_prime0 = np.zeros(dft_image.shape, dtype=np.complex128)
    for r in range(k):
        for c in range(k):
            fim_prime0[r, c] = fim_pri[r, c]

    fim_prime1 = np.fft.ifftshift(fim_prime0)
    fim_prime2 = np.fft.ifft2(fim_prime1)
    fim_prime = np.real(fim_prime1)

    return fim_prime

def process():
    k = 25
    epsilon = 0.1

    input_dir = r"C:\Users\DELL\桌面\数字内容安全实验\实验四\lfw_home\lfw_funneled"
    output_dir = r"C:\Users\DELL\桌面\数字内容安全实验\实验四\lfw_home\lfw_funneled_privacy"

    folders = [folder for folder in os.listdir(input_dir) if os.path.isdir(os.path.join(input_dir, folder))]

    for folder in folders:
        folder_path = os.path.join(input_dir, folder)
        output_folder = os.path.join(output_dir, folder)
        os.makedirs(output_folder, exist_ok=True)  # 确保输出文件夹存在

        for filename in os.listdir(folder_path):
            image_path = os.path.join(folder_path, filename)
            image = Image.open(image_path)
            image_array = np.array(image)
            resized_image = cv2.resize(image_array, (128, 128))

            fim = preprocess_image(resized_image)
            fim_prime = cal_add_lambda(fim, k, epsilon)

            color_image = cv2.merge([fim_prime.astype(np.uint8), resized_image[:, :, 1], resized_image[:, :, 2]])
            image_new = Image.fromarray(color_image)

            output_path = os.path.join(output_folder, filename)
            image_new.save(output_path)

            image.close()

if __name__ == "__main__":
    process()
